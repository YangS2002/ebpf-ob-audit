#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import csv
import html
import math
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


KV_RE = re.compile(r"(\w+)=([^\s]+)")
NUM_RE = re.compile(r"^-?(?:\d+)(?:\.\d+)?$")


@dataclass(frozen=True)
class RemoteFile:
    role: str
    name: str
    ip: str
    user: str
    port: int
    password: str
    remote_path: str


@dataclass
class MetricRow:
    role: str
    source_name: str
    source_ip: str
    local_path: str
    line_no: int
    seq: int
    ts: str
    event: str
    values: Dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect agent/collector timing logs from deployed nodes and generate CSV + HTML visualization."
    )
    parser.add_argument("--agent-config", required=True, help="agent deploy yaml path")
    parser.add_argument("--collector-config", required=True, help="collector deploy yaml path")
    parser.add_argument("--out-dir", default="", help="output directory; default: tools/timing_report")
    parser.add_argument("--ssh-user", default="", help="override SSH username from config")
    parser.add_argument("--ssh-port", type=int, default=0, help="override SSH port from config")
    parser.add_argument("--identity-file", default="", help="ssh private key path")
    parser.add_argument("--skip-download", action="store_true", help="parse existing files under out-dir/raw")
    parser.add_argument("--strict-host-key", action="store_true", help="do not disable StrictHostKeyChecking")
    parser.add_argument("--serve-port", type=int, default=0, help="serve the report over HTTP on this port after generating")
    parser.add_argument("--agent-log", default="agent.log", help="agent log path relative to deploy_home")
    parser.add_argument("--collector-timing-log", default="logs/collector_timing.log", help="collector timing log path relative to deploy_home")
    return parser.parse_args()


def import_yaml():
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError as exc:
        raise SystemExit(
            "PyYAML is required to read deploy configs. Install with: python3 -m pip install pyyaml\n"
            "or Debian package: sudo apt install python3-yaml"
        ) from exc


def load_yaml(path: str) -> Dict[str, Any]:
    yaml = import_yaml()
    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict):
        raise SystemExit(f"invalid yaml root: {path}")
    return data


def expand_user_path(path: str) -> str:
    if path.startswith("~/"):
        return "$HOME/" + path[2:]
    return path


def path_join_remote(base: str, rel: str) -> str:
    base = expand_user_path(base).rstrip("/")
    rel = rel.lstrip("/")
    return f"{base}/{rel}"


def config_user(config: Dict[str, Any], args: argparse.Namespace) -> Tuple[str, int, str]:
    user_cfg = config.get("user") if isinstance(config.get("user"), dict) else {}
    username = args.ssh_user or str(user_cfg.get("username") or os.environ.get("USER") or "")
    if not username:
        raise SystemExit("SSH username not found; set user.username in config or pass --ssh-user")
    port = args.ssh_port or int(user_cfg.get("port") or 22)
    password = str(user_cfg.get("password") or "")
    return username, port, password


def discover_agent_files(config: Dict[str, Any], args: argparse.Namespace) -> List[RemoteFile]:
    username, port, password = config_user(config, args)
    agent = config.get("agent") if isinstance(config.get("agent"), dict) else {}
    agent_global = agent.get("global") if isinstance(agent.get("global"), dict) else {}
    deploy_home = str(agent_global.get("deploy_home") or "~/ebpf-ob-audit-agent")
    ob = config.get("oceanbase-ce") if isinstance(config.get("oceanbase-ce"), dict) else {}
    servers = ob.get("servers") if isinstance(ob.get("servers"), list) else []
    files: List[RemoteFile] = []
    for index, server in enumerate(servers):
        if not isinstance(server, dict):
            continue
        name = str(server.get("name") or f"agent-{index + 1}")
        ip = str(server.get("ip") or "")
        if not ip:
            continue
        node_cfg = agent.get(name) if isinstance(agent.get(name), dict) else {}
        node_home = str(node_cfg.get("deploy_home") or deploy_home)
        files.append(RemoteFile("agent", name, ip, username, port, password, path_join_remote(node_home, args.agent_log)))
    return files


def discover_collector_files(config: Dict[str, Any], args: argparse.Namespace) -> List[RemoteFile]:
    username, port, password = config_user(config, args)
    collector = config.get("collector") if isinstance(config.get("collector"), dict) else {}
    collector_global = collector.get("global") if isinstance(collector.get("global"), dict) else {}
    deploy_home = str(collector_global.get("deploy_home") or "/home/yangshuo17/ebpf-ob-audit-collector")
    servers = collector.get("servers") if isinstance(collector.get("servers"), list) else []
    files: List[RemoteFile] = []
    seen: set[Tuple[str, str]] = set()
    for index, server in enumerate(servers):
        if not isinstance(server, dict):
            continue
        name = str(server.get("name") or f"collector-{index + 1}")
        ip = str(server.get("ip") or "")
        if not ip:
            continue
        node_home = str(server.get("deploy_home") or deploy_home)
        remote_path = path_join_remote(node_home, args.collector_timing_log)
        key = (ip, remote_path)
        if key in seen:
            continue
        seen.add(key)
        files.append(RemoteFile("collector", name, ip, username, port, password, remote_path))
    return files


def ssh_base(remote: RemoteFile, args: argparse.Namespace) -> List[str]:
    cmd = ["ssh", "-p", str(remote.port)]
    if args.identity_file:
        cmd += ["-i", args.identity_file]
    if not args.strict_host_key:
        cmd += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return cmd


def scp_base(remote: RemoteFile, args: argparse.Namespace) -> List[str]:
    cmd = ["scp", "-P", str(remote.port)]
    if args.identity_file:
        cmd += ["-i", args.identity_file]
    if not args.strict_host_key:
        cmd += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return cmd


def with_password(cmd: List[str], password: str) -> List[str]:
    if not password:
        return cmd
    if not shutil.which("sshpass"):
        raise SystemExit("config has SSH password but sshpass not found. Install sshpass or configure SSH key login.")
    return ["sshpass", "-p", password] + cmd


def remote_exists(remote: RemoteFile, args: argparse.Namespace) -> bool:
    target = f"{remote.user}@{remote.ip}"
    cmd = with_password(ssh_base(remote, args) + [target, f"test -r {shell_quote(remote.remote_path)}"], remote.password)
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def safe_name(remote: RemoteFile) -> str:
    clean_path = remote.remote_path.strip("/").replace("/", "_").replace("$", "")
    return f"{remote.role}_{remote.name}_{remote.ip}_{clean_path}.log".replace(":", "_")


def download_one(remote: RemoteFile, args: argparse.Namespace, raw_dir: Path) -> Optional[Path]:
    local_path = raw_dir / safe_name(remote)
    if not remote_exists(remote, args):
        print(f"missing remote log: {remote.role} {remote.name} {remote.ip}:{remote.remote_path}", file=sys.stderr)
        return None
    src = f"{remote.user}@{remote.ip}:{remote.remote_path}"
    cmd = with_password(scp_base(remote, args) + [src, str(local_path)], remote.password)
    print(f"download {remote.role} {remote.name} {remote.ip}:{remote.remote_path} -> {local_path}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"download failed: {src}", file=sys.stderr)
        return None
    return local_path


def parse_scalar(value: str) -> Any:
    if NUM_RE.match(value):
        return float(value) if "." in value else int(value)
    return value


def parse_metric_line(line: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    if "event=agent_metrics" not in line and "event=collector_metrics" not in line:
        return None
    kv = {key: parse_scalar(value) for key, value in KV_RE.findall(line)}
    event = str(kv.get("event") or "")
    if event not in ("agent_metrics", "collector_metrics"):
        return None
    return event, kv


def parse_logs(local_files: List[Tuple[RemoteFile, Path]]) -> List[MetricRow]:
    rows: List[MetricRow] = []
    seq_by_role: Dict[str, int] = defaultdict(int)
    for remote, path in local_files:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line_no, line in enumerate(file, 1):
                parsed = parse_metric_line(line)
                if not parsed:
                    continue
                event, values = parsed
                seq_by_role[remote.role] += 1
                rows.append(MetricRow(
                    role=remote.role,
                    source_name=remote.name,
                    source_ip=remote.ip,
                    local_path=str(path),
                    line_no=line_no,
                    seq=seq_by_role[remote.role],
                    ts=str(values.get("ts") or ""),
                    event=event,
                    values=values,
                ))
    return rows


def write_csv(rows: List[MetricRow], output: Path) -> None:
    keys = sorted({key for row in rows for key in row.values.keys()})
    base = ["role", "source_name", "source_ip", "seq", "ts", "event", "local_path", "line_no"]
    fields = base + [key for key in keys if key not in {"ts", "event"}]
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            data = {
                "role": row.role,
                "source_name": row.source_name,
                "source_ip": row.source_ip,
                "seq": row.seq,
                "ts": row.ts,
                "event": row.event,
                "local_path": row.local_path,
                "line_no": row.line_no,
            }
            data.update({key: value for key, value in row.values.items() if key not in {"ts", "event"}})
            writer.writerow(data)


def to_float(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def series(rows: List[MetricRow], event: str, field: str) -> List[Tuple[int, float, str]]:
    out = []
    for row in rows:
        if row.event != event:
            continue
        value = to_float(row.values.get(field))
        if value is None:
            continue
        out.append((row.seq, value, f"{row.source_name}@{row.source_ip}"))
    return out


def polyline(points: List[Tuple[float, float]], width: int, height: int, pad: int) -> str:
    if not points:
        return ""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    if xmax == xmin:
        xmax = xmin + 1
    if ymax == ymin:
        ymax = ymin + 1
    coords = []
    for x, y in points:
        sx = pad + (x - xmin) / (xmax - xmin) * (width - 2 * pad)
        sy = height - pad - (y - ymin) / (ymax - ymin) * (height - 2 * pad)
        coords.append(f"{sx:.1f},{sy:.1f}")
    return " ".join(coords)


def svg_chart(title: str, data: List[Tuple[int, float, str]], color: str = "#2563eb") -> str:
    width, height, pad = 900, 260, 42
    if not data:
        return f"<section><h3>{html.escape(title)}</h3><p>No data</p></section>"
    points = [(float(x), y) for x, y, _ in data]
    ys = [y for _, y, _ in data]
    path = polyline(points, width, height, pad)
    ymin, ymax = min(ys), max(ys)
    last = data[-1][1]
    return f"""
<section class="chart">
<h3>{html.escape(title)}</h3>
<div class="hint">min={ymin:.3f}, max={ymax:.3f}, last={last:.3f}</div>
<svg viewBox="0 0 {width} {height}" width="100%" height="{height}">
  <rect x="0" y="0" width="{width}" height="{height}" fill="#fff" stroke="#ddd"/>
  <line x1="{pad}" y1="{height-pad}" x2="{width-pad}" y2="{height-pad}" stroke="#999"/>
  <line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height-pad}" stroke="#999"/>
  <polyline points="{path}" fill="none" stroke="{color}" stroke-width="2"/>
</svg>
</section>
"""


def latest_table(rows: List[MetricRow], event: str, fields: Sequence[str]) -> str:
    latest: Dict[str, MetricRow] = {}
    for row in rows:
        if row.event == event:
            latest[f"{row.source_name}@{row.source_ip}"] = row
    if not latest:
        return f"<h3>{html.escape(event)} latest</h3><p>No data</p>"
    body = []
    for source, row in sorted(latest.items()):
        tds = [f"<td>{html.escape(source)}</td>"]
        for field in fields:
            tds.append(f"<td>{html.escape(str(row.values.get(field, '')))}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    header = "<tr><th>source</th>" + "".join(f"<th>{html.escape(f)}</th>" for f in fields) + "</tr>"
    return f"<h3>{html.escape(event)} latest</h3><table>{header}{''.join(body)}</table>"


def write_html(rows: List[MetricRow], output: Path, csv_name: str, raw_files: List[Tuple[RemoteFile, Path]]) -> None:
    agent_fields = ["sent_batches", "sent_records", "sent_bytes", "failed_uploads", "retry_uploads", "dropped_records", "avg_rtt_us", "median_rtt_us", "max_rtt_us", "avg_submit_us"]
    collector_fields = ["batches", "records", "bytes", "avg_parse_us", "avg_wait_inflight_us", "avg_build_docs_us", "avg_insert_many_us", "avg_mongo_total_us", "avg_upload_total_us"]
    raw_list = "".join(f"<li>{html.escape(r.role)} {html.escape(r.name)} {html.escape(r.ip)}: {html.escape(str(p))}</li>" for r, p in raw_files)
    content = f"""
<!doctype html>
<html><head><meta charset="utf-8"><title>Audit Timing Report</title>
<style>
body {{ font-family: sans-serif; margin: 24px; color: #111827; }}
table {{ border-collapse: collapse; margin: 12px 0 24px 0; font-size: 13px; }}
th, td {{ border: 1px solid #d1d5db; padding: 6px 8px; text-align: right; }}
th:first-child, td:first-child {{ text-align: left; }}
th {{ background: #f3f4f6; }}
.chart {{ margin: 24px 0; }}
.hint {{ color: #6b7280; font-size: 13px; margin-bottom: 4px; }}
</style></head><body>
<h1>Audit Timing Report</h1>
<p>generated_at={html.escape(datetime.now().isoformat(timespec='seconds'))}</p>
<p>csv=<a href="{html.escape(csv_name)}">{html.escape(csv_name)}</a></p>
<h2>Downloaded logs</h2><ul>{raw_list}</ul>
<h2>Latest metrics</h2>
{latest_table(rows, 'agent_metrics', agent_fields)}
{latest_table(rows, 'collector_metrics', collector_fields)}
<h2>Charts</h2>
{svg_chart('Agent avg_rtt_us', series(rows, 'agent_metrics', 'avg_rtt_us'))}
{svg_chart('Agent max_rtt_us', series(rows, 'agent_metrics', 'max_rtt_us'), '#dc2626')}
{svg_chart('Agent dropped_records', series(rows, 'agent_metrics', 'dropped_records'), '#f59e0b')}
{svg_chart('Collector avg_upload_total_us', series(rows, 'collector_metrics', 'avg_upload_total_us'), '#16a34a')}
{svg_chart('Collector avg_mongo_total_us', series(rows, 'collector_metrics', 'avg_mongo_total_us'), '#7c3aed')}
{svg_chart('Collector avg_insert_many_us', series(rows, 'collector_metrics', 'avg_insert_many_us'), '#0891b2')}
</body></html>
"""
    output.write_text(content, encoding="utf-8")


def use_existing_raw(out_dir: Path) -> List[Tuple[RemoteFile, Path]]:
    raw_dir = out_dir / "raw"
    files = []
    for path in sorted(raw_dir.glob("*.log")):
        role = "collector" if "collector" in path.name else "agent"
        remote = RemoteFile(role, path.stem, "local", "", 0, "", str(path))
        files.append((remote, path))
    return files


def main() -> int:
    args = parse_args()
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = Path(__file__).resolve().parent / "timing_report"
    raw_dir = out_dir / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    if args.skip_download:
        local_files = use_existing_raw(out_dir)
    else:
        agent_config = load_yaml(args.agent_config)
        collector_config = load_yaml(args.collector_config)
        remotes = discover_agent_files(agent_config, args) + discover_collector_files(collector_config, args)
        if not remotes:
            raise SystemExit("no remote logs discovered from deploy configs")
        for stale in raw_dir.glob("*.log"):
            stale.unlink()
        local_files = []
        for remote in remotes:
            path = download_one(remote, args, raw_dir)
            if path:
                local_files.append((remote, path))

    rows = parse_logs(local_files)
    csv_path = out_dir / "timing_metrics.csv"
    html_path = out_dir / "timing_report.html"
    write_csv(rows, csv_path)
    write_html(rows, html_path, csv_path.name, local_files)
    print(f"rows={len(rows)}")
    print(f"csv={csv_path}")
    print(f"html={html_path}")
    if args.serve_port > 0:
        import http.server
        import socketserver

        handler = lambda *handler_args: http.server.SimpleHTTPRequestHandler(*handler_args, directory=str(out_dir))
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("0.0.0.0", args.serve_port), handler) as server:
            print(f"serving http://0.0.0.0:{args.serve_port}/timing_report.html  (Ctrl+C to stop)")
            server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
