#!/usr/bin/env python3
import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UPROBE_DIR = REPO_ROOT / "uprobe"
DEPLOY_SCRIPT = UPROBE_DIR / "deploy" / "deploy_agent.py"
COMPARE_SCRIPT = UPROBE_DIR / "test" / "distributed_sql_test" / "compare_official_collector.py"
DEFAULT_WORKLOAD = UPROBE_DIR / "test" / "distributed_sql_test" / "workload.sql"
DEFAULT_OUT_DIR = UPROBE_DIR / "test" / "distributed_sql_test" / "out" / "single"

COLOR = {
    "reset": "\033[0m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
}
MARKER_RE = re.compile(r"EBPF_[A-Z0-9_]+")
FIELD_MAP = {
    "server_ip": "svr_ip",
    "request_id": "request_id",
    "trace_id": "trace_id",
    "session_id": "sid",
    "client_ip": "client_ip",
    "tenant_id": "tenant_id",
    "tenant_name": "tenant_name",
    "effective_tenant_id": "effective_tenant_id",
    "user_id": "user_id",
    "user_name": "user_name",
    "user_client_ip": "user_client_ip",
    "db_id": "db_id",
    "db_name": "db_name",
    "sql_id": "sql_id",
    "query_sql": "query_sql",
    "affected_rows": "affected_rows",
    "return_rows": "return_rows",
    "ret_code": "ret_code",
    "elapsed_time": "elapsed_time",
    "execute_time": "execute_time",
    "stmt_type_name": "stmt_type",
    "plan_type_name": "plan_type",
    "params_value": "params_value",
    "trans_status_name": "trans_status",
}


def color(name, text):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{COLOR[name]}{text}{COLOR['reset']}"


def stage(name, detail=""):
    text = f"▶ {name}"
    if detail:
        text += f" | {detail}"
    print(color("cyan", f"\n{'=' * 18} {text} {'=' * 18}"))


def ok(name, detail=""):
    text = f"✓ {name}"
    if detail:
        text += f" | {detail}"
    print(color("green", text))


def warn(name, detail=""):
    text = f"! {name}"
    if detail:
        text += f" | {detail}"
    print(color("yellow", text))


def load_deploy_config(path):
    sys.path.insert(0, str(UPROBE_DIR / "deploy"))
    from deploy_agent import parse_config

    return parse_config(Path(path).resolve())


def run(cmd, *, input_path=None, output_path=None, env=None, check=True, cwd=REPO_ROOT):
    stdin = None
    stdout = None
    try:
        if input_path:
            stdin = open(input_path, "rb")
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            stdout = open(output_path, "wb")
        printable = " ".join(str(x) for x in cmd)
        print(f"RUN {printable}")
        result = subprocess.run(cmd, stdin=stdin, stdout=stdout, env=env, cwd=str(cwd), text=False)
        if check and result.returncode != 0:
            raise SystemExit(result.returncode)
        return result
    finally:
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()


def mysql_cmd(args, user, *, batch=True, raw=True):
    cmd = [
        "mysql",
        "-h", args.ob_host,
        "-P", str(args.ob_port),
        "-u", user,
        "-A",
        "--skip-ssl",
    ]
    if batch:
        cmd.append("--batch")
    if raw:
        cmd.append("--raw")
    if args.mysql_force:
        cmd.append("--force")
    return cmd


def mysql_env(password):
    env = os.environ.copy()
    env["MYSQL_PWD"] = password
    return env


def mysql_scalar(args, sql):
    cmd = mysql_cmd(args, args.audit_user) + ["-N", "-e", sql]
    print("RUN mysql scalar")
    result = subprocess.run(cmd, env=mysql_env(args.audit_password), text=True, capture_output=True, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout.strip().splitlines()[-1].strip()


def extract_markers(sql_path):
    text = Path(sql_path).read_text(encoding="utf-8")
    return sorted(set(MARKER_RE.findall(text)))


def deploy_action(args, action):
    cmd = [sys.executable, str(DEPLOY_SCRIPT), "-c", str(args.deploy_config), "--action", action]
    if args.skip_build and action in {"deploy", "deploy-start"}:
        cmd.append("--skip-build")
    run(cmd)


def build_tools(args):
    if args.skip_tools_build:
        warn("build tools skipped")
        return
    if not (UPROBE_DIR / "bin" / "adt_to_csv").exists():
        run(["make", "-C", str(UPROBE_DIR), "tools"])
    ok("tools ready")


def execute_workload(args):
    cmd = mysql_cmd(args, args.workload_user)
    if args.workload_database:
        cmd.extend(["-D", args.workload_database])
    run(cmd, input_path=args.workload, env=mysql_env(args.workload_password))


def export_official(args, start_time, end_time, out_path):
    sql = "SELECT * from oceanbase.GV$OB_SQL_AUDIT where is_inner_sql=0"
    cmd = mysql_cmd(args, args.audit_user) + ["-e", sql]
    run(cmd, output_path=out_path, env=mysql_env(args.audit_password))


def sshpass_prefix(password):
    if not password:
        return []
    if shutil.which("sshpass") is None:
        raise SystemExit("collector password provided but sshpass not found")
    os.environ["SSHPASS"] = password
    return ["sshpass", "-e"]


def download_collector(args, config, out_path):
    if args.collector_local_path:
        shutil.copy2(args.collector_local_path, out_path)
        ok("collector copied", str(out_path))
        return
    host = args.collector_host or config.collector_addr.rsplit(":", 1)[0]
    user = args.collector_user or config.username
    port = args.collector_ssh_port or config.port
    password = args.collector_password if args.collector_password is not None else config.password
    remote = f"{user}@{host}:{args.collector_path}"
    cmd = sshpass_prefix(password) + ["scp", "-P", str(port), remote, str(out_path)]
    run(cmd)
    ok("collector downloaded", f"{remote} -> {out_path}")


def convert_collector(adt_path, csv_path):
    run([str(UPROBE_DIR / "bin" / "adt_to_csv"), str(adt_path), str(csv_path), "all"])


def compare_with_official(args, official_tsv, collector_csv, out_dir):
    compare_out = out_dir / "compare"
    cmd = [
        sys.executable,
        str(COMPARE_SCRIPT),
        "--workload", str(args.workload),
        "--official-tsv", str(official_tsv),
        "--collector-csv", str(collector_csv),
        "--out-dir", str(compare_out),
    ]
    return run(cmd, check=False).returncode


def detect_dialect(path):
    sample = Path(path).read_text(encoding="utf-8-sig", errors="replace")[:8192]
    if not sample.strip():
        return csv.excel_tab
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t")
    except csv.Error:
        lines = sample.splitlines()
        first_line = lines[0] if lines else ""
        return csv.excel_tab if "\t" in first_line else csv.excel


def read_rows(path):
    if Path(path).stat().st_size == 0:
        return [], []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, dialect=detect_dialect(path))
        fields = [normalize_value(field).lower() for field in (reader.fieldnames or [])]
        rows = []
        for row in reader:
            rows.append({normalize_value(key).lower(): value for key, value in row.items()})
        return rows, fields


def marker_of(row):
    value = row.get("query_sql") or ""
    match = MARKER_RE.search(str(value))
    return match.group(0) if match else ""


def write_filtered(src, dst, markers, *, start_us=None, end_us=None):
    rows, fields = read_rows(src)
    keep = []
    for row in rows:
        if marker_of(row) not in markers:
            continue
        if start_us is not None and end_us is not None and "request_timestamp" in row:
            try:
                ts = int(row.get("request_timestamp") or 0)
            except ValueError:
                continue
            if ts < start_us or ts > end_us:
                continue
        keep.append(row)
    with open(dst, "w", newline="", encoding="utf-8") as f:
        if fields:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(keep)
    return keep


def index_by_marker(rows):
    data = {}
    for row in rows:
        marker = marker_of(row)
        if marker:
            data.setdefault(marker, []).append(row)
    return data


def normalize_value(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_row(row, field_map=None):
    if field_map is None:
        return {key: normalize_value(value) for key, value in row.items()}
    return {official: normalize_value(row.get(collector)) for collector, official in field_map.items()}


def write_rows(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_normalized_outputs(official_rows, collector_rows, official_path, collector_path):
    fields = list(FIELD_MAP.values())
    write_rows(official_path, [normalize_row(row) for row in official_rows], fields)
    write_rows(collector_path, [normalize_row(row, FIELD_MAP) for row in collector_rows], fields)
    ok("normalized row counts", f"official={len(official_rows)} collector={len(collector_rows)}")


def compare_records(markers, official_rows, collector_rows, report_path):
    official = index_by_marker(official_rows)
    collector = index_by_marker(collector_rows)
    failures = []
    lines = []

    for marker in markers:
        off = official.get(marker, [])
        col = collector.get(marker, [])
        if not off:
            failures.append(f"missing official marker={marker}")
            lines.append(f"FAIL missing official marker={marker}")
            continue
        if not col:
            failures.append(f"missing collector marker={marker}")
            lines.append(f"FAIL missing collector marker={marker}")
            continue

        lines.append(f"OK marker={marker} official_rows={len(off)} collector_rows={len(col)}")
        off0 = normalize_row(off[0])
        col0 = normalize_row(col[0], FIELD_MAP)
        for official_field in FIELD_MAP.values():
            if normalize_value(off0.get(official_field)) != normalize_value(col0.get(official_field)):
                failures.append(f"diff marker={marker} field={official_field} official={off0.get(official_field)} collector={col0.get(official_field)}")
                lines.append(f"  DIFF {official_field}: official={off0.get(official_field)} collector={col0.get(official_field)}")

    Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(color("blue", f"REPORT {report_path}"))
    summary = f"SUMMARY markers={len(markers)} official_markers={len(official)} collector_markers={len(collector)} failures={len(failures)}"
    print(color("red" if failures else "green", summary))
    if failures:
        for failure in failures[:50]:
            print(f"FAIL {failure}")
        return 1
    return 0


def parse_time_us(value):
    text = value.strip()
    if not text:
        return None
    if "." in text:
        base, frac = text.split(".", 1)
        frac = (frac + "000000")[:6]
    else:
        base, frac = text, "000000"
    tm = time.strptime(base, "%Y-%m-%d %H:%M:%S")
    return int(time.mktime(tm)) * 1000000 + int(frac)


def parse_args():
    parser = argparse.ArgumentParser(description="Deploy multi-node uprobe, run SQL, export GV$OB_SQL_AUDIT, download collector ADT, compare records.")
    parser.add_argument("--deploy-config", required=True)
    parser.add_argument("--workload", default=str(DEFAULT_WORKLOAD))
    parser.add_argument("--case-name", default="", help="name used for output subdirectory when provided")
    parser.add_argument("--workload-user", default="root@sys")
    parser.add_argument("--workload-password", default="oceanbase")
    parser.add_argument("--workload-database", default="")
    parser.add_argument("--audit-user", default="root@sys")
    parser.add_argument("--audit-password", default="oceanbase")
    parser.add_argument("--ob-host", default="7.27.43.145")
    parser.add_argument("--ob-port", type=int, default=2881)
    parser.add_argument("--mysql-force", action="store_true")
    parser.add_argument("--collector-host", default="")
    parser.add_argument("--collector-user", default="")
    parser.add_argument("--collector-ssh-port", type=int, default=0)
    parser.add_argument("--collector-password", default=None)
    parser.add_argument("--collector-path", default="collector_events.adt")
    parser.add_argument("--collector-local-path", default="", help="copy collector ADT from local path instead of scp")
    parser.add_argument("--collector-stop-wait-seconds", type=float, default=2.0)
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-deploy", action="store_true")
    parser.add_argument("--skip-tools-build", action="store_true")
    parser.add_argument("--no-stop", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_deploy_config(args.deploy_config)
    out_dir = Path(args.out_dir)
    if args.case_name:
        out_dir = out_dir / args.case_name
    out_dir.mkdir(parents=True, exist_ok=True)

    official_tsv = out_dir / "official_ob_sql_audit.tsv"
    collector_adt = out_dir / "collector_events.adt"
    collector_csv = out_dir / "collector_events.csv"

    stage("prepare", f"case={args.case_name or 'single'} workload={args.workload}")
    build_tools(args)

    stage("time window", "capture start timestamp")
    start_time = mysql_scalar(args, "SELECT NOW(6)")
    ok("start_time", start_time)
    end_time = start_time
    try:
        if not args.skip_deploy:
            stage("deploy uprobe")
            deploy_action(args, "deploy")
            ok("deploy done")
        else:
            warn("deploy skipped")
        stage("start uprobe")
        deploy_action(args, "start")
        ok("uprobe started")
        stage("execute workload", Path(args.workload).name)
        execute_workload(args)
        ok("workload done")
        stage("time window", "capture end timestamp")
        end_time = mysql_scalar(args, "SELECT NOW(6)")
        ok("end_time", end_time)
    finally:
        if not args.no_stop:
            stage("stop uprobe", "flush batch to collector")
            deploy_action(args, "stop")
            ok("uprobe stopped")
            time.sleep(args.collector_stop_wait_seconds)
        else:
            warn("stop skipped")

    stage("export official", "GV$OB_SQL_AUDIT")
    export_official(args, start_time, end_time, official_tsv)
    ok("official exported", str(official_tsv))
    stage("download collector")
    download_collector(args, config, collector_adt)
    stage("convert collector", "ADT -> CSV")
    convert_collector(collector_adt, collector_csv)
    ok("collector converted", str(collector_csv))

    stage("compare records")
    compare_code = compare_with_official(args, official_tsv, collector_csv, out_dir)
    if compare_code == 0:
        ok("compare passed", str(out_dir / "compare"))
    else:
        warn("compare failed", str(out_dir / "compare"))
    return compare_code


if __name__ == "__main__":
    raise SystemExit(main())
