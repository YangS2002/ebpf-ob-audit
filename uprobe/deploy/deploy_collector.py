#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[2]
UPROBE_DIR = REPO_ROOT / "uprobe"
DEFAULT_BUILD_DIR = UPROBE_DIR / ".deploy_output_collector"
SYSTEM_LIB_PREFIXES = (
    "/lib64/ld-linux",
    "/lib/x86_64-linux-gnu/ld-linux",
    "/lib/aarch64-linux-gnu/ld-linux",
)


@dataclass
class CollectorNode:
    name: str
    ip: str
    listen_port: int
    deploy_home: str
    listen_addr: str = ""
    advertise_addr: str = ""
    instance_id: str = ""
    runtime: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeployConfig:
    username: str
    port: int
    password: str
    deploy_home: str
    storage: str
    registry_enabled: bool
    registry_etcd_endpoints: str
    registry_service_name: str
    registry_lease_ttl_sec: int
    registry_keepalive_interval_sec: int
    mongodb_uri: str
    mongodb_database: str
    mongodb_collection: str
    mongodb_metrics_collection: str
    mongodb_event_ttl_days: int
    mongodb_metrics_ttl_days: int
    mongodb_app_name: str
    mongodb_write_concern: str
    mongodb_connect_timeout_ms: int
    mongodb_server_selection_timeout_ms: int
    mongodb_socket_timeout_ms: int
    mongodb_pool_min_size: int
    mongodb_pool_max_size: int
    mongodb_insert_concurrency: int
    mongodb_bulk_max_records: int
    mongodb_bulk_max_bytes: int
    mongodb_ordered_insert: bool
    collectors: List[CollectorNode] = field(default_factory=list)


@dataclass
class CmdResult:
    ok: bool
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class NodeResult:
    name: str
    ip: str
    action: str
    ok: bool
    detail: str


class DeployError(Exception):
    pass


def quote_arg(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, dry_run: bool = False, capture: bool = False) -> CmdResult:
    printable = " ".join(quote_arg(arg) for arg in cmd)
    if dry_run:
        print(f"DRY-RUN {printable}")
        return CmdResult(True, 0)
    if not capture:
        print(f"RUN {printable}")
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=capture)
    if capture:
        return CmdResult(result.returncode == 0, result.returncode, result.stdout.strip(), result.stderr.strip())
    return CmdResult(result.returncode == 0, result.returncode)


def require_cmd(cmd: List[str], cwd: Optional[Path] = None, dry_run: bool = False, capture: bool = False) -> CmdResult:
    result = run_cmd(cmd, cwd=cwd, dry_run=dry_run, capture=capture)
    if not result.ok:
        detail = result.stderr or result.stdout or f"exit {result.returncode}"
        raise DeployError(detail)
    return result


def load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError:
        return parse_yaml_subset(path)
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict):
        raise DeployError(f"config root must be mapping: {path}")
    return data


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    return value


def parse_yaml_subset(path: Path) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]
    last_key_at_indent: Dict[int, Tuple[Any, str]] = {}

    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if text.startswith("- "):
            item_text = text[2:].strip()
            if not isinstance(parent, list):
                holder = last_key_at_indent.get(indent)
                if not holder:
                    raise DeployError(f"unsupported yaml list at {path}:{line_no}")
                holder_parent, holder_key = holder
                new_list: List[Any] = []
                holder_parent[holder_key] = new_list
                parent = new_list
                stack.append((indent - 1, parent))
            if ":" in item_text:
                key, value = item_text.split(":", 1)
                item: Dict[str, Any] = {key.strip(): parse_scalar(value)}
                parent.append(item)
                stack.append((indent, item))
                last_key_at_indent[indent + 2] = (item, key.strip())
            else:
                parent.append(parse_scalar(item_text))
            continue

        if ":" not in text:
            raise DeployError(f"unsupported yaml line at {path}:{line_no}: {raw}")
        key, value = text.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not isinstance(parent, dict):
            raise DeployError(f"unsupported yaml mapping at {path}:{line_no}")
        if value == "":
            child: Dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
            last_key_at_indent[indent + 2] = (parent, key)
        else:
            parent[key] = parse_scalar(value)
            last_key_at_indent[indent + 2] = (parent, key)
    return root


def get_path(data: Dict[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def to_yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if text == "" or any(ch in text for ch in [":", "#", " ", "\t"]):
        return '"' + text.replace('"', '\\"') + '"'
    return text


def dump_yaml(data: Dict[str, Any], indent: int = 0) -> List[str]:
    lines: List[str] = []
    prefix = " " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.extend(dump_yaml(value, indent + 2))
        else:
            lines.append(f"{prefix}{key}: {to_yaml_scalar(value)}")
    return lines


def default_collector_runtime() -> Dict[str, Any]:
    return {
        "collector": {
            "listen_addr": "",
            "registry": {
                "enabled": True,
                "etcd_endpoints": "",
                "service_name": "",
                "instance_id": "",
                "advertise_addr": "",
                "lease_ttl_sec": 10,
                "keepalive_interval_sec": 3,
            },
        },
        "storage": {"type": "mongodb"},
        "mongodb": {
            "uri": "",
            "database": "",
            "collection": "",
            "metrics_collection": "audit_pipeline_metrics",
            "event_ttl_days": 3,
            "metrics_ttl_days": 1,
            "app_name": "ebpf-ob-audit-collector",
            "write_concern": "w1",
            "connect_timeout_ms": 2000,
            "server_selection_timeout_ms": 3000,
            "socket_timeout_ms": 5000,
            "pool_min_size": 1,
            "pool_max_size": 4,
            "insert_concurrency": 2,
            "bulk_max_records": 1000,
            "bulk_max_bytes": 4194304,
            "ordered_insert": False,
        },
    }


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "yes")


def parse_host_port(addr: str) -> Tuple[str, int]:
    if ":" not in addr:
        return addr, 0
    host, port = addr.rsplit(":", 1)
    return host, int(port)


def parse_config(path: Path) -> DeployConfig:
    data = load_yaml(path)
    user = get_path(data, "user", {}) or {}
    global_cfg = get_path(data, "collector.global", {}) or {}
    servers = get_path(data, "collector.servers", []) or []

    username = str(user.get("username", ""))
    port = int(user.get("port", 22))
    password = str(user.get("password", ""))
    deploy_home = str(global_cfg.get("deploy_home", "/home/yangshuo17/ebpf-ob-audit-collector"))
    runtime_global = deep_merge(default_collector_runtime(), global_cfg.get("runtime", {}) if isinstance(global_cfg.get("runtime", {}), dict) else {})

    config = DeployConfig(
        username=username,
        port=port,
        password=password,
        deploy_home=deploy_home,
        storage=str(get_path(runtime_global, "storage.type", "mongodb")),
        registry_enabled=bool_value(get_path(runtime_global, "collector.registry.enabled", True)),
        registry_etcd_endpoints=str(get_path(runtime_global, "collector.registry.etcd_endpoints", "")),
        registry_service_name=str(get_path(runtime_global, "collector.registry.service_name", "")),
        registry_lease_ttl_sec=int(get_path(runtime_global, "collector.registry.lease_ttl_sec", 10)),
        registry_keepalive_interval_sec=int(get_path(runtime_global, "collector.registry.keepalive_interval_sec", 3)),
        mongodb_uri=str(get_path(runtime_global, "mongodb.uri", "")),
        mongodb_database=str(get_path(runtime_global, "mongodb.database", "")),
        mongodb_collection=str(get_path(runtime_global, "mongodb.collection", "")),
        mongodb_metrics_collection=str(get_path(runtime_global, "mongodb.metrics_collection", "audit_pipeline_metrics")),
        mongodb_event_ttl_days=int(get_path(runtime_global, "mongodb.event_ttl_days", 3)),
        mongodb_metrics_ttl_days=int(get_path(runtime_global, "mongodb.metrics_ttl_days", 1)),
        mongodb_app_name=str(get_path(runtime_global, "mongodb.app_name", "ebpf-ob-audit-collector")),
        mongodb_write_concern=str(get_path(runtime_global, "mongodb.write_concern", "w1")),
        mongodb_connect_timeout_ms=int(get_path(runtime_global, "mongodb.connect_timeout_ms", 2000)),
        mongodb_server_selection_timeout_ms=int(get_path(runtime_global, "mongodb.server_selection_timeout_ms", 3000)),
        mongodb_socket_timeout_ms=int(get_path(runtime_global, "mongodb.socket_timeout_ms", 5000)),
        mongodb_pool_min_size=int(get_path(runtime_global, "mongodb.pool_min_size", 1)),
        mongodb_pool_max_size=int(get_path(runtime_global, "mongodb.pool_max_size", 4)),
        mongodb_insert_concurrency=int(get_path(runtime_global, "mongodb.insert_concurrency", 2)),
        mongodb_bulk_max_records=int(get_path(runtime_global, "mongodb.bulk_max_records", 1000)),
        mongodb_bulk_max_bytes=int(get_path(runtime_global, "mongodb.bulk_max_bytes", 4194304)),
        mongodb_ordered_insert=bool_value(get_path(runtime_global, "mongodb.ordered_insert", False)),
        collectors=[],
    )

    if isinstance(servers, list):
        for idx, server in enumerate(servers):
            if not isinstance(server, dict):
                continue
            name = str(server.get("name", f"collector{idx + 1}"))
            ip = str(server.get("ip", ""))
            listen_addr = str(server.get("listen_addr", ""))
            advertise_addr = str(server.get("advertise_addr", ""))
            listen_port = int(server.get("listen_port", 0))
            if listen_addr and not listen_port:
                _, listen_port = parse_host_port(listen_addr)
            if not listen_addr:
                listen_addr = f"0.0.0.0:{listen_port}"
            if not advertise_addr and ip and listen_port:
                advertise_addr = f"{ip}:{listen_port}"
            instance_id = str(server.get("instance_id", name))
            node_home = str(server.get("deploy_home", deploy_home))
            node_runtime = deep_merge(runtime_global, server.get("runtime", {}) if isinstance(server.get("runtime", {}), dict) else {})
            node_runtime = deep_merge(node_runtime, {"collector": {"listen_addr": listen_addr, "registry": {
                "instance_id": instance_id,
                "advertise_addr": advertise_addr,
            }}})
            node_runtime = deep_merge(node_runtime, server.get("override", {}) if isinstance(server.get("override", {}), dict) else {})
            config.collectors.append(CollectorNode(name, ip, listen_port, node_home, listen_addr, advertise_addr, instance_id, node_runtime))

    validate_config(config)
    return config


def validate_config(config: DeployConfig) -> None:
    missing: List[str] = []
    if not config.username:
        missing.append("user.username")
    if not config.collectors:
        missing.append("collector.servers")
    for node in config.collectors:
        if not node.ip:
            missing.append(f"collector.servers[{node.name}].ip")
        if not node.listen_port:
            missing.append(f"collector.servers[{node.name}].listen_port")
        if not node.advertise_addr:
            missing.append(f"collector.servers[{node.name}].advertise_addr")
    if missing:
        raise DeployError("missing required config fields: " + ", ".join(missing))


def is_empty_required(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (dict, list, tuple, set)):
        return len(value) == 0
    return False


def add_required_error(errors: List[str], kind: str, node: CollectorNode, field: str) -> None:
    value = get_path(node.runtime, field)
    if is_empty_required(value):
        errors.append(f"CONFIG ERROR {kind} {node.name} {node.ip}: missing runtime.{field}")


def validate_collector_runtime(config: DeployConfig) -> None:
    errors: List[str] = []
    for node in config.collectors:
        add_required_error(errors, "collector", node, "collector.listen_addr")
        add_required_error(errors, "collector", node, "storage.type")
        if get_path(node.runtime, "storage.type", "") == "mongodb":
            add_required_error(errors, "collector", node, "mongodb.uri")
            add_required_error(errors, "collector", node, "mongodb.database")
            add_required_error(errors, "collector", node, "mongodb.collection")
    if errors:
        raise DeployError("\n".join(errors))


def build_collector(skip_build: bool) -> None:
    if skip_build:
        return
    require_cmd(["make", "-C", str(UPROBE_DIR), "bin/audit_collector"])


def verify_collector_binary() -> Path:
    binary = UPROBE_DIR / "bin" / "audit_collector"
    if not binary.exists():
        raise DeployError(f"collector binary not found: {binary}. run make -C {UPROBE_DIR} bin/audit_collector")
    return binary


def parse_ldd_line(line: str) -> Optional[Path]:
    line = line.strip()
    match = re.search(r"=>\s+(/\S+)", line)
    if match:
        return Path(match.group(1))
    match = re.match(r"(/\S+)", line)
    if match:
        return Path(match.group(1))
    return None


def should_bundle_lib(path: Path) -> bool:
    text = str(path)
    if any(text.startswith(prefix) for prefix in SYSTEM_LIB_PREFIXES):
        return False
    name = path.name
    bundle_prefixes = (
        "libgrpc", "libprotobuf", "libabsl", "libgpr", "libcares", "libre2", "libupb",
        "libaddress_sorting", "libstdc++", "libgcc_s", "libssl", "libcrypto", "libz",
        "libmongoc", "libbson", "libsasl", "libsnappy", "libzstd", "libresolv", "libicu",
    )
    return name.startswith(bundle_prefixes)


def collect_libraries(binary: Path, lib_dir: Path) -> List[Path]:
    result = subprocess.run(["ldd", str(binary)], text=True, capture_output=True, check=True)
    libs: List[Path] = []
    copied = set()
    for line in result.stdout.splitlines():
        path = parse_ldd_line(line)
        if path and should_bundle_lib(path) and path.name not in copied:
            shutil.copy2(path, lib_dir / path.name)
            copied.add(path.name)
            libs.append(path)
    return libs


def write_text(path: Path, content: str, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def render_collector_yaml(node: CollectorNode) -> str:
    return "\n".join([
        "# collector 运行时配置，由 deploy_collector.py 根据 collector-deploy YAML 生成。",
        "# 请不要手工修改远端该文件；需要变更时修改部署 YAML 的 global、节点字段或 override。",
        *dump_yaml(node.runtime),
        "",
    ])


def render_start_script() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail
DEPLOY_HOME=$(cd "$(dirname "$0")/.." && pwd)
CONF=${1:-$DEPLOY_HOME/conf/collector.yaml}
COLLECTOR_ID=$(python3 - "$CONF" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding='utf-8') as f:
    data = yaml.safe_load(f)
print(data['collector']['registry']['instance_id'])
PY
)
PORT=$(python3 - "$CONF" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding='utf-8') as f:
    data = yaml.safe_load(f)
print(str(data['collector']['listen_addr']).rsplit(':', 1)[1])
PY
)
if [ -z "${PORT:-}" ]; then
  echo "collector_listen_addr missing in $CONF" >&2
  exit 1
fi
export LD_LIBRARY_PATH="$DEPLOY_HOME/lib:${LD_LIBRARY_PATH:-}"
cd "$DEPLOY_HOME"
mkdir -p "$DEPLOY_HOME/logs" "$DEPLOY_HOME/run"
LOG_FILE="$DEPLOY_HOME/logs/collector.log"
PID_FILE="$DEPLOY_HOME/run/collector-${PORT}.pid"
echo "[$COLLECTOR_ID port=$PORT] event=collector_start config=$CONF log=$LOG_FILE" >> "$LOG_FILE"
"$DEPLOY_HOME/bin/audit_collector" --config "$CONF" 2>&1 | awk -v prefix="[$COLLECTOR_ID port=$PORT] " '{ print prefix $0; fflush(); }' >> "$LOG_FILE"
"""


def make_package(binary: Path, work_dir: Path) -> Path:
    package_root = work_dir / "collector-common"
    if package_root.exists():
        shutil.rmtree(package_root)
    for subdir in ("bin", "lib", "run", "logs", "conf"):
        (package_root / subdir).mkdir(parents=True)
    shutil.copy2(binary, package_root / "bin" / "audit_collector")
    # Field-encoding schema file; collector reads it at startup (default cwd-relative
    # path resolves to deploy_home, matching where start_collector.sh launches).
    schema_file = UPROBE_DIR / "audit_schema.json"
    if not schema_file.exists():
        raise DeployError(f"schema file not found: {schema_file}")
    shutil.copy2(schema_file, package_root / "audit_schema.json")
    write_text(package_root / "run" / "start_collector.sh", render_start_script(), 0o755)
    collect_libraries(binary, package_root / "lib")
    archive = work_dir / "uprobe-collector-common.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(package_root, arcname=".")
    return archive


def maybe_sshpass(config: DeployConfig, cmd: List[str]) -> List[str]:
    if not config.password:
        return cmd
    if shutil.which("sshpass") is None:
        raise DeployError("config has user.password but sshpass is not installed. Install sshpass or configure passwordless SSH.")
    os.environ["SSHPASS"] = config.password
    return ["sshpass", "-e"] + cmd


def ssh_base(config: DeployConfig, host: str) -> List[str]:
    return maybe_sshpass(config, ["ssh", "-p", str(config.port), f"{config.username}@{host}"])


def scp_base(config: DeployConfig, source: Path, host: str, dest: str) -> List[str]:
    return maybe_sshpass(config, ["scp", "-P", str(config.port), str(source), f"{config.username}@{host}:{dest}"])


def remote(config: DeployConfig, node: CollectorNode, command: str, dry_run: bool = False, capture: bool = False) -> CmdResult:
    return run_cmd(ssh_base(config, node.ip) + [command], dry_run=dry_run, capture=capture)


def deploy_node(config: DeployConfig, node: CollectorNode, archive: Path, dry_run: bool) -> NodeResult:
    remote_tmp = f"/tmp/{archive.name}"
    conf_path = archive.parent / f"collector-{node.name}-{node.listen_port}.yaml"
    write_text(conf_path, render_collector_yaml(node))
    remote_conf = f"{node.deploy_home}/conf/collector-{node.listen_port}.yaml"
    require_cmd(ssh_base(config, node.ip) + [f"mkdir -p {quote_arg(node.deploy_home)} {quote_arg(node.deploy_home + '/conf')}"] , dry_run=dry_run)
    require_cmd(scp_base(config, archive, node.ip, remote_tmp), dry_run=dry_run)
    unpack_cmd = f"tar -xzf {quote_arg(remote_tmp)} -C {quote_arg(node.deploy_home)} && rm -f {quote_arg(remote_tmp)}"
    require_cmd(ssh_base(config, node.ip) + [unpack_cmd], dry_run=dry_run)
    require_cmd(scp_base(config, conf_path, node.ip, remote_conf), dry_run=dry_run)
    return NodeResult(node.name, node.ip, "deploy", True, f"deployed to {node.deploy_home}")


def start_node(config: DeployConfig, node: CollectorNode, dry_run: bool) -> NodeResult:
    pattern = "[a]udit_collector --config conf/collector-" + str(node.listen_port) + ".yaml"
    pid_file = f"run/collector-{node.listen_port}.pid"
    cmd = (
        f"cd {quote_arg(node.deploy_home)} && mkdir -p logs run && "
        # 强制重启: 先杀掉该端口已存在的旧实例, 保证是全新进程(累计指标从零开始)。
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$pids\" ]; then kill $pids; sleep 1; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); if [ -n \"$left\" ]; then kill -9 $left; fi; fi; "
        # 无条件清空共享 logs 目录(collector.log / collector_timing.log), 避免旧数据污染下一次统计。
        f"rm -f logs/*; "
        f"nohup ./run/start_collector.sh {quote_arg('conf/collector-' + str(node.listen_port) + '.yaml')} > /dev/null 2>&1 < /dev/null & echo $! > {quote_arg(pid_file)}; state=started; "
        f"sleep 3; "
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if ss -ltn sport = :{node.listen_port} 2>/dev/null | tail -n +2 | grep -q .; then listening=yes; else listening=no; fi; "
        f"if [ -n \"$pids\" ]; then running=yes; else running=no; fi; "
        f"printf 'state=%s running=%s listening=%s port={node.listen_port} pids=%s config=conf/collector-{node.listen_port}.yaml' \"$state\" \"$running\" \"$listening\" \"$pids\"; "
        f"if [ \"$running\" != yes ] || [ \"$listening\" != yes ]; then exit 1; fi"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if dry_run:
        return NodeResult(node.name, node.ip, "start", True, "dry-run")
    detail = compact((result.stdout + "\n" + result.stderr).strip(), 300)
    if not result.ok:
        raise DeployError(detail or f"exit {result.returncode}")
    return NodeResult(node.name, node.ip, "start", True, detail or "started")


def stop_node(config: DeployConfig, node: CollectorNode, dry_run: bool) -> NodeResult:
    pattern = "[a]udit_collector --config conf/collector-" + str(node.listen_port) + ".yaml"
    cmd = (
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -z \"$pids\" ]; then echo state=not_running; exit 0; fi; "
        f"kill $pids; "
        f"for i in $(seq 1 15); do "
        f"sleep 1; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -z \"$left\" ]; then break; fi; "
        f"done; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$left\" ]; then kill -9 $left; fi; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$left\" ]; then echo state=failed; exit 1; else echo state=stopped; fi"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    return NodeResult(node.name, node.ip, "stop", True, compact(result.stdout, 160) or "stopped")


def logs_node(config: DeployConfig, node: CollectorNode, dry_run: bool) -> NodeResult:
    log_file = f"{node.deploy_home}/logs/collector.log"
    cmd = (
        f"printf 'node=%s ip=%s log=%s lines=50\\n' {quote_arg(node.name)} {quote_arg(node.ip)} {quote_arg(log_file)}; "
        f"if [ -f {quote_arg(log_file)} ]; then tail -n 50 {quote_arg(log_file)}; else echo 'log_missing'; fi"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    if dry_run:
        return NodeResult(node.name, node.ip, "logs", True, "dry-run")
    return NodeResult(node.name, node.ip, "logs", True, result.stdout)


def clean_node(config: DeployConfig, node: CollectorNode, dry_run: bool) -> NodeResult:
    stop_detail = ""
    if not dry_run:
        try:
            stop_detail = stop_node(config, node, dry_run=False).detail
        except DeployError as exc:
            stop_detail = f"stop failed before clean: {exc}"
    cmd = f"rm -rf {quote_arg(node.deploy_home)} && echo cleaned:{quote_arg(node.deploy_home)}"
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    return NodeResult(node.name, node.ip, "clean", True, compact((stop_detail + "\n" + result.stdout).strip()))


def clear_logs_node(config: DeployConfig, node: CollectorNode, dry_run: bool) -> NodeResult:
    cmd = (
        f"mkdir -p {quote_arg(node.deploy_home + '/logs')} && "
        f": > {quote_arg(node.deploy_home + '/logs/collector.log')} && "
        f"rm -f {quote_arg(node.deploy_home + '/logs')}/collector-*.log && "
        f"echo cleared:{quote_arg(node.deploy_home + '/logs/collector.log')}"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    return NodeResult(node.name, node.ip, "clear-logs", True, compact(result.stdout, 180) or "logs cleared")


def compact(text: str, limit: int = 600) -> str:
    text = " | ".join(line.strip() for line in text.splitlines() if line.strip())
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def print_summary(results: List[NodeResult]) -> None:
    print("\nSUMMARY")
    print(f"{'RESULT':6} {'ACTION':12} {'NODE':12} {'IP':15} DETAIL")
    for result in results:
        status = "OK" if result.ok else "FAIL"
        print(f"{status:6} {result.action:12} {result.name:12} {result.ip:15} {result.detail}")


def render_collector_start_for_node(node: CollectorNode) -> str:
    conf_rel = f"conf/collector-{node.listen_port}.yaml"
    return f"""#!/usr/bin/env bash
set -euo pipefail
DEPLOY_HOME=$(cd "$(dirname "$0")/.." && pwd)
CONF="$DEPLOY_HOME/{conf_rel}"
export LD_LIBRARY_PATH="$DEPLOY_HOME/lib:${{LD_LIBRARY_PATH:-}}"
cd "$DEPLOY_HOME"
mkdir -p "$DEPLOY_HOME/logs" "$DEPLOY_HOME/run"
LOG_FILE="$DEPLOY_HOME/logs/collector.log"
echo "[{node.instance_id} port={node.listen_port}] event=collector_start config=$CONF log=$LOG_FILE" >> "$LOG_FILE"
"$DEPLOY_HOME/bin/audit_collector" --config "$CONF" 2>&1 | awk -v prefix="[{node.instance_id} port={node.listen_port}] " '{{ print prefix $0; fflush(); }}' >> "$LOG_FILE"
"""


def render_install_note_collector(node: CollectorNode, archive_name: str) -> str:
    dh = node.deploy_home
    conf_rel = f"conf/collector-{node.listen_port}.yaml"
    return "\n".join([
        f"# eBPF OB Audit collector 手动部署  instance={node.instance_id} ip={node.ip} port={node.listen_port}",
        "# 前置: 目标机可达 MongoDB 与 etcd (etcd 注册模式)。",
        "",
        "1) 上传到目标机:",
        f"   scp {archive_name} <user>@{node.ip}:/tmp/",
        "2) 解包到部署目录:",
        f"   mkdir -p {dh} && tar -xzf /tmp/{archive_name} -C {dh}",
        f"3) 核对 {conf_rel}: collector.listen_addr / mongodb.uri /",
        "   collector.registry.etcd_endpoints / service_name / advertise_addr (agent 可达地址)。",
        "4) 启动:",
        f"   cd {dh} && nohup ./run/start_collector.sh >/dev/null 2>&1 &",
        f"5) 日志: tail -f {dh}/logs/collector.log",
        f"6) 停止: pkill -f 'audit_collector --config {conf_rel}'",
        "",
    ])


def build_lib_cache(binary: Path, work_dir: Path) -> Path:
    lib_cache = work_dir / "_libcache"
    if lib_cache.exists():
        shutil.rmtree(lib_cache)
    lib_cache.mkdir(parents=True)
    collect_libraries(binary, lib_cache)
    return lib_cache


def package_node(node: CollectorNode, binary: Path, lib_cache: Path, work_dir: Path) -> NodeResult:
    root = work_dir / f"collector-{node.name}-{node.listen_port}"
    if root.exists():
        shutil.rmtree(root)
    for subdir in ("bin", "lib", "run", "conf", "logs"):
        (root / subdir).mkdir(parents=True)
    shutil.copy2(binary, root / "bin" / "audit_collector")
    schema_file = UPROBE_DIR / "audit_schema.json"
    if not schema_file.exists():
        raise DeployError(f"schema file not found: {schema_file}")
    shutil.copy2(schema_file, root / "audit_schema.json")
    for lib in lib_cache.iterdir():
        shutil.copy2(lib, root / "lib" / lib.name)
    write_text(root / "run" / "start_collector.sh", render_collector_start_for_node(node), 0o755)
    write_text(root / "conf" / f"collector-{node.listen_port}.yaml", render_collector_yaml(node))
    archive = work_dir / f"uprobe-collector-{node.name}-{node.listen_port}.tar.gz"
    write_text(root / "INSTALL.txt", render_install_note_collector(node, archive.name))
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=".")
    return NodeResult(node.name, node.ip, "package", True, str(archive))


def package_all(config: DeployConfig, build_dir: Path, skip_build: bool, continue_on_failure: bool) -> List[NodeResult]:
    validate_collector_runtime(config)
    build_collector(skip_build)
    binary = verify_collector_binary()
    build_dir.mkdir(parents=True, exist_ok=True)
    lib_cache = build_lib_cache(binary, build_dir)
    results: List[NodeResult] = []
    for node in config.collectors:
        try:
            result = package_node(node, binary, lib_cache, build_dir)
            print(f"PACKAGE OK {node.name} {node.ip}: {result.detail}")
            results.append(result)
        except DeployError as exc:
            print(f"PACKAGE FAIL {node.name} {node.ip}: {exc}", file=sys.stderr)
            results.append(NodeResult(node.name, node.ip, "package", False, str(exc)))
            if not continue_on_failure:
                break
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build, package, deploy, start, stop, clean, check, and clear audit collector logs over SSH.")
    parser.add_argument("-c", "--config", required=True, help="collector deploy yaml path")
    parser.add_argument("--action", choices=["deploy", "deploy-start", "start", "stop", "logs", "clean", "restart", "clear-logs", "package"], default="deploy", help="remote action; 'package' builds self-contained per-instance tarballs locally (no SSH)")
    parser.add_argument("--skip-build", action="store_true", help="skip local make build")
    parser.add_argument("--dry-run", action="store_true", help="print commands without modifying remote machines")
    parser.add_argument("--continue-on-failure", action="store_true", help="continue remaining nodes after a node fails")
    parser.add_argument("--build-dir", default=str(DEFAULT_BUILD_DIR), help="local deploy work directory")
    return parser.parse_args()


def prepare_archive(args: argparse.Namespace, build_dir: Path) -> Optional[Path]:
    if args.action not in ("deploy", "deploy-start"):
        return None
    build_collector(args.skip_build)
    binary = verify_collector_binary()
    archive = make_package(binary, build_dir)
    print(f"PACKAGE common: {archive}")
    return archive


def run_action(args: argparse.Namespace, config: DeployConfig, node: CollectorNode, archive: Optional[Path]) -> List[NodeResult]:
    if args.action == "deploy":
        if archive is None:
            raise DeployError("missing package archive")
        return [deploy_node(config, node, archive, args.dry_run)]
    if args.action == "deploy-start":
        if archive is None:
            raise DeployError("missing package archive")
        return [deploy_node(config, node, archive, args.dry_run), start_node(config, node, args.dry_run)]
    if args.action == "start":
        return [start_node(config, node, args.dry_run)]
    if args.action == "stop":
        return [stop_node(config, node, args.dry_run)]
    if args.action == "logs":
        return [logs_node(config, node, args.dry_run)]
    if args.action == "clean":
        return [clean_node(config, node, args.dry_run)]
    if args.action == "clear-logs":
        return [clear_logs_node(config, node, args.dry_run)]
    if args.action == "restart":
        return [stop_node(config, node, args.dry_run), start_node(config, node, args.dry_run)]
    raise DeployError(f"unknown action: {args.action}")


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    build_dir = Path(args.build_dir).resolve()
    results: List[NodeResult] = []
    try:
        config = parse_config(config_path)
        if args.action == "package":
            results = package_all(config, build_dir, args.skip_build, args.continue_on_failure)
            print_summary(results)
            return 0 if results and all(result.ok for result in results) else 1
        if args.action in ("start", "deploy-start"):
            validate_collector_runtime(config)
        if config.password:
            print("INFO using user.password for SSH via sshpass.")
        build_dir.mkdir(parents=True, exist_ok=True)
        archive = prepare_archive(args, build_dir)
        seen = set()
        for node in config.collectors:
            key = (node.ip, node.deploy_home) if args.action in ("clear-logs", "logs") else None
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            try:
                node_results = run_action(args, config, node, archive)
                results.extend(node_results)
                for result in node_results:
                    print(f"{result.action.upper()} {'OK' if result.ok else 'FAIL'} {node.name} {node.ip}: {result.detail}")
            except DeployError as exc:
                failed = NodeResult(node.name, node.ip, args.action, False, str(exc))
                results.append(failed)
                print(f"{args.action.upper()} FAIL {node.name} {node.ip}: {exc}", file=sys.stderr)
                if not args.continue_on_failure:
                    print_summary(results)
                    return 1
        print_summary(results)
        return 0 if all(result.ok for result in results) else 1
    except (DeployError, subprocess.CalledProcessError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        if results:
            print_summary(results)
        return 1


if __name__ == "__main__":
    sys.exit(main())
