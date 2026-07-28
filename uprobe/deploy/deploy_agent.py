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
DEFAULT_BUILD_DIR = UPROBE_DIR / ".deploy_output"
SYSTEM_LIB_PREFIXES = (
    "/lib64/ld-linux",
    "/lib/x86_64-linux-gnu/ld-linux",
    "/lib/aarch64-linux-gnu/ld-linux",
)


@dataclass
class Node:
    name: str
    ip: str
    deploy_home: str
    observer_path: str = ""
    offset: str = ""
    output_file: str = "out.adt"


@dataclass
class DeployConfig:
    username: str
    port: int
    password: str
    sudo_password: str
    deploy_home: str
    collector_addr: str
    collector_discovery_enabled: bool
    collector_discovery_etcd_endpoints: str
    collector_discovery_service_name: str
    collector_discovery_watch: bool
    collector_discovery_retry_interval_ms: int
    collector_discovery_selection_policy: str
    grpc_batch_bytes: int
    grpc_timeout_ms: int
    observer_path: str
    offset: str
    output_file: str
    nodes: List[Node] = field(default_factory=list)


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
    if capture:
        result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True)
        return CmdResult(result.returncode == 0, result.returncode, result.stdout.strip(), result.stderr.strip())
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
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


def parse_config(path: Path) -> DeployConfig:
    data = load_yaml(path)
    user = get_path(data, "user", {}) or {}
    agent_global = get_path(data, "agent.global", {}) or {}
    ob_global = get_path(data, "oceanbase-ce.global", {}) or {}
    servers = get_path(data, "oceanbase-ce.servers", []) or []

    username = str(user.get("username", ""))
    port = int(user.get("port", 22))
    password = str(user.get("password", ""))
    sudo_password = str(user.get("sudo_password", user.get("user_password", "")))
    deploy_home = str(agent_global.get("deploy_home", "~/ebpf-ob-audit-agent"))
    collector_addr = str(agent_global.get("collector_addr", ""))
    collector_discovery_enabled = bool(agent_global.get("collector_discovery_enabled", True))
    collector_discovery_etcd_endpoints = str(agent_global.get("collector_discovery_etcd_endpoints", "http://7.27.43.139:2379"))
    collector_discovery_service_name = str(agent_global.get("collector_discovery_service_name", "audit-collector"))
    collector_discovery_watch = bool(agent_global.get("collector_discovery_watch", True))
    collector_discovery_retry_interval_ms = int(agent_global.get("collector_discovery_retry_interval_ms", 3000))
    collector_discovery_selection_policy = str(agent_global.get("collector_discovery_selection_policy", "hash_agent"))
    grpc_batch_bytes = int(agent_global.get("grpc_batch_bytes", 262144))
    grpc_timeout_ms = int(agent_global.get("grpc_timeout_ms", 2000))
    observer_path = str(agent_global.get("observer_path", ""))
    offset = str(agent_global.get("offset", ""))
    output_file = str(agent_global.get("output_file", "out.adt"))

    if not observer_path:
        home_path = str(ob_global.get("home_path", ""))
        if home_path:
            observer_path = f"{home_path}/bin/observer"

    nodes: List[Node] = []
    if isinstance(servers, list):
        for idx, server in enumerate(servers):
            if not isinstance(server, dict):
                continue
            name = str(server.get("name", f"node{idx + 1}"))
            ip = str(server.get("ip", ""))
            node_cfg = get_path(data, f"agent.{name}", {}) or {}
            nodes.append(Node(
                name=name,
                ip=ip,
                deploy_home=str(node_cfg.get("deploy_home", deploy_home)),
                observer_path=str(node_cfg.get("observer_path", observer_path)),
                offset=str(node_cfg.get("offset", offset)),
                output_file=str(node_cfg.get("output_file", output_file)),
            ))

    config = DeployConfig(username, port, password, sudo_password, deploy_home, collector_addr,
                          collector_discovery_enabled, collector_discovery_etcd_endpoints,
                          collector_discovery_service_name, collector_discovery_watch,
                          collector_discovery_retry_interval_ms, collector_discovery_selection_policy,
                          grpc_batch_bytes, grpc_timeout_ms, observer_path, offset, output_file, nodes)
    validate_config(config)
    return config


def validate_config(config: DeployConfig) -> None:
    missing: List[str] = []
    if not config.username:
        missing.append("user.username")
    if not config.nodes:
        missing.append("oceanbase-ce.servers")
    for node in config.nodes:
        if not node.ip:
            missing.append(f"oceanbase-ce.servers[{node.name}].ip")
    if missing:
        raise DeployError("missing required config fields: " + ", ".join(missing))


def build_agent(skip_build: bool) -> None:
    if skip_build:
        return
    require_cmd(["make", "-C", str(UPROBE_DIR)])


def verify_agent_binary() -> Path:
    binary = UPROBE_DIR / "bin" / "uprobe"
    if not binary.exists():
        raise DeployError(f"agent binary not found: {binary}. run make -C {UPROBE_DIR}")
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
        "libaddress_sorting", "libstdc++", "libgcc_s", "libssl", "libcrypto",
    )
    return name.startswith(bundle_prefixes)


def collect_libraries(binary: Path, lib_dir: Path) -> List[Path]:
    result = subprocess.run(["ldd", str(binary)], text=True, capture_output=True, check=True)
    libs: List[Path] = []
    for line in result.stdout.splitlines():
        path = parse_ldd_line(line)
        if path and should_bundle_lib(path):
            shutil.copy2(path, lib_dir / path.name)
            libs.append(path)
    return libs


def write_text(path: Path, content: str, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def render_uprobe_conf(config: DeployConfig, node: Node) -> str:
    return "\n".join([
        "# generated by uprobe/deploy/deploy_agent.py",
        f"server_ip={node.ip}",
        f"agent_id=agent-{node.name}-{node.ip}",
        "",
        f"collector_addr={config.collector_addr}",
        f"collector_discovery_enabled={str(config.collector_discovery_enabled).lower()}",
        f"collector_discovery_etcd_endpoints={config.collector_discovery_etcd_endpoints}",
        f"collector_discovery_service_name={config.collector_discovery_service_name}",
        f"collector_discovery_watch={str(config.collector_discovery_watch).lower()}",
        f"collector_discovery_retry_interval_ms={config.collector_discovery_retry_interval_ms}",
        f"collector_discovery_selection_policy={config.collector_discovery_selection_policy}",
        "",
        f"grpc_batch_bytes={config.grpc_batch_bytes}",
        f"grpc_timeout_ms={config.grpc_timeout_ms}",
        "grpc_queue_bytes=262144",
        "grpc_retry_initial_ms=100",
        "grpc_retry_max_ms=500",
        "",
    ])


def render_start_script(config: DeployConfig) -> str:
    observer = config.observer_path or "<observer-path>"
    offset = config.offset or "<offset>"
    output_file = config.output_file or "out.adt"
    incomplete = "" if config.observer_path and config.offset else "\necho 'startup command incomplete: set observer_path and offset' >&2\nexit 1\n"
    return f"""#!/usr/bin/env bash
set -euo pipefail
DEPLOY_HOME=$(cd "$(dirname "$0")/.." && pwd)
export LD_LIBRARY_PATH="$DEPLOY_HOME/lib:${{LD_LIBRARY_PATH:-}}"
mkdir -p "$DEPLOY_HOME/logs"
	export UPROBE_LOG_FILE="$DEPLOY_HOME/agent.log"
	: > "$UPROBE_LOG_FILE"
	{incomplete}exec "$DEPLOY_HOME/bin/uprobe" "{observer}" "{offset}" "$DEPLOY_HOME/{output_file}" "$DEPLOY_HOME/conf/uprobe.conf"
"""


def make_package(config: DeployConfig, binary: Path, work_dir: Path) -> Path:
    package_root = work_dir / "agent-common"
    if package_root.exists():
        shutil.rmtree(package_root)
    for subdir in ("bin", "lib", "run", "logs"):
        (package_root / subdir).mkdir(parents=True)

    shutil.copy2(binary, package_root / "bin" / "uprobe")
    write_text(package_root / "run" / "start_agent.sh", render_start_script(config), 0o755)
    collect_libraries(binary, package_root / "lib")

    archive = work_dir / "uprobe-agent-common.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(package_root, arcname=".")
    return archive


def maybe_sshpass(config: DeployConfig, cmd: List[str]) -> List[str]:
    if not config.password:
        return cmd
    if shutil.which("sshpass") is None:
        raise DeployError("config has user.password but sshpass is not installed. Install sshpass on deploy machine or configure passwordless SSH.")
    os.environ["SSHPASS"] = config.password
    return ["sshpass", "-e"] + cmd


def ssh_base(config: DeployConfig, host: str) -> List[str]:
    return maybe_sshpass(config, ["ssh", "-p", str(config.port), f"{config.username}@{host}"])


def scp_base(config: DeployConfig, source: Path, host: str, dest: str) -> List[str]:
    return maybe_sshpass(config, ["scp", "-P", str(config.port), str(source), f"{config.username}@{host}:{dest}"])


def remote(config: DeployConfig, node: Node, command: str, dry_run: bool = False, capture: bool = False) -> CmdResult:
    return run_cmd(ssh_base(config, node.ip) + [command], dry_run=dry_run, capture=capture)


def deploy_node(config: DeployConfig, node: Node, archive: Path, dry_run: bool) -> NodeResult:
    remote_tmp = f"/tmp/{archive.name}"
    conf_path = archive.parent / f"uprobe-{node.name}-{node.ip}.conf"
    write_text(conf_path, render_uprobe_conf(config, node))
    remote_conf = f"{node.deploy_home}/conf/uprobe.conf"
    require_cmd(ssh_base(config, node.ip) + [f"mkdir -p {quote_arg(node.deploy_home)} {quote_arg(node.deploy_home + '/conf')}"], dry_run=dry_run)
    require_cmd(scp_base(config, archive, node.ip, remote_tmp), dry_run=dry_run)
    unpack_cmd = f"tar -xzf {quote_arg(remote_tmp)} -C {quote_arg(node.deploy_home)} && rm -f {quote_arg(remote_tmp)}"
    require_cmd(ssh_base(config, node.ip) + [unpack_cmd], dry_run=dry_run)
    require_cmd(scp_base(config, conf_path, node.ip, remote_conf), dry_run=dry_run)
    return NodeResult(node.name, node.ip, "deploy", True, f"deployed to {node.deploy_home}")


def sudo_start_background(config: DeployConfig, command: str, log_file: str) -> str:
    if config.sudo_password:
        return f"(printf '%s\\n' {quote_arg(config.sudo_password)} | sudo -S -p '' -E {command}) > {log_file} 2>&1 < /dev/null &"
    return f"nohup sudo -n -E {command} > {log_file} 2>&1 < /dev/null &"


def sudo_prefix(config: DeployConfig) -> str:
    if config.sudo_password:
        return f"printf '%s\\n' {quote_arg(config.sudo_password)} | sudo -S -p '' -E"
    return "sudo -n -E"


def sudo_kill_prefix(config: DeployConfig) -> str:
    if config.sudo_password:
        return f"printf '%s\\n' {quote_arg(config.sudo_password)} | sudo -S -p ''"
    return "sudo -n"


def start_node(config: DeployConfig, node: Node, dry_run: bool) -> NodeResult:
    if not node.observer_path or not node.offset:
        missing = []
        if not node.observer_path:
            missing.append("observer_path")
        if not node.offset:
            missing.append("offset")
        raise DeployError("missing " + ", ".join(missing))
    pattern = node.deploy_home + "/bin/[u]probe"
    start_cmd = sudo_start_background(config, "./run/start_agent.sh", "logs/uprobe.log")
    agent_log = "agent.log"
    cmd = (
        f"cd {quote_arg(node.deploy_home)} && mkdir -p logs run && "
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$pids\" ]; then state=already_running; "
        f"else "
        f"{start_cmd} echo $! > run/agent.pid; state=started; "
        f"fi; "
        f"sleep 3; "
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$pids\" ]; then running=yes; else running=no; fi; "
        f"if grep -q 'event=attach_success' {agent_log} 2>/dev/null; then attach=ok; "
        f"elif grep -q 'event=attach_failed\|event=bpf_load_failed\|event=ring_buffer_create_failed' {agent_log} 2>/dev/null; then attach=fail; "
        f"else attach=unknown; fi; "
        f"if grep -q 'event=collector_state state=READY' {agent_log} 2>/dev/null; then grpc=ready; "
        f"elif grep -q 'event=collector_connect discovery=etcd target=<none>' {agent_log} 2>/dev/null; then grpc=waiting; "
        f"else grpc=unknown; fi; "
        f"printf 'state=%s running=%s attach=%s grpc=%s\\n' \"$state\" \"$running\" \"$attach\" \"$grpc\"; "
        f"if [ \"$running\" != yes ]; then echo log_tail:; tail -n 30 {agent_log} logs/uprobe.log 2>/dev/null || true; exit 1; fi; "
        f"if [ \"$grpc\" != ready ]; then echo log_tail:; tail -n 30 {agent_log} logs/uprobe.log 2>/dev/null || true; exit 1; fi"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if dry_run:
        return NodeResult(node.name, node.ip, "start", True, "dry-run")
    detail = compact((result.stdout + "\n" + result.stderr).strip(), 500)
    if not result.ok:
        raise DeployError(detail or f"exit {result.returncode}")
    if "running=yes" not in result.stdout:
        raise DeployError(detail or "start command returned but uprobe process not found")
    return NodeResult(node.name, node.ip, "start", True, detail or "started")


def stop_node(config: DeployConfig, node: Node, dry_run: bool) -> NodeResult:
    pattern = node.deploy_home + "/bin/[u]probe"
    sudo_kill = sudo_kill_prefix(config)
    cmd = (
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -z \"$pids\" ]; then echo state=not_running; exit 0; fi; "
        f"{sudo_kill} kill $pids; sleep 1; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$left\" ]; then {sudo_kill} kill -9 $left; fi; "
        f"left=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$left\" ]; then echo state=failed; exit 1; else echo state=stopped; fi"
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    return NodeResult(node.name, node.ip, "stop", True, compact(result.stdout, 160) or "stopped")


def status_node(config: DeployConfig, node: Node, dry_run: bool) -> NodeResult:
    pattern = node.deploy_home + "/bin/[u]probe"
    cmd = (
        f"if [ -d {quote_arg(node.deploy_home)} ]; then deploy=present; else deploy=missing; fi; "
        f"pids=$(pgrep -f {quote_arg(pattern)} || true); "
        f"if [ -n \"$pids\" ]; then running=yes; else running=no; fi; "
        f"if grep -q 'event=attach_success' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null; then attach=ok; "
        f"elif grep -q 'event=attach_failed\|event=bpf_load_failed\|event=ring_buffer_create_failed' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null; then attach=fail; "
        f"else attach=unknown; fi; "
        f"grpc=unknown; "
        f"if grep -q 'event=collector_state state=READY' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null; then grpc=ready; fi; "
        f"if grep -q 'event=collector_connect discovery=etcd target=<none>' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null; then grpc=waiting; fi; "
        f"if grep -q 'grpc upload failed' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null; then grpc=upload_failed; fi; "
        f"target=$(grep 'event=collector_connect ' {quote_arg(node.deploy_home)}/agent.log 2>/dev/null | tail -n 1 | tr ' ' '\n' | grep '^target=' | tail -n 1 | cut -d= -f2-); "
        f"printf 'deploy=%s running=%s attach=%s grpc=%s target=%s' \"$deploy\" \"$running\" \"$attach\" \"$grpc\" \"${{target:-unknown}}\""
    )
    result = remote(config, node, cmd, dry_run=dry_run, capture=True)
    if not result.ok:
        raise DeployError(result.stderr or result.stdout or f"exit {result.returncode}")
    if dry_run:
        return NodeResult(node.name, node.ip, "status", True, "dry-run")
    return NodeResult(node.name, node.ip, "status", True, compact(result.stdout, 240))


def clean_node(config: DeployConfig, node: Node, dry_run: bool) -> NodeResult:
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
    detail = compact((stop_detail + "\n" + result.stdout).strip())
    return NodeResult(node.name, node.ip, "clean", True, detail or "cleaned")


def split_collector(value: str) -> Tuple[str, str]:
    if not value or ":" not in value:
        return "", ""
    host, port = value.rsplit(":", 1)
    return host.strip(), port.strip()


def compact(text: str, limit: int = 600) -> str:
    text = " | ".join(line.strip() for line in text.splitlines() if line.strip())
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def print_start_command(node: Node) -> None:
    if node.observer_path and node.offset:
        cmd = f"cd {quote_arg(node.deploy_home)} && sudo ./run/start_agent.sh"
        print(f"START {node.name} {node.ip}: {cmd}")
    else:
        missing = []
        if not node.observer_path:
            missing.append("observer_path")
        if not node.offset:
            missing.append("offset")
        print(f"START {node.name} {node.ip}: incomplete, missing {', '.join(missing)}")
        print(f"       edit {node.deploy_home}/conf/uprobe.conf if needed, then run {node.deploy_home}/run/start_agent.sh")


def print_summary(results: List[NodeResult]) -> None:
    print("\nSUMMARY")
    print(f"{'RESULT':6} {'ACTION':12} {'NODE':8} {'IP':15} DETAIL")
    for result in results:
        status = "OK" if result.ok else "FAIL"
        print(f"{status:6} {result.action:12} {result.name:8} {result.ip:15} {result.detail}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build, package, deploy, start, stop, clean, and check uprobe agents over SSH.")
    parser.add_argument("-c", "--config", required=True, help="OBD-like deploy yaml path")
    parser.add_argument("--action", choices=["deploy", "deploy-start", "start", "stop", "status", "clean", "restart"], default="deploy", help="remote action")
    parser.add_argument("--skip-build", action="store_true", help="skip local make build")
    parser.add_argument("--dry-run", action="store_true", help="print commands without modifying remote machines")
    parser.add_argument("--continue-on-failure", action="store_true", help="continue remaining nodes after a node fails")
    parser.add_argument("--build-dir", default=str(DEFAULT_BUILD_DIR), help="local deploy work directory")
    return parser.parse_args()


def prepare_archives(args: argparse.Namespace, config: DeployConfig, build_dir: Path) -> Dict[str, Path]:
    if args.action not in ("deploy", "deploy-start"):
        return {}
    build_agent(args.skip_build)
    binary = verify_agent_binary()
    archive = make_package(config, binary, build_dir)
    print(f"PACKAGE common: {archive}")
    return {node.name: archive for node in config.nodes}


def run_action(args: argparse.Namespace, config: DeployConfig, node: Node, archives: Dict[str, Path]) -> List[NodeResult]:
    if args.action == "deploy":
        return [deploy_node(config, node, archives[node.name], args.dry_run)]
    if args.action == "deploy-start":
        return [
            deploy_node(config, node, archives[node.name], args.dry_run),
            start_node(config, node, args.dry_run),
            status_node(config, node, args.dry_run),
        ]
    if args.action == "start":
        return [start_node(config, node, args.dry_run), status_node(config, node, args.dry_run)]
    if args.action == "stop":
        return [stop_node(config, node, args.dry_run), status_node(config, node, args.dry_run)]
    if args.action == "status":
        return [status_node(config, node, args.dry_run)]
    if args.action == "clean":
        return [clean_node(config, node, args.dry_run)]
    if args.action == "restart":
        return [stop_node(config, node, args.dry_run), start_node(config, node, args.dry_run), status_node(config, node, args.dry_run)]
    raise DeployError(f"unknown action: {args.action}")


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    build_dir = Path(args.build_dir).resolve()
    results: List[NodeResult] = []
    try:
        config = parse_config(config_path)
        if config.password:
            print("INFO using user.password for SSH via sshpass. If sshpass is missing, install requirements/system dependency or configure passwordless SSH.")
        if config.sudo_password:
            print("INFO using user.sudo_password for remote sudo.")
        build_dir.mkdir(parents=True, exist_ok=True)
        archives = prepare_archives(args, config, build_dir)
        for node in config.nodes:
            try:
                node_results = run_action(args, config, node, archives)
                results.extend(node_results)
                for result in node_results:
                    print(f"{result.action.upper()} {'OK' if result.ok else 'FAIL'} {node.name} {node.ip}: {result.detail}")
                if args.action in ("deploy",):
                    print_start_command(node)
            except DeployError as exc:
                failed = NodeResult(node.name, node.ip, args.action, False, str(exc))
                results.append(failed)
                print(f"{args.action.upper()} FAIL {node.name} {node.ip}: {exc}", file=sys.stderr)
                if not args.continue_on_failure:
                    print_summary(results)
                    return 1
        print_summary(results)
        return 0 if all(result.ok for result in results if result.action != "status") else 1 if any(not result.ok and result.action != "status" for result in results) else 0
    except (DeployError, subprocess.CalledProcessError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        if results:
            print_summary(results)
        return 1


if __name__ == "__main__":
    sys.exit(main())
