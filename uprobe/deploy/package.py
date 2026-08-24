#!/usr/bin/env python3
"""合并打包：一次性产出包含 agent 与 collector 的单一目录。

- 复用 deploy_agent.py / deploy_collector.py 的构建与依赖库收集逻辑。
- 不渲染/生成任何配置文件；直接拷贝 deploy/ 下用户维护的默认配置文件
  （agent.yaml / collector.yaml）。因所有节点配置一致（server_ip/advertise_addr
  留空由程序自动探测、id 自动派生），一份配置即可分发到所有机器。

产物目录结构（self-contained，逐机上传对应子目录即可）：
    <build-dir>/<name>/
      agent/     bin/uprobe  lib/*.so  conf/agent.yaml  start_agent.sh  logs/ run/
      collector/ bin/audit_collector  lib/*.so  audit_schema.json
                 conf/collector.yaml  start_collector.sh  logs/ run/
"""
import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deploy_agent as agent
import deploy_collector as collector

DEPLOY_DIR = Path(__file__).resolve().parent
UPROBE_DIR = DEPLOY_DIR.parent
DEFAULT_BUILD_DIR = UPROBE_DIR / ".deploy_bundle"
DEFAULT_AGENT_CONF = DEPLOY_DIR / "agent.yaml"
DEFAULT_COLLECTOR_CONF = DEPLOY_DIR / "collector.yaml"

AGENT_START = """#!/usr/bin/env bash
# BPF 需要 root/CAP_BPF：请用 sudo ./start_agent.sh 运行。
set -euo pipefail
DEPLOY_HOME=$(cd "$(dirname "$0")" && pwd)
export LD_LIBRARY_PATH="$DEPLOY_HOME/lib:${LD_LIBRARY_PATH:-}"
mkdir -p "$DEPLOY_HOME/logs" "$DEPLOY_HOME/run"
export UPROBE_LOG_FILE="$DEPLOY_HOME/logs/agent.log"
: > "$UPROBE_LOG_FILE"
exec "$DEPLOY_HOME/bin/uprobe" "$DEPLOY_HOME/conf/agent.yaml"
"""

COLLECTOR_START = """#!/usr/bin/env bash
set -euo pipefail
DEPLOY_HOME=$(cd "$(dirname "$0")" && pwd)
CONF="${1:-$DEPLOY_HOME/conf/collector.yaml}"
export LD_LIBRARY_PATH="$DEPLOY_HOME/lib:${LD_LIBRARY_PATH:-}"
cd "$DEPLOY_HOME"
mkdir -p logs run
exec "$DEPLOY_HOME/bin/audit_collector" --config "$CONF" >> "$DEPLOY_HOME/logs/collector.log" 2>&1
"""


def _reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def build_bundle(build_dir: Path, name: str, agent_conf: Path, collector_conf: Path, skip_build: bool) -> Path:
    if not agent_conf.exists():
        raise SystemExit(f"agent config not found: {agent_conf}（请在 deploy/ 下放置默认配置文件）")
    if not collector_conf.exists():
        raise SystemExit(f"collector config not found: {collector_conf}（请在 deploy/ 下放置默认配置文件）")

    agent.build_agent(skip_build)
    collector.build_collector(skip_build)
    agent_bin = agent.verify_agent_binary()
    collector_bin = collector.verify_collector_binary()
    schema_file = UPROBE_DIR / "audit_schema.json"
    if not schema_file.exists():
        raise SystemExit(f"schema file not found: {schema_file}")

    bundle = build_dir / name
    _reset_dir(bundle)

    # ---- agent ----
    agent_root = bundle / "agent"
    for sub in ("bin", "lib", "conf", "logs", "run"):
        (agent_root / sub).mkdir(parents=True)
    shutil.copy2(agent_bin, agent_root / "bin" / "uprobe")
    agent.collect_libraries(agent_bin, agent_root / "lib")
    shutil.copy2(agent_conf, agent_root / "conf" / "agent.yaml")
    _write(agent_root / "start_agent.sh", AGENT_START, 0o755)

    # ---- collector ----
    collector_root = bundle / "collector"
    for sub in ("bin", "lib", "conf", "logs", "run"):
        (collector_root / sub).mkdir(parents=True)
    shutil.copy2(collector_bin, collector_root / "bin" / "audit_collector")
    collector.collect_libraries(collector_bin, collector_root / "lib")
    shutil.copy2(schema_file, collector_root / "audit_schema.json")
    shutil.copy2(collector_conf, collector_root / "conf" / "collector.yaml")
    _write(collector_root / "start_collector.sh", COLLECTOR_START, 0o755)

    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a single bundle folder containing agent + collector.")
    parser.add_argument("--build-dir", default=str(DEFAULT_BUILD_DIR), help="local output directory")
    parser.add_argument("--name", default="audit-bundle", help="bundle folder name")
    parser.add_argument("--agent-config", default=str(DEFAULT_AGENT_CONF), help="agent runtime config to copy in")
    parser.add_argument("--collector-config", default=str(DEFAULT_COLLECTOR_CONF), help="collector runtime config to copy in")
    parser.add_argument("--skip-build", action="store_true", help="reuse existing binaries, skip make")
    args = parser.parse_args()

    bundle = build_bundle(
        Path(args.build_dir), args.name,
        Path(args.agent_config), Path(args.collector_config),
        args.skip_build,
    )
    print(f"bundle ready: {bundle}")
    print("  agent/     -> 上传到每台 agent 机，运行: sudo ./start_agent.sh")
    print("  collector/ -> 上传到每台 collector 机，运行: ./start_collector.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
