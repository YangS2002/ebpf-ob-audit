#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
RUN_ONE = TEST_DIR / "run_one.py"
COLOR = {
    "reset": "\033[0m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
}


def color(name, text):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{COLOR[name]}{text}{COLOR['reset']}"


def batch_stage(name, detail=""):
    text = f"◆ {name}"
    if detail:
        text += f" | {detail}"
    print(color("cyan", f"\n{'#' * 22} {text} {'#' * 22}"))

CASES = [
    {
        "name": "normal",
        "workload": TEST_DIR / "workload.sql",
        "mysql_force": False,
    },
    {
        "name": "error",
        "workload": TEST_DIR / "error_workload.sql",
        "mysql_force": True,
    },
]


def run_case(args, case):
    cmd = [
        sys.executable,
        str(RUN_ONE),
        "--deploy-config", args.deploy_config,
        "--workload", str(case["workload"]),
        "--case-name", case["name"],
        "--out-dir", args.out_dir,
        "--ob-host", args.ob_host,
        "--ob-port", str(args.ob_port),
        "--workload-user", args.workload_user,
        "--workload-password", args.workload_password,
        "--audit-user", args.audit_user,
        "--audit-password", args.audit_password,
        "--collector-path", args.collector_path,
        "--collector-stop-wait-seconds", str(args.collector_stop_wait_seconds),
    ]
    if args.collector_host:
        cmd.extend(["--collector-host", args.collector_host])
    if args.collector_user:
        cmd.extend(["--collector-user", args.collector_user])
    if args.collector_ssh_port:
        cmd.extend(["--collector-ssh-port", str(args.collector_ssh_port)])
    if args.collector_password is not None:
        cmd.extend(["--collector-password", args.collector_password])
    if args.collector_local_path:
        cmd.extend(["--collector-local-path", args.collector_local_path])
    if args.workload_database:
        cmd.extend(["--workload-database", args.workload_database])
    if args.skip_build:
        cmd.append("--skip-build")
    if args.skip_tools_build:
        cmd.append("--skip-tools-build")
    if case["mysql_force"]:
        cmd.append("--mysql-force")
    if args.no_deploy_after_first and case["name"] != CASES[0]["name"]:
        cmd.append("--skip-deploy")

    batch_stage(f"case {case['name']}", Path(case["workload"]).name)
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(color("green", f"CASE PASS {case['name']}"))
    else:
        print(color("red", f"CASE FAIL {case['name']} exit={result.returncode}"))
    return result.returncode


def parse_args():
    parser = argparse.ArgumentParser(description="Run all distributed SQL audit deploy tests.")
    parser.add_argument("--deploy-config", required=True)
    parser.add_argument("--out-dir", default=str(TEST_DIR / "out" / "batch"))
    parser.add_argument("--ob-host", default="7.27.43.145")
    parser.add_argument("--ob-port", type=int, default=2881)
    parser.add_argument("--workload-user", default="root@sys")
    parser.add_argument("--workload-password", default="oceanbase")
    parser.add_argument("--workload-database", default="")
    parser.add_argument("--audit-user", default="root@sys")
    parser.add_argument("--audit-password", default="oceanbase")
    parser.add_argument("--collector-host", default="")
    parser.add_argument("--collector-user", default="")
    parser.add_argument("--collector-ssh-port", type=int, default=0)
    parser.add_argument("--collector-password", default=None)
    parser.add_argument("--collector-path", default="collector_events.adt")
    parser.add_argument("--collector-local-path", default="")
    parser.add_argument("--collector-stop-wait-seconds", type=float, default=2.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-tools-build", action="store_true")
    parser.add_argument("--no-deploy-after-first", action="store_true", default=True)
    parser.add_argument("--deploy-each-case", action="store_false", dest="no_deploy_after_first")
    return parser.parse_args()


def main():
    args = parse_args()
    failed = []
    batch_stage("batch start", f"cases={len(CASES)}")
    for case in CASES:
        code = run_case(args, case)
        if code != 0:
            failed.append((case["name"], code))
    summary = f"BATCH SUMMARY total={len(CASES)} failed={len(failed)}"
    print(color("red" if failed else "green", summary))
    for name, code in failed:
        print(f"FAIL {name} exit={code}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
