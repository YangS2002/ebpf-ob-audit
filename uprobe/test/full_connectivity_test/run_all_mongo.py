#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import os
import subprocess
import sys
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
RUN_ONE_MONGO = TEST_DIR / "run_one_mongo.py"
COLOR = {
    "reset": "\033[0m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "red": "\033[31m",
}

CASES = [
    {
        "name": "full_connectivity",
        "workload": TEST_DIR / "workload.sql",
        "mysql_force": False,
    },
]


def color(name, text):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{COLOR[name]}{text}{COLOR['reset']}"


def batch_stage(name, detail=""):
    text = f"◆ {name}"
    if detail:
        text += f" | {detail}"
    print(color("cyan", f"\n{'#' * 22} {text} {'#' * 22}"))


def run_case(args, case):
    cmd = [
        sys.executable,
        str(RUN_ONE_MONGO),
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
        "--mongo-uri", args.mongo_uri,
        "--mongo-db", args.mongo_db,
        "--mongo-collection", args.mongo_collection,
        "--mongo-query", args.mongo_query,
        "--mongo-limit", str(args.mongo_limit),
        "--mongo-sort", args.mongo_sort,
        "--mongo-export-wait-seconds", str(args.mongo_export_wait_seconds),
    ]
    if args.workload_database:
        cmd.extend(["--workload-database", args.workload_database])
    if case["mysql_force"]:
        cmd.append("--mysql-force")
    if args.mongo_sort_desc:
        cmd.append("--mongo-sort-desc")
    if args.mismatches_only:
        cmd.append("--mismatches-only")

    if case["name"] != CASES[0]["name"]:
        cmd.append("--no-clear-mongo")

    batch_stage(f"case {case['name']}", Path(case["workload"]).name)
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(color("green", f"CASE PASS {case['name']}"))
    else:
        print(color("red", f"CASE FAIL {case['name']} exit={result.returncode}"))
    return result.returncode


def parse_args():
    parser = argparse.ArgumentParser(description="Run all distributed SQL audit tests against MongoDB collector storage.")
    parser.add_argument("--deploy-config", default="", help="unused; kept for compatibility")
    parser.add_argument("--out-dir", default=str(TEST_DIR / "out" / "batch_mongo"))
    parser.add_argument("--ob-host", default="7.27.222.3")
    parser.add_argument("--ob-port", type=int, default=2881)
    parser.add_argument("--workload-user", default="root@sys")
    parser.add_argument("--workload-password", default="oceanbase")
    parser.add_argument("--workload-database", default="")
    parser.add_argument("--audit-user", default="root@sys")
    parser.add_argument("--audit-password", default="oceanbase")
    parser.add_argument("--mongo-uri", default="mongodb://audit_collector:1@7.27.43.145:27017/ob_audit?authSource=ob_audit")
    parser.add_argument("--mongo-db", default="ob_audit")
    parser.add_argument("--mongo-collection", default="audit_events")
    parser.add_argument("--mongo-query", default="{}")
    parser.add_argument("--mongo-limit", type=int, default=0)
    parser.add_argument("--mongo-sort", default="event_seq")
    parser.add_argument("--mongo-sort-desc", action="store_true")
    parser.add_argument("--mongo-export-wait-seconds", type=float, default=5.0)
    parser.add_argument("--mismatches-only", action="store_true", help="only print/write failed compare units")
    return parser.parse_args()


def main():
    args = parse_args()
    failed = []
    batch_stage("mongo batch start", f"cases={len(CASES)}")
    for case in CASES:
        code = run_case(args, case)
        if code != 0:
            failed.append((case["name"], code))
    summary = f"MONGO BATCH SUMMARY total={len(CASES)} failed={len(failed)}"
    print(color("red" if failed else "green", summary))
    for name, code in failed:
        print(f"FAIL {name} exit={code}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
