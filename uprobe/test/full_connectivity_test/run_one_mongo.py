#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import sys
import time
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
SHARED_TEST_DIR = TEST_DIR.parent / "distributed_sql_test"
sys.path.insert(0, str(SHARED_TEST_DIR))

from run_one import (
    DEFAULT_OUT_DIR,
    DEFAULT_WORKLOAD,
    UPROBE_DIR,
    compare_with_official,
    execute_workload,
    export_official,
    mysql_scalar,
    ok,
    run,
    stage,
    warn,
)

DEFAULT_WORKLOAD = TEST_DIR / "big_sql_test.sql"
DEFAULT_OUT_DIR = TEST_DIR / "out" / "single"

MONGO_TO_CSV = UPROBE_DIR / "tools" / "mongo_to_csv.py"


def clear_mongo(args):
    try:
        from pymongo import MongoClient  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "pymongo is required. Install with: python3 -m pip install pymongo\n"
            "or Debian package: sudo apt install python3-pymongo"
        ) from exc
    client = MongoClient(args.mongo_uri)
    result = client[args.mongo_db][args.mongo_collection].delete_many({})
    ok("mongo cleared", f"deleted={result.deleted_count}")


def export_mongo(args, out_path):
    cmd = [
        sys.executable,
        str(MONGO_TO_CSV),
        "--uri", args.mongo_uri,
        "--db", args.mongo_db,
        "--collection", args.mongo_collection,
        "--output", str(out_path),
        "--query", args.mongo_query,
        "--sort", args.mongo_sort,
    ]
    if args.mongo_sort_desc:
        cmd.append("--sort-desc")
    if args.mongo_limit > 0:
        cmd.extend(["--limit", str(args.mongo_limit)])
    run(cmd)


def parse_args():
    parser = argparse.ArgumentParser(description="Run SQL workload, export GV$OB_SQL_AUDIT and MongoDB audit_events, compare records.")
    parser.add_argument("--deploy-config", default="", help="unused; kept for compatibility")
    parser.add_argument("--workload", default=str(DEFAULT_WORKLOAD))
    parser.add_argument("--case-name", default="", help="name used for output subdirectory when provided")
    parser.add_argument("--workload-user", default="root@sys")
    parser.add_argument("--workload-password", default="oceanbase")
    parser.add_argument("--workload-database", default="")
    parser.add_argument("--audit-user", default="root@sys")
    parser.add_argument("--audit-password", default="oceanbase")
    parser.add_argument("--ob-host", default="7.27.43.136")
    parser.add_argument("--ob-port", type=int, default=2881)
    parser.add_argument("--mysql-force", action="store_true")
    parser.add_argument("--mongo-uri", default="mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit")
    parser.add_argument("--mongo-db", default="ob_audit")
    parser.add_argument("--mongo-collection", default="audit_events")
    parser.add_argument("--mongo-query", default="{}")
    parser.add_argument("--mongo-limit", type=int, default=0)
    parser.add_argument("--mongo-sort", default="event_seq")
    parser.add_argument("--mongo-sort-desc", action="store_true")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR.parent / "single_mongo"))
    parser.add_argument("--mongo-export-wait-seconds", type=float, default=5.0)
    parser.add_argument("--no-clear-mongo", action="store_true")
    parser.add_argument("--mismatches-only", action="store_true", help="only print/write failed compare units")
    return parser.parse_args()


def main():
    args = parse_args()
    out_dir = Path(args.out_dir)
    if args.case_name:
        out_dir = out_dir / args.case_name
    out_dir.mkdir(parents=True, exist_ok=True)

    official_tsv = out_dir / "official_ob_sql_audit.tsv"
    collector_csv = out_dir / "collector_events.csv"

    stage("prepare", f"case={args.case_name or 'single'} workload={args.workload}")
    if not args.no_clear_mongo:
        stage("clear mongo", f"{args.mongo_db}.{args.mongo_collection}")
        clear_mongo(args)
    else:
        warn("mongo clear skipped")

    stage("time window", "capture start timestamp")
    start_time = mysql_scalar(args, "SELECT NOW(6)")
    ok("start_time", start_time)

    stage("execute workload", Path(args.workload).name)
    execute_workload(args)
    ok("workload done")

    stage("time window", "capture end timestamp")
    end_time = mysql_scalar(args, "SELECT NOW(6)")
    ok("end_time", end_time)

    if args.mongo_export_wait_seconds > 0:
        stage("wait mongo", f"{args.mongo_export_wait_seconds}s")
        time.sleep(args.mongo_export_wait_seconds)

    stage("export official", "GV$OB_SQL_AUDIT")
    export_official(args, start_time, end_time, official_tsv)
    ok("official exported", str(official_tsv))

    stage("export collector", "MongoDB -> CSV")
    export_mongo(args, collector_csv)
    ok("collector exported", str(collector_csv))

    stage("compare records")
    compare_code = compare_with_official(args, official_tsv, collector_csv, out_dir)
    if compare_code == 0:
        ok("compare passed", str(out_dir / "compare"))
    else:
        warn("compare failed", str(out_dir / "compare"))
    return compare_code


if __name__ == "__main__":
    raise SystemExit(main())
