#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


CSV_FIELDS: List[str] = [
    "event_seq",
    "parent_event_seq",
    "next_fragment_seq",
    "pid",
    "tid",
    "user_id",
    "tenant_id",
    "effective_tenant_id",
    "session_id",
    "proxy_session_id",
    "db_id",
    "affected_rows",
    "return_rows",
    "transaction_hash",
    "request_id",
    "ret_code",
    "request_timestamp",
    "elapsed_time",
    "execute_time",
    "query_sql_len",
    "params_value_len",
    "perf_bpf_entry_ns",
    "perf_bpf_before_output_ns",
    "perf_agent_receive_ns",
    "perf_agent_before_submit_ns",
    "perf_agent_after_submit_ns",
    "perf_collector_receive_ns",
    "perf_mongo_before_insert_ns",
    "stmt_type_value",
    "stmt_type",
    "plan_type",
    "plan_type_name",
    "trans_status",
    "trans_status_name",
    "fragment_flags",
    "next_fragment_field",
    "user_name",
    "proxy_user_name",
    "tenant_name",
    "user_client_ip",
    "client_ip",
    "server_ip",
    "db_name",
    "sql_id",
    "trace_id",
    "query_sql",
    "params_value",
]


FIELD_ALIASES = {
    "plan_type": ["plan_type_value", "plan_type"],
    "plan_type_name": ["plan_type_name", "plan_type"],
    "trans_status": ["trans_status_value", "trans_status"],
    "trans_status_name": ["trans_status_name", "trans_status"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export MongoDB audit_events documents to collector CSV compatible with compare_official_collector.py.")
    parser.add_argument("--uri", default="mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit", help="MongoDB URI")
    parser.add_argument("--db", default="ob_audit", help="MongoDB database")
    parser.add_argument("--collection", default="audit_events", help="MongoDB collection")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--query", default="{}", help="MongoDB filter JSON")
    parser.add_argument("--limit", type=int, default=0, help="Max documents to export; 0 means all")
    parser.add_argument("--sort", default="event_seq", help="Sort field, empty disables sort")
    parser.add_argument("--sort-desc", action="store_true", help="Sort descending")
    return parser.parse_args()


def import_pymongo():
    try:
        from pymongo import MongoClient  # type: ignore
        return MongoClient
    except ImportError as exc:
        raise SystemExit(
            "pymongo is required. Install with: python3 -m pip install pymongo\n"
            "or Debian package: sudo apt install python3-pymongo"
        ) from exc


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(value)
    return "".join(" " if ch in "\r\n\t" else ch for ch in text if ch >= " " or ch in "\r\n\t")


def value_for_field(doc: Dict[str, Any], field: str) -> str:
    for key in FIELD_ALIASES.get(field, [field]):
        if key in doc:
            return clean_text(doc.get(key))
    return ""


def export_csv(docs: Iterable[Dict[str, Any]], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for doc in docs:
            row = {field: value_for_field(doc, field) for field in CSV_FIELDS}
            writer.writerow(row)
            count += 1
    return count


def main() -> int:
    args = parse_args()
    try:
        query = json.loads(args.query)
    except json.JSONDecodeError as exc:
        print(f"invalid --query JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(query, dict):
        print("--query must be a JSON object", file=sys.stderr)
        return 1

    MongoClient = import_pymongo()
    client = MongoClient(args.uri)
    collection = client[args.db][args.collection]
    cursor = collection.find(query, {field: 1 for field in set(CSV_FIELDS + ["plan_type_value", "trans_status_value"])})
    if args.sort:
        cursor = cursor.sort(args.sort, -1 if args.sort_desc else 1)
    if args.limit > 0:
        cursor = cursor.limit(args.limit)
    count = export_csv(cursor, Path(args.output))
    print(f"exported={count} output={args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
