#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import json
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_URI = "mongodb://audit_collector:1@7.27.43.139:27017/ob_audit?authSource=ob_audit"
DEFAULT_DB = "ob_audit"
DEFAULT_COLLECTION = "audit_events"

METRICS = [
    ("bpf_capture", "perf_bpf_entry_ns", "perf_bpf_before_output_ns"),
    ("ringbuf_to_agent", "perf_bpf_before_output_ns", "perf_agent_receive_ns"),
    ("agent_process", "perf_agent_receive_ns", "perf_agent_before_submit_ns"),
    ("agent_submit_copy", "perf_agent_before_submit_ns", "perf_agent_after_submit_ns"),
    ("collector_to_mongo", "perf_collector_receive_ns", "perf_mongo_before_insert_ns"),
]

UNIT_DIVISORS = {
    "ns": 1.0,
    "us": 1000.0,
    "ms": 1000000.0,
}

BASE_FIELDS = [
    "event_seq",
    "ingest_time",
    "db_name",
    "sql_id",
    "trace_id",
    "query_sql",
]

PERF_FIELDS = sorted({field for _, start, end in METRICS for field in (start, end)})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze eBPF audit perf fields from MongoDB. Cross-machine metrics are intentionally excluded."
        )
    )
    parser.add_argument("--uri", default=DEFAULT_URI, help="MongoDB URI")
    parser.add_argument("--db", default=DEFAULT_DB, help="MongoDB database")
    parser.add_argument("--collection", default=DEFAULT_COLLECTION, help="MongoDB collection")
    parser.add_argument("--db-name", default="", help="filter by audit db_name")
    parser.add_argument("--query", default="{}", help="extra MongoDB filter JSON")
    parser.add_argument("--since-minutes", type=int, default=0, help="only analyze documents newer than N minutes")
    parser.add_argument("--limit", type=int, default=0, help="max documents to read; 0 means all")
    parser.add_argument("--bucket-seconds", type=int, default=10, help="time-series bucket size in seconds")
    parser.add_argument("--unit", choices=sorted(UNIT_DIVISORS.keys()), default="us", help="output latency unit")
    parser.add_argument("--plot-dir", default="", help="write PNG charts to this directory")
    parser.add_argument("--top", type=int, default=20, help="print top N slow records per metric")
    parser.add_argument("--include-negative", action="store_true", help="keep negative deltas instead of dropping them")
    parser.add_argument("--diagnose", action="store_true", help="print match counts for each filter condition")
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


def import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore
        return plt
    except ImportError as exc:
        raise SystemExit(
            "matplotlib is required for --plot-dir. Install with: python3 -m pip install matplotlib\n"
            "or Debian package: sudo apt install python3-matplotlib"
        ) from exc


def load_extra_query(text: str) -> Dict[str, Any]:
    try:
        query = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid --query JSON: {exc}") from exc
    if not isinstance(query, dict):
        raise SystemExit("--query must be a JSON object")
    return query


def build_query(args: argparse.Namespace) -> Dict[str, Any]:
    query = load_extra_query(args.query)
    query["perf_bpf_entry_ns"] = {"$exists": True, "$gt": 0}
    if args.db_name:
        query["db_name"] = args.db_name
    if args.since_minutes > 0:
        query["ingest_time"] = {"$gte": datetime.now(timezone.utc) - timedelta(minutes=args.since_minutes)}
    return query


def to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return math.nan
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return ordered[int(pos)]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (pos - lower)


def stats_for(values: List[float]) -> Dict[str, float]:
    if not values:
        return {
            "count": 0,
            "avg": math.nan,
            "min": math.nan,
            "max": math.nan,
            "p50": math.nan,
            "p95": math.nan,
            "p99": math.nan,
        }
    return {
        "count": len(values),
        "avg": statistics.fmean(values),
        "min": min(values),
        "max": max(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def fmt(value: float) -> str:
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "nan"
    if abs(value) < 1000:
        return f"{value:.3f}"
    if abs(value) < 1000000:
        return f"{value:.1f}"
    return f"{value:.0f}"


def truncate_sql(sql: Any, max_len: int = 160) -> str:
    text = "" if sql is None else str(sql).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return text if len(text) <= max_len else text[:max_len] + "..."


def bucket_time(value: Any, bucket_seconds: int) -> Optional[datetime]:
    if not isinstance(value, datetime) or bucket_seconds <= 0:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    ts = int(value.timestamp())
    return datetime.fromtimestamp(ts - ts % bucket_seconds, tz=timezone.utc)


def collect(collection: Any, query: Dict[str, Any], args: argparse.Namespace) -> Tuple[Dict[str, List[float]], Dict[str, List[Tuple[float, Dict[str, Any]]]], Dict[datetime, Dict[str, List[float]]], int, int]:
    projection = {field: 1 for field in BASE_FIELDS + PERF_FIELDS}
    cursor = collection.find(query, projection).sort("ingest_time", 1)
    if args.limit > 0:
        cursor = cursor.limit(args.limit)

    divisor = UNIT_DIVISORS[args.unit]
    metric_values: Dict[str, List[float]] = {name: [] for name, _, _ in METRICS}
    slow_records: Dict[str, List[Tuple[float, Dict[str, Any]]]] = {name: [] for name, _, _ in METRICS}
    series: Dict[datetime, Dict[str, List[float]]] = defaultdict(lambda: {name: [] for name, _, _ in METRICS})
    docs = 0
    skipped = 0

    for doc in cursor:
        docs += 1
        bucket = bucket_time(doc.get("ingest_time"), args.bucket_seconds)
        valid_doc = False
        for name, start_field, end_field in METRICS:
            start = to_int(doc.get(start_field))
            end = to_int(doc.get(end_field))
            if start is None or end is None or start <= 0 or end <= 0:
                continue
            value = (end - start) / divisor
            if value < 0 and not args.include_negative:
                continue
            valid_doc = True
            metric_values[name].append(value)
            slow_records[name].append((value, doc))
            if bucket is not None:
                series[bucket][name].append(value)
        if not valid_doc:
            skipped += 1

    return metric_values, slow_records, series, docs, skipped


def print_summary(metric_values: Dict[str, List[float]], docs: int, skipped: int, unit: str) -> None:
    print(f"documents_read={docs} skipped_without_valid_perf={skipped}")
    print(f"\nsummary_{unit}")
    print(f"{'metric':30s} {'count':>10s} {'avg':>12s} {'min':>12s} {'p50':>12s} {'p95':>12s} {'p99':>12s} {'max':>12s}")
    for name, _, _ in METRICS:
        stats = stats_for(metric_values[name])
        print(
            f"{name:30s} {int(stats['count']):10d} {fmt(stats['avg']):>12s} {fmt(stats['min']):>12s} "
            f"{fmt(stats['p50']):>12s} {fmt(stats['p95']):>12s} {fmt(stats['p99']):>12s} {fmt(stats['max']):>12s}"
        )


def print_top_slow(slow_records: Dict[str, List[Tuple[float, Dict[str, Any]]]], top: int) -> None:
    if top <= 0:
        return
    for name, _, _ in METRICS:
        records = sorted(slow_records[name], key=lambda item: item[0], reverse=True)[:top]
        if not records:
            continue
        print(f"\ntop_{top}_{name}")
        print(f"{'value':>12s} {'event_seq':>18s} {'db_name':20s} {'sql_id':34s} query_sql")
        for value, doc in records:
            print(
                f"{fmt(value):>12s} {str(doc.get('event_seq', '')):>18s} "
                f"{str(doc.get('db_name', ''))[:20]:20s} {str(doc.get('sql_id', ''))[:34]:34s} "
                f"{truncate_sql(doc.get('query_sql'))}"
            )


def plot_summary(plt: Any, metric_values: Dict[str, List[float]], output: Path, unit: str) -> None:
    names = [name for name, _, _ in METRICS]
    avgs = [stats_for(metric_values[name])["avg"] for name in names]
    p95s = [stats_for(metric_values[name])["p95"] for name in names]
    maxs = [stats_for(metric_values[name])["max"] for name in names]
    finite_values = [value for value in avgs + p95s + maxs if not math.isnan(value)]

    plt.figure(figsize=(14, 7))
    if not finite_values:
        plt.text(0.5, 0.5, "No perf data", ha="center", va="center", fontsize=18)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output)
        plt.close()
        return

    x = list(range(len(names)))
    bars = []
    bars += plt.bar([i - 0.25 for i in x], [0 if math.isnan(v) else v for v in avgs], width=0.25, label="avg")
    bars += plt.bar(x, [0 if math.isnan(v) else v for v in p95s], width=0.25, label="p95")
    bars += plt.bar([i + 0.25 for i in x], [0 if math.isnan(v) else v for v in maxs], width=0.25, label="max")
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            plt.annotate(fmt(height), xy=(bar.get_x() + bar.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, rotation=90)
    plt.xticks(x, names, rotation=25, ha="right")
    plt.ylabel(unit)
    plt.ylim(0, max(finite_values) * 1.25)
    plt.title("Audit pipeline perf summary")
    plt.legend()
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output)
    plt.close()


def plot_series(plt: Any, series: Dict[datetime, Dict[str, List[float]]], output: Path, unit: str) -> None:
    plt.figure(figsize=(14, 7))
    if not series:
        plt.text(0.5, 0.5, "No time-series data", ha="center", va="center", fontsize=18)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output)
        plt.close()
        return
    buckets = sorted(series.keys())
    for name, _, _ in METRICS:
        y = []
        for bucket in buckets:
            values = series[bucket][name]
            y.append(statistics.fmean(values) if values else math.nan)
        plt.plot(buckets, y, marker="o", linewidth=1, label=name)
    plt.ylabel(f"avg {unit}")
    plt.xlabel("ingest_time bucket")
    plt.title("Audit pipeline perf time series")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output)
    plt.close()


def write_plots(metric_values: Dict[str, List[float]], series: Dict[datetime, Dict[str, List[float]]], plot_dir: str, unit: str) -> None:
    if not plot_dir:
        return
    output_dir = Path(plot_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    plt = import_matplotlib()
    summary_path = output_dir / "perf_summary.png"
    series_path = output_dir / "perf_timeseries.png"
    plot_summary(plt, metric_values, summary_path, unit)
    plot_series(plt, series, series_path, unit)
    print(f"\nplots_written={output_dir}")
    print(f"summary_chart={summary_path}")
    print(f"timeseries_chart={series_path}")


def print_diagnosis(collection: Any, args: argparse.Namespace, query: Dict[str, Any]) -> None:
    print("diagnosis")
    print(f"total_documents={collection.count_documents({})}")
    print(f"db_name_documents={collection.count_documents({'db_name': args.db_name}) if args.db_name else 'not_set'}")
    print(f"perf_documents={collection.count_documents({'perf_bpf_entry_ns': {'$exists': True}})}")
    print(f"perf_gt0_documents={collection.count_documents({'perf_bpf_entry_ns': {'$gt': 0}})}")
    print(f"final_query_documents={collection.count_documents(query)}")
    latest = collection.find_one({}, {"event_seq": 1, "ingest_time": 1, "db_name": 1, "perf_bpf_entry_ns": 1}, sort=[("ingest_time", -1)])
    latest_perf = collection.find_one({"perf_bpf_entry_ns": {"$exists": True}}, {"event_seq": 1, "ingest_time": 1, "db_name": 1, "perf_bpf_entry_ns": 1}, sort=[("ingest_time", -1)])
    latest_db = collection.find_one({"db_name": args.db_name}, {"event_seq": 1, "ingest_time": 1, "db_name": 1, "perf_bpf_entry_ns": 1}, sort=[("ingest_time", -1)]) if args.db_name else None
    print(f"latest_any={latest}")
    print(f"latest_perf={latest_perf}")
    if args.db_name:
        print(f"latest_db_name={latest_db}")
    print()


def main() -> int:
    args = parse_args()
    MongoClient = import_pymongo()
    client = MongoClient(args.uri)
    collection = client[args.db][args.collection]
    query = build_query(args)
    if args.diagnose:
        print_diagnosis(collection, args, query)

    metric_values, slow_records, series, docs, skipped = collect(collection, query, args)
    print_summary(metric_values, docs, skipped, args.unit)
    print_top_slow(slow_records, args.top)
    write_plots(metric_values, series, args.plot_dir, args.unit)
    if docs == 0:
        print("\nno documents matched. Check --db-name, --since-minutes, or perf fields.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
