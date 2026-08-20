#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

import argparse
import math
import re
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


LINE_RE = re.compile(
    r"grpc upload perf: collector=(?P<collector>\S+) "
    r"(?:db_name=(?P<db_name>\S*) )?"
    r"records=(?P<records>\d+) bytes=(?P<bytes>\d+) roundtrip_us=(?P<roundtrip>[0-9.]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze agent gRPC upload RTT logs.")
    parser.add_argument("--log", action="append", required=True, help="agent logs/uprobe.log path; can be repeated")
    parser.add_argument("--db-name", default="", help="filter by db_name printed by agent")
    parser.add_argument("--plot-dir", default="", help="write PNG charts to this directory")
    parser.add_argument("--bucket-size", type=int, default=100, help="batch count per time-series bucket")
    parser.add_argument("--top", type=int, default=20, help="print top N slow uploads")
    return parser.parse_args()


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
        return {"count": 0, "avg": math.nan, "min": math.nan, "p50": math.nan, "p95": math.nan, "p99": math.nan, "max": math.nan}
    return {
        "count": len(values),
        "avg": statistics.fmean(values),
        "min": min(values),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
    }


def fmt(value: float) -> str:
    if math.isnan(value):
        return "nan"
    if abs(value) < 1000:
        return f"{value:.3f}"
    if abs(value) < 1000000:
        return f"{value:.1f}"
    return f"{value:.0f}"


def parse_log_line(path: Path, line_no: int, line: str) -> Optional[Dict[str, Any]]:
    match = LINE_RE.search(line)
    if not match:
        return None
    return {
        "source": str(path),
        "line_no": line_no,
        "collector": match.group("collector"),
        "db_name": match.group("db_name") or "",
        "records": int(match.group("records")),
        "bytes": int(match.group("bytes")),
        "roundtrip_us": float(match.group("roundtrip")),
    }


def read_rows(paths: List[str], db_name: str) -> Tuple[List[Dict[str, Any]], int]:
    rows: List[Dict[str, Any]] = []
    total = 0
    for text in paths:
        path = Path(text)
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line_no, line in enumerate(file, 1):
                row = parse_log_line(path, line_no, line)
                if not row:
                    continue
                total += 1
                if db_name and row["db_name"] != db_name:
                    continue
                rows.append(row)
    return rows, total


def print_summary(rows: List[Dict[str, Any]], total: int, db_name: str) -> None:
    values = [row["roundtrip_us"] for row in rows]
    sizes = [float(row["bytes"]) for row in rows]
    records = [float(row["records"]) for row in rows]
    stats = stats_for(values)
    size_stats = stats_for(sizes)
    record_stats = stats_for(records)
    print(f"total_log_uploads={total} matched_uploads={len(rows)} db_name={db_name or '<all>'}")
    print("\ngrpc_roundtrip_us")
    print(f"{'count':>10s} {'avg':>12s} {'min':>12s} {'p50':>12s} {'p95':>12s} {'p99':>12s} {'max':>12s}")
    print(
        f"{int(stats['count']):10d} {fmt(stats['avg']):>12s} {fmt(stats['min']):>12s} {fmt(stats['p50']):>12s} "
        f"{fmt(stats['p95']):>12s} {fmt(stats['p99']):>12s} {fmt(stats['max']):>12s}"
    )
    print("\nupload_bytes")
    print(
        f"avg={fmt(size_stats['avg'])} min={fmt(size_stats['min'])} p50={fmt(size_stats['p50'])} "
        f"p95={fmt(size_stats['p95'])} max={fmt(size_stats['max'])}"
    )
    print("upload_records")
    print(
        f"avg={fmt(record_stats['avg'])} min={fmt(record_stats['min'])} p50={fmt(record_stats['p50'])} "
        f"p95={fmt(record_stats['p95'])} max={fmt(record_stats['max'])}"
    )


def print_top(rows: List[Dict[str, Any]], top: int) -> None:
    if top <= 0:
        return
    print(f"\ntop_{top}_grpc_roundtrip")
    print(f"{'roundtrip_us':>14s} {'records':>8s} {'bytes':>10s} {'collector':24s} {'db_name':24s} source:line")
    for row in sorted(rows, key=lambda item: item["roundtrip_us"], reverse=True)[:top]:
        print(
            f"{fmt(row['roundtrip_us']):>14s} {row['records']:8d} {row['bytes']:10d} "
            f"{row['collector'][:24]:24s} {row['db_name'][:24]:24s} {row['source']}:{row['line_no']}"
        )


def bucket_rows(rows: List[Dict[str, Any]], bucket_size: int) -> List[Tuple[int, float, float]]:
    if bucket_size <= 0:
        bucket_size = 100
    buckets = []
    for start in range(0, len(rows), bucket_size):
        chunk = rows[start:start + bucket_size]
        values = [row["roundtrip_us"] for row in chunk]
        buckets.append((start + len(chunk), statistics.fmean(values), max(values)))
    return buckets


def plot(rows: List[Dict[str, Any]], plot_dir: str, bucket_size: int) -> None:
    if not plot_dir:
        return
    output_dir = Path(plot_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    plt = import_matplotlib()

    values = [row["roundtrip_us"] for row in rows]
    summary_path = output_dir / "grpc_rtt_summary.png"
    series_path = output_dir / "grpc_rtt_series.png"
    hist_path = output_dir / "grpc_rtt_hist.png"

    plt.figure(figsize=(10, 6))
    if values:
        stats = stats_for(values)
        names = ["avg", "p50", "p95", "p99", "max"]
        y = [stats[name] for name in names]
        bars = plt.bar(names, y)
        for bar in bars:
            height = bar.get_height()
            plt.annotate(fmt(height), xy=(bar.get_x() + bar.get_width() / 2, height), xytext=(0, 3),
                         textcoords="offset points", ha="center", va="bottom", fontsize=9)
        plt.ylabel("us")
        plt.title("gRPC upload roundtrip summary")
        plt.grid(axis="y", alpha=0.3)
    else:
        plt.text(0.5, 0.5, "No gRPC RTT data", ha="center", va="center", fontsize=18)
        plt.axis("off")
    plt.tight_layout()
    plt.savefig(summary_path)
    plt.close()

    plt.figure(figsize=(12, 6))
    buckets = bucket_rows(rows, bucket_size)
    if buckets:
        x = [item[0] for item in buckets]
        avg_y = [item[1] for item in buckets]
        max_y = [item[2] for item in buckets]
        plt.plot(x, avg_y, marker="o", linewidth=1, label="avg")
        plt.plot(x, max_y, marker="o", linewidth=1, label="max")
        plt.xlabel("upload count")
        plt.ylabel("us")
        plt.title(f"gRPC upload roundtrip by every {bucket_size} uploads")
        plt.legend()
        plt.grid(True, alpha=0.3)
    else:
        plt.text(0.5, 0.5, "No gRPC RTT data", ha="center", va="center", fontsize=18)
        plt.axis("off")
    plt.tight_layout()
    plt.savefig(series_path)
    plt.close()

    plt.figure(figsize=(10, 6))
    if values:
        plt.hist(values, bins=min(100, max(10, int(math.sqrt(len(values))))))
        plt.xlabel("roundtrip_us")
        plt.ylabel("count")
        plt.title("gRPC upload roundtrip distribution")
        plt.grid(axis="y", alpha=0.3)
    else:
        plt.text(0.5, 0.5, "No gRPC RTT data", ha="center", va="center", fontsize=18)
        plt.axis("off")
    plt.tight_layout()
    plt.savefig(hist_path)
    plt.close()

    print(f"\nplots_written={output_dir}")
    print(f"summary_chart={summary_path}")
    print(f"series_chart={series_path}")
    print(f"hist_chart={hist_path}")


def main() -> int:
    args = parse_args()
    rows, total = read_rows(args.log, args.db_name)
    print_summary(rows, total, args.db_name)
    print_top(rows, args.top)
    plot(rows, args.plot_dir, args.bucket_size)
    if not rows:
        print("\nno matching grpc RTT rows. Check --log, --db-name, and whether agent was rebuilt/restarted.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
