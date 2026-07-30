#!/usr/bin/env python3
"""
Compare workflow:
1. Load SQL statements from workload file as comparison units.
2. Normalize workload SQL, official GV$OB_SQL_AUDIT TSV QUERY_SQL, and collector CSV query_sql
   by trimming, collapsing whitespace, removing trailing semicolons, and fixing TSV multiline SQL.
3. For each workload SQL:
   - search collector rows by normalized query_sql;
   - if collector has 0 rows: report missing;
   - if collector has >1 rows: report duplicate and skip field compare for this SQL;
   - if collector has 1 row: use its trace_id and query_sql to find official row;
   - if official has 0 rows: report official missing;
   - if official has >1 rows: report duplicate and skip field compare for this SQL;
   - compare official fields with collector fields through FIELD_MAP.
4. Each workload SQL is printed as one unit. PASS units are green and show one random field value.
5. Final summary prints workload SQL count, collector missing SQLs, and official mismatch SQLs.
"""
import argparse
import csv
import os
import random
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
UPROBE_DIR = REPO_ROOT / "uprobe"
DEFAULT_ADT_TO_CSV = UPROBE_DIR / "bin" / "adt_to_csv"

FIELD_MAP = {
    "server_ip": "svr_ip",
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
    "stmt_type": "stmt_type",
    "plan_type": "plan_type",
    "params_value": "params_value",
    "trans_status_name": "trans_status",
}
OFFICIAL_FIELDS = list(FIELD_MAP.values())
COMPARE_FIELDS = [field for field in OFFICIAL_FIELDS if field != "query_sql"]
OUTPUT_FIELDS = ["event_seq"] + OFFICIAL_FIELDS

COLOR = {
    "reset": "\033[0m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
}


def color(name, text):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{COLOR[name]}{text}{COLOR['reset']}"


def normalize_text(value):
    text = str(value or "")
    text = text.replace("\\n", " ").replace("\\r", " ")
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = "".join(" " if ch.isspace() else ch for ch in text if ch >= " " or ch.isspace())
    return re.sub(r"\s+", " ", text).strip()


def normalize_sql(value):
    text = normalize_text(value)
    text = normalize_text(strip_sql_comments(text))
    while text.endswith(";"):
        text = text[:-1].rstrip()
    return text


def normalize_key(value):
    return normalize_text(value).lower()


def short_sql(sql, max_bytes=32):
    text = normalize_sql(sql)
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text
    return data[:max_bytes].decode("utf-8", errors="ignore") + "..."


def strip_sql_comments(sql_text):
    out = []
    quote = ""
    escape = False
    i = 0
    while i < len(sql_text):
        ch = sql_text[i]
        nxt = sql_text[i + 1] if i + 1 < len(sql_text) else ""
        if escape:
            out.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and quote:
            out.append(ch)
            escape = True
            i += 1
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "-" and nxt == "-":
            i += 2
            while i < len(sql_text) and sql_text[i] not in "\r\n":
                i += 1
            continue
        if ch == "#":
            i += 1
            while i < len(sql_text) and sql_text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < len(sql_text) and not (sql_text[i] == "*" and sql_text[i + 1] == "/"):
                i += 1
            i += 2 if i + 1 < len(sql_text) else 0
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_sql_statements(sql_text):
    statements = []
    buf = []
    quote = ""
    escape = False
    for ch in sql_text:
        buf.append(ch)
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            continue
        if ch == ";":
            stmt = normalize_sql("".join(buf))
            if stmt:
                statements.append(stmt)
            buf = []
    tail = normalize_sql("".join(buf))
    if tail:
        statements.append(tail)
    return statements


def load_workload(path):
    sql_text = Path(path).read_text(encoding="utf-8", errors="replace")
    seen = set()
    statements = []
    for stmt in split_sql_statements(sql_text):
        if stmt not in seen:
            seen.add(stmt)
            statements.append(stmt)
    return statements


def read_official_tsv(path):
    path = Path(path)
    if path.stat().st_size == 0:
        return []
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    if not lines:
        return []
    headers = [normalize_key(cell) for cell in lines[0].split("\t")]
    expected_tabs = len(headers) - 1
    records = []
    current = ""
    for line in lines[1:]:
        current = line if not current else current + "\\n" + line
        if current.count("\t") >= expected_tabs:
            records.append(current)
            current = ""
    if current:
        records.append(current)
    rows = []
    for record in records:
        cells = record.split("\t", expected_tabs)
        cells += [""] * (len(headers) - len(cells))
        rows.append({headers[i]: cells[i] for i in range(len(headers))})
    return rows


def read_collector_csv(path):
    path = Path(path)
    if path.stat().st_size == 0:
        return []
    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        return [{normalize_key(key): value for key, value in row.items()} for row in reader]


def write_csv(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def normalize_official(row):
    normalized = {field: normalize_text(row.get(field)) for field in OFFICIAL_FIELDS}
    normalized["query_sql"] = normalize_sql(row.get("query_sql"))
    normalized["event_seq"] = ""
    return normalized


def normalize_collector(row):
    normalized = {official: normalize_text(row.get(collector)) for collector, official in FIELD_MAP.items()}
    normalized["query_sql"] = normalize_sql(row.get("query_sql"))
    normalized["event_seq"] = normalize_text(row.get("event_seq"))
    return normalized


def convert_adt(adt_path, csv_path, adt_to_csv):
    cmd = [str(adt_to_csv), str(adt_path), str(csv_path), "all"]
    print(color("cyan", "RUN " + " ".join(cmd)))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def index_by_sql(rows):
    indexed = {}
    for row in rows:
        indexed.setdefault(row.get("query_sql", ""), []).append(row)
    return indexed


def official_matches(official_rows, sql, trace_id):
    return [row for row in official_rows if row.get("query_sql") == sql and row.get("trace_id") == trace_id]


def diff_rows(official, collector):
    diffs = []
    for field in COMPARE_FIELDS:
        official_value = normalize_text(official.get(field))
        collector_value = normalize_text(collector.get(field))
        if official_value != collector_value:
            diffs.append((field, official.get(field, ""), collector.get(field, "")))
    return diffs


def print_lines(lines, color_name):
    for line in lines:
        print(color(color_name, line))


def compare(workload_sqls, official_rows, collector_rows, report_path, max_print, mismatches_only=False):
    collector_index = index_by_sql(collector_rows)
    collector_missing = []
    duplicate_collector = []
    official_missing = []
    duplicate_official = []
    mismatches = []
    pass_count = 0
    report = []
    printed = 0

    for idx, sql in enumerate(workload_sqls, 1):
        title = short_sql(sql)
        unit = ["", f"SQL #{idx} {title}"]
        collectors = collector_index.get(sql, [])
        if not collectors:
            collector_missing.append(sql)
            unit.append("  MISSING collector")
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "red")
                printed += 1
            continue
        if len(collectors) > 1:
            duplicate_collector.append((sql, len(collectors)))
            unit.append(f"  DUPLICATE collector rows={len(collectors)} unsupported")
            unit.append("  event_seq=" + ",".join(row.get("event_seq", "") for row in collectors))
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "yellow")
                printed += 1
            continue

        collector = collectors[0]
        trace_id = collector.get("trace_id", "")
        officials = official_matches(official_rows, sql, trace_id)
        unit.append(f"  event_seq={collector.get('event_seq', '')} trace_id={trace_id}")
        if not officials:
            official_missing.append(sql)
            unit.append("  MISSING official")
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "red")
                printed += 1
            continue
        if len(officials) > 1:
            duplicate_official.append((sql, len(officials)))
            unit.append(f"  DUPLICATE official rows={len(officials)} unsupported")
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "yellow")
                printed += 1
            continue

        official = officials[0]
        diffs = diff_rows(official, collector)
        if diffs:
            mismatches.append(sql)
            unit.append(f"  DIFF fields={len(diffs)}")
            for field, official_value, collector_value in diffs:
                unit.append(f"  KEY {field}")
                unit.append(f"    official : {short_sql(official_value) if field == 'query_sql' else official_value}")
                unit.append(f"    collector: {short_sql(collector_value) if field == 'query_sql' else collector_value}")
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "red")
                printed += 1
            continue

        pass_count += 1
        if not mismatches_only:
            sample_field = random.choice(COMPARE_FIELDS)
            unit.append("  PASS")
            unit.append(f"  official {sample_field}: {short_sql(official.get(sample_field, '')) if sample_field == 'query_sql' else official.get(sample_field, '')}")
            unit.append(f"  collector {sample_field}: {short_sql(collector.get(sample_field, '')) if sample_field == 'query_sql' else collector.get(sample_field, '')}")
            report.extend(unit)
            if printed < max_print:
                print_lines(unit, "green")
                printed += 1

    Path(report_path).write_text("\n".join(report) + "\n", encoding="utf-8")
    return {
        "pass": pass_count,
        "collector_missing": collector_missing,
        "duplicate_collector": duplicate_collector,
        "official_missing": official_missing,
        "duplicate_official": duplicate_official,
        "mismatches": mismatches,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Compare workload SQL against collector records and official GV$OB_SQL_AUDIT.")
    parser.add_argument("--workload", required=True)
    parser.add_argument("--official-tsv", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--collector-csv")
    group.add_argument("--collector-adt")
    parser.add_argument("--adt-to-csv", default=str(DEFAULT_ADT_TO_CSV))
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--max-print", type=int, default=50)
    parser.add_argument("--mismatches-only", action="store_true", help="print and write only failed SQL units; suppress PASS details")
    return parser.parse_args()


def main():
    args = parse_args()
    official_path = Path(args.official_tsv)
    out_dir = Path(args.out_dir) if args.out_dir else official_path.parent / "compare_official_collector"
    out_dir.mkdir(parents=True, exist_ok=True)

    collector_csv = Path(args.collector_csv) if args.collector_csv else out_dir / "collector_events.csv"
    if args.collector_adt:
        convert_adt(args.collector_adt, collector_csv, Path(args.adt_to_csv))

    workload_sqls = load_workload(args.workload)
    official_rows = [normalize_official(row) for row in read_official_tsv(official_path)]
    collector_rows = [normalize_collector(row) for row in read_collector_csv(collector_csv)]

    write_csv(out_dir / "official.normalized.csv", official_rows)
    write_csv(out_dir / "collector.normalized.csv", collector_rows)

    result = compare(workload_sqls, official_rows, collector_rows, out_dir / "compare_report.txt", args.max_print, args.mismatches_only)

    fail_count = (len(result["collector_missing"]) + len(result["duplicate_collector"]) +
                  len(result["official_missing"]) + len(result["duplicate_official"]) +
                  len(result["mismatches"]))
    print(color("cyan", ""))
    print(color("cyan", f"SUMMARY workload_sql={len(workload_sqls)} pass={result['pass']} fail={fail_count} "
                        f"collector_missing={len(result['collector_missing'])} "
                        f"duplicate_collector={len(result['duplicate_collector'])} "
                        f"official_missing={len(result['official_missing'])} "
                        f"duplicate_official={len(result['duplicate_official'])} "
                        f"mismatches={len(result['mismatches'])}"))
    print(color("cyan", f"REPORT {out_dir / 'compare_report.txt'}"))
    print(color("cyan", f"collector_missing={len(result['collector_missing'])}"))
    for sql in result["collector_missing"]:
        print(color("red", f"  missing collector: {short_sql(sql)}"))
    print(color("cyan", f"collector_duplicate={len(result['duplicate_collector'])}"))
    for sql, count in result["duplicate_collector"]:
        print(color("yellow", f"  duplicate collector rows={count}: {short_sql(sql)}"))
    print(color("cyan", f"official_missing={len(result['official_missing'])}"))
    for sql in result["official_missing"]:
        print(color("red", f"  missing official: {short_sql(sql)}"))
    print(color("cyan", f"official_duplicate={len(result['duplicate_official'])}"))
    for sql, count in result["duplicate_official"]:
        print(color("yellow", f"  duplicate official rows={count}: {short_sql(sql)}"))
    print(color("cyan", f"official_mismatch={len(result['mismatches'])}"))
    for sql in result["mismatches"]:
        print(color("red", f"  mismatch: {short_sql(sql)}"))
    print(color("cyan", f"out_dir={out_dir}"))

    failed = any(result[key] for key in ("collector_missing", "duplicate_collector", "official_missing", "duplicate_official", "mismatches"))
    print(color("red" if failed else "green", "COMPARE FAIL" if failed else "COMPARE PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
