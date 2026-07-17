#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from pathlib import Path


def norm_name(value):
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def norm_value(value):
    if value is None:
        return ""
    value = value.strip()
    value = re.sub(r"\s+", " ", value)
    return value


def norm_sql(value):
    value = norm_value(value)
    value = value.replace("`", "")
    value = value.rstrip(";")
    value = re.sub(r"\s*,\s*", ",", value)
    value = re.sub(r"\s*\(\s*", "(", value)
    value = re.sub(r"\s*\)\s*", ")", value)
    value = re.sub(r"\s*=\s*", "=", value)
    return value.upper()


def detect_dialect(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        sample = f.read(8192)
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t|;")
    except csv.Error:
        class Dialect(csv.excel):
            delimiter = "\t" if path.suffix.lower().endswith(".tsv") or "\t" in sample.splitlines()[0] else ","
        return Dialect


def read_table(path):
    dialect = detect_dialect(path)
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, dialect=dialect, skipinitialspace=True)
        if not reader.fieldnames:
            raise SystemExit(f"empty or invalid file: {path}")
        raw_headers = reader.fieldnames
        header_map = {}
        for h in raw_headers:
            n = norm_name(h)
            if n and n not in header_map:
                header_map[n] = h
        rows = []
        for idx, row in enumerate(reader, 2):
            normalized = {}
            for n, raw in header_map.items():
                normalized[n] = norm_value(row.get(raw, ""))
            rows.append((idx, normalized))
    return header_map, rows


def key_for(row, preferred):
    for col in preferred:
        value = row.get(col, "")
        if value:
            return col, norm_sql(value) if col == "query_sql" else value
    return None, None


def build_index(rows, preferred):
    index = {}
    duplicates = set()
    for line_no, row in rows:
        key_col, key = key_for(row, preferred)
        if key is None:
            continue
        k = (key_col, key)
        if k in index:
            duplicates.add(k)
        else:
            index[k] = (line_no, row)
    for k in duplicates:
        index.pop(k, None)
    return index, duplicates


def values_equal(col, left, right):
    if col == "query_sql":
        return norm_sql(left) == norm_sql(right)
    if col in {"stmt_type", "stmt_type_name", "trans_status", "trans_status_name"}:
        return norm_enum(left) == norm_enum(right)
    return norm_value(left) == norm_value(right)


def norm_enum(value):
    value = norm_value(value).upper()
    value = re.sub(r"[^A-Z0-9]+", "_", value).strip("_")
    aliases = {
        "TRANSACTION_NOT_OPENED": "TRANS_NOT_OPENED",
        "TRANSACTION_STARTED": "TRANS_STARTED",
        "TRANSACTION_ENDED": "TRANS_ENDED",
        "ENABLE_COMMITTABLE_TRANSACTION": "COMMIT_TRANS",
    }
    return aliases.get(value, value)


def build_compare_pairs(test_headers, other_headers, ignored):
    alias_pairs = {
        "stmt_type": "stmt_type_name",
        "trans_status": "trans_status_name",
    }
    pairs = []
    used_test = set()
    for other_col, test_col in alias_pairs.items():
        if other_col in ignored or test_col in ignored:
            continue
        if other_col in other_headers and test_col in test_headers:
            pairs.append((test_col, other_col))
            used_test.add(test_col)

    for col in test_headers:
        if col in ignored or col in used_test:
            continue
        if col in alias_pairs and alias_pairs[col] in test_headers:
            continue
        if col in other_headers:
            pairs.append((col, col))
    return pairs


def main():
    parser = argparse.ArgumentParser(
        description="Compare test.csv.csv with another CSV/TSV in same folder. Column names are case-insensitive."
    )
    parser.add_argument("test", nargs="?", default="test.csv.csv", help="captured CSV, default: test.csv.csv")
    parser.add_argument("other", nargs="?", default="audit.tsv.tsv", help="reference CSV/TSV, default: audit.tsv.tsv")
    parser.add_argument("--dir", default=str(Path(__file__).resolve().parent), help="base directory")
    parser.add_argument("--key", action="append", help="match key column, can repeat. default: sql_id, trace_id, request_id, query_sql")
    parser.add_argument("--ignore", action="append", default=[], help="ignore column, can repeat")
    parser.add_argument("--strict-row", action="store_true", help="do not fallback to row order when key is missing or duplicate")
    parser.add_argument("--max", type=int, default=200, help="max differences to print")
    args = parser.parse_args()

    base = Path(args.dir)
    test_path = Path(args.test)
    other_path = Path(args.other)
    if not test_path.is_absolute():
        test_path = base / test_path
    if not other_path.is_absolute():
        other_path = base / other_path

    test_headers, test_rows = read_table(test_path)
    other_headers, other_rows = read_table(other_path)

    ignored = {"request_id"}
    ignored.update(norm_name(c) for c in args.ignore)
    compare_pairs = build_compare_pairs(test_headers, other_headers, ignored)
    common_cols = [test_col for test_col, _ in compare_pairs]

    matched_test_cols = {test_col for test_col, _ in compare_pairs}
    missing_cols = [test_headers[c] for c in test_headers if c not in matched_test_cols and c not in ignored]
    if missing_cols:
        print("Columns only in test:")
        for c in missing_cols:
            print(f"  - {c}")
        print()

    preferred_keys = [norm_name(k) for k in args.key] if args.key else ["sql_id", "trace_id", "request_id", "query_sql"]
    preferred_keys = [k for k in preferred_keys if k in common_cols]
    if not preferred_keys:
        print("No common key column found, fallback to row order", file=sys.stderr)

    other_index, duplicates = build_index(other_rows, preferred_keys)
    if duplicates:
        print("Duplicate keys in other file ignored:")
        for key_col, key in sorted(duplicates):
            print(f"  - {key_col}={key}")
        print()

    diff_count = 0
    missing_row_count = 0
    compared_rows = 0

    for pos, (test_line, test_row) in enumerate(test_rows):
        other_line = None
        other_row = None
        key_col = None
        key = None
        if preferred_keys:
            key_col, key = key_for(test_row, preferred_keys)
            if key is not None:
                found = other_index.get((key_col, key))
                if found:
                    other_line, other_row = found
        if other_row is None and pos < len(other_rows) and not args.strict_row:
            other_line, other_row = other_rows[pos]
            key_col, key = "row", str(pos + 1)
        if other_row is None:
            missing_row_count += 1
            print(f"Missing row for test line {test_line}: {key_col}={key}")
            continue

        compared_rows += 1
        for test_col, other_col in compare_pairs:
            left = test_row.get(test_col, "")
            right = other_row.get(other_col, "")
            if not values_equal(test_col, left, right):
                diff_count += 1
                print(f"DIFF #{diff_count}: test line {test_line}, other line {other_line}, key {key_col}={key}")
                print(f"  column: {test_headers[test_col]} <-> {other_headers[other_col]}")
                print(f"  test : {left}")
                print(f"  other: {right}")
                if diff_count >= args.max:
                    print(f"Reached --max={args.max}, stop printing.")
                    print(f"Summary: compared_rows={compared_rows}, missing_rows={missing_row_count}, diffs_printed={diff_count}")
                    return 1

    print(f"Summary: compared_rows={compared_rows}, missing_rows={missing_row_count}, diffs={diff_count}")
    return 1 if diff_count or missing_row_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
