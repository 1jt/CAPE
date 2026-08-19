#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path

FIELDS = [
    "scheme", "keyword_num", "values_per_keyword", "value_bit_length",
    "conjunctive_keyword_num", "preprocessing_ms", "query_time_ms",
    "query_size_bytes", "response_size_bytes", "execution_status", "correctness_status",
]

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("inputs", nargs="+")
args = parser.parse_args()
rows = []
for name in args.inputs:
    with Path(name).open(newline="", encoding="utf-8") as handle:
        rows.extend(csv.DictReader(handle))
with Path(args.output).open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)

print(f"{'Scheme':<12} {'Prep(ms)':>12} {'Query(ms)':>12} {'Query(B)':>12} {'Response(B)':>14} {'Execution':>11}")
for row in rows:
    print(f"{row['scheme']:<12} {row['preprocessing_ms']:>12} {row['query_time_ms']:>12} "
          f"{row['query_size_bytes']:>12} {row['response_size_bytes']:>14} {row['execution_status']:>11}")
