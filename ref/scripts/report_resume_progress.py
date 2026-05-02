#!/usr/bin/env python3
"""Report completed and remaining candidate_ids for resumable benchmark runs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import List, Set


def resolve_path(root_dir: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root_dir / path


def read_candidate_ids(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8") as f:
        rows = csv.DictReader(f)
        return [row["candidate_id"] for row in rows if row.get("candidate_id")]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Report resumable benchmark progress.")
    p.add_argument("--input-csv", required=True, help="Full candidate input CSV")
    p.add_argument("--output-csv", required=True, help="Existing output CSV")
    p.add_argument(
        "--remaining-csv",
        default="",
        help="Optional CSV to write the remaining candidate rows",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root_dir = Path(__file__).resolve().parents[1]
    input_csv = resolve_path(root_dir, args.input_csv)
    output_csv = resolve_path(root_dir, args.output_csv)
    remaining_csv = resolve_path(root_dir, args.remaining_csv) if args.remaining_csv else None

    with input_csv.open("r", newline="", encoding="utf-8") as f:
        input_rows = list(csv.DictReader(f))
        fieldnames = list(input_rows[0].keys()) if input_rows else []

    output_done: Set[str] = set(read_candidate_ids(output_csv))
    input_ids = [row["candidate_id"] for row in input_rows if row.get("candidate_id")]
    remaining_rows = [row for row in input_rows if row.get("candidate_id") not in output_done]

    if remaining_csv is not None:
        remaining_csv.parent.mkdir(parents=True, exist_ok=True)
        with remaining_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(remaining_rows)

    print(
        "[RESUME]",
        f"input_total={len(input_ids)}",
        f"completed={len(output_done)}",
        f"remaining={len(remaining_rows)}",
        f"last_completed={max(output_done, key=int) if output_done else 'N/A'}",
        f"remaining_csv={remaining_csv if remaining_csv is not None else 'N/A'}",
    )


if __name__ == "__main__":
    main()
