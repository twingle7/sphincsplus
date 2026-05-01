#!/usr/bin/env python3
"""Extract the full M4-ok candidate set for sign/verify reruns.

Inputs:
- logs/params-security-pass-v1.csv
- logs/params-benchmark-v1-full.csv

Output:
- logs/params-m4-ok-for-signverify-v1.csv

This script keeps the full M3 security-pass row shape so that
`collect_benchmark_params.sh` can reuse the derived metrics and regenerate
temporary parameter headers without additional joins.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_rows(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def resolve_path(root_dir: Path, s: str) -> Path:
    p = Path(s)
    return p if p.is_absolute() else root_dir / p


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract full M4-ok candidates for sign/verify reruns."
    )
    p.add_argument("--security-csv", default="logs/params-security-pass-v1.csv")
    p.add_argument("--stark-csv", default="logs/params-benchmark-v1-full.csv")
    p.add_argument("--output-csv", default="logs/params-m4-ok-for-signverify-v1.csv")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root_dir = Path(__file__).resolve().parents[1]

    security_csv = resolve_path(root_dir, args.security_csv)
    stark_csv = resolve_path(root_dir, args.stark_csv)
    output_csv = resolve_path(root_dir, args.output_csv)

    security_rows = load_rows(security_csv)
    stark_rows = load_rows(stark_csv)

    security_pass = {
        r["candidate_id"]: r
        for r in security_rows
        if r.get("security_pass", "1") == "1"
    }
    stark_ok_ids = {
        r["candidate_id"]
        for r in stark_rows
        if r.get("status") == "ok"
    }

    selected = [
        security_pass[cid]
        for cid in sorted(stark_ok_ids, key=int)
        if cid in security_pass
    ]

    fieldnames = list(security_rows[0].keys()) if security_rows else []
    write_rows(output_csv, selected, fieldnames)

    print(
        "[M4->SV] done:",
        f"security_pass={len(security_pass)}",
        f"stark_ok={len(stark_ok_ids)}",
        f"selected={len(selected)}",
        f"output_csv={output_csv}",
    )


if __name__ == "__main__":
    main()
