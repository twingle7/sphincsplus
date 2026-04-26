#!/usr/bin/env python3
"""M3: security filtering for SPHINCS+ Poseidon2 candidates.

Input:
- M2 structural-pass CSV (default: logs/params-search-struct-pass-v1.csv)

Output:
- logs/params-security-pass-v1.csv

Model notes:
- This is a reproducible *proxy-v1* filter for milestone M3.
- It does NOT claim a formal proof-equivalent bound.
- It provides auditable fields:
  comb_security_bits, poseidon2_security_bits, budget_security_bits,
  claimed_security_bits, security_pass, security_reject_reason.
"""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Dict, List


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_rows(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def safe_int(row: Dict[str, str], key: str) -> int:
    try:
        return int(row[key])
    except Exception as exc:
        raise ValueError(f"invalid integer field {key}={row.get(key)!r}") from exc


def log2_floor(x: int) -> int:
    if x <= 0:
        raise ValueError("log2 undefined for non-positive")
    return int(math.log2(x))


def evaluate_row(
    row: Dict[str, str],
    *,
    target_bits: int,
    poseidon2_floor_bits: int,
    q_reference: int,
) -> Dict[str, str]:
    n = safe_int(row, "n")
    k = safe_int(row, "k")
    a = safe_int(row, "a")
    q = safe_int(row, "q")

    hash_bits = 8 * n
    fors_bits = k * a

    # proxy-v1: composition-level bound (conservative proxy for M3 automation)
    comb_security_bits = min(hash_bits, fors_bits)

    # proxy-v1: instance-level floor is externally configured (default 128)
    poseidon2_security_bits = poseidon2_floor_bits

    # proxy-v1: q-budget degradation relative to q_reference
    # if q <= q_reference: no penalty; otherwise subtract log2 growth.
    if q <= q_reference:
        budget_penalty_bits = 0
    else:
        budget_penalty_bits = max(0, log2_floor(q) - log2_floor(q_reference))
    budget_security_bits = max(0, comb_security_bits - budget_penalty_bits)

    claimed_security_bits = min(
        comb_security_bits,
        poseidon2_security_bits,
        budget_security_bits,
    )

    reject_reasons: List[str] = []
    if comb_security_bits < target_bits:
        reject_reasons.append("comb<target")
    if poseidon2_security_bits < target_bits:
        reject_reasons.append("p2<target")
    if budget_security_bits < target_bits:
        reject_reasons.append("budget<target")

    security_pass = len(reject_reasons) == 0

    out = dict(row)
    out["security_model"] = "proxy-v1"
    out["target_bits"] = str(target_bits)
    out["poseidon2_floor_bits"] = str(poseidon2_floor_bits)
    out["q_reference"] = str(q_reference)
    out["comb_security_bits"] = str(comb_security_bits)
    out["budget_penalty_bits"] = str(budget_penalty_bits)
    out["budget_security_bits"] = str(budget_security_bits)
    out["poseidon2_security_bits"] = str(poseidon2_security_bits)
    out["claimed_security_bits"] = str(claimed_security_bits)
    out["security_pass"] = "1" if security_pass else "0"
    out["security_reject_reason"] = "" if security_pass else ";".join(reject_reasons)
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Evaluate M3 security filter from M2 structural-pass candidates."
    )
    p.add_argument(
        "--input-csv",
        default="logs/params-search-struct-pass-v1.csv",
        help="input structural-pass CSV from M2",
    )
    p.add_argument(
        "--output-csv",
        default="logs/params-security-pass-v1.csv",
        help="output M3 security-pass CSV",
    )
    p.add_argument(
        "--all-output-csv",
        default="logs/params-security-eval-v1.csv",
        help="optional full evaluation CSV (pass+reject)",
    )
    p.add_argument("--target-bits", type=int, default=128, help="security target")
    p.add_argument(
        "--poseidon2-floor-bits",
        type=int,
        default=128,
        help="assumed Poseidon2 instance floor for proxy-v1",
    )
    p.add_argument(
        "--q-reference",
        type=int,
        default=(2**16),
        help="reference signing budget for zero-penalty budget bound",
    )
    return p.parse_args()


def resolve_path(root_dir: Path, s: str) -> Path:
    p = Path(s)
    return p if p.is_absolute() else root_dir / p


def main() -> None:
    args = parse_args()
    root_dir = Path(__file__).resolve().parents[1]

    in_csv = resolve_path(root_dir, args.input_csv)
    out_csv = resolve_path(root_dir, args.output_csv)
    all_csv = resolve_path(root_dir, args.all_output_csv)

    rows = load_rows(in_csv)
    evaluated = [
        evaluate_row(
            r,
            target_bits=args.target_bits,
            poseidon2_floor_bits=args.poseidon2_floor_bits,
            q_reference=args.q_reference,
        )
        for r in rows
    ]
    passed = [r for r in evaluated if r["security_pass"] == "1"]

    # Keep deterministic ordering: best claimed first, then smaller signature.
    def sort_key(r: Dict[str, str]):
        return (
            -int(r["claimed_security_bits"]),
            int(r.get("sig_bytes", "0")),
            int(r["n"]),
            int(r["h"]),
            int(r["d"]),
            int(r["k"]),
            int(r["a"]),
            int(r["w"]),
            int(r["q"]),
        )

    evaluated.sort(key=sort_key)
    passed.sort(key=sort_key)

    fieldnames = list(evaluated[0].keys()) if evaluated else [
        "candidate_id",
        "n",
        "h",
        "d",
        "k",
        "a",
        "w",
        "q",
        "security_model",
        "target_bits",
        "poseidon2_floor_bits",
        "q_reference",
        "comb_security_bits",
        "budget_penalty_bits",
        "budget_security_bits",
        "poseidon2_security_bits",
        "claimed_security_bits",
        "security_pass",
        "security_reject_reason",
    ]

    write_rows(all_csv, evaluated, fieldnames)
    write_rows(out_csv, passed, fieldnames)

    print(
        "[M3] done:",
        f"total={len(evaluated)}",
        f"security_pass={len(passed)}",
        f"output_csv={out_csv}",
        f"all_output_csv={all_csv}",
    )


if __name__ == "__main__":
    main()
