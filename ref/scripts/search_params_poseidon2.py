#!/usr/bin/env python3
"""M2: SPHINCS+ Poseidon2 parameter search (structural filter + size metrics).

This script enumerates candidate tuples (n,h,d,k,a,w,q), computes:
- WOTS len1/len2/len
- FORS message bits/bytes
- H_msg split requirements
- key/signature byte sizes
- structural validity + reject reasons

Outputs:
- logs/params-search-raw-v1.csv
- logs/params-search-struct-pass-v1.csv
"""

from __future__ import annotations

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


def parse_num_token(token: str) -> int:
    token = token.strip()
    if not token:
        raise ValueError("empty token")
    if "^" in token:
        base, exp = token.split("^", 1)
        return int(base.strip()) ** int(exp.strip())
    return int(token)


def parse_axis(spec: str) -> List[int]:
    """Parse axis expression: e.g. "16,24,32", "60-66", "60-68:2", "2^20"."""
    values = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            range_part = part
            step = 1
            if ":" in part:
                range_part, step_part = part.split(":", 1)
                step = parse_num_token(step_part)
            start_s, end_s = range_part.split("-", 1)
            start = parse_num_token(start_s)
            end = parse_num_token(end_s)
            if step <= 0:
                raise ValueError(f"invalid step in axis: {part}")
            if start > end:
                raise ValueError(f"range start > end in axis: {part}")
            for v in range(start, end + 1, step):
                values.add(v)
        else:
            values.add(parse_num_token(part))
    out = sorted(values)
    if not out:
        raise ValueError(f"axis spec produced no values: {spec}")
    return out


def is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def wots_len2(len1: int, w: int) -> int:
    # floor(log_w(len1*(w-1))) + 1
    x = len1 * (w - 1)
    l2 = 0
    while x > 0:
        x //= w
        l2 += 1
    return max(1, l2)


@dataclass
class Candidate:
    n: int
    h: int
    d: int
    k: int
    a: int
    w: int
    q: int


def evaluate(c: Candidate) -> dict:
    reasons: List[str] = []

    if min(c.n, c.h, c.d, c.k, c.a, c.w, c.q) <= 0:
        reasons.append("non_positive_param")

    if c.w not in (16, 256):
        reasons.append("unsupported_w")
    if not is_power_of_two(c.w):
        reasons.append("w_not_power_of_two")

    if c.h % c.d != 0:
        reasons.append("h_not_divisible_by_d")
        tree_height = -1
    else:
        tree_height = c.h // c.d
        if tree_height <= 0:
            reasons.append("invalid_tree_height")

    if reasons:
        # Some metrics still useful for debugging rows.
        tree_bits = -1
        leaf_bits = -1
    else:
        tree_bits = tree_height * (c.d - 1)
        leaf_bits = tree_height

    # This repository's hash_message() currently enforces these bounds.
    if tree_bits > 64:
        reasons.append("tree_bits_gt_64_impl_limit")
    if leaf_bits > 32:
        reasons.append("leaf_bits_gt_32_impl_limit")

    wlog = int(math.log2(c.w)) if c.w > 0 and is_power_of_two(c.w) else -1
    len1 = math.ceil((8 * c.n) / wlog) if wlog > 0 else -1
    len2 = wots_len2(len1, c.w) if len1 > 0 and c.w > 1 else -1
    wots_len = len1 + len2 if len1 > 0 and len2 > 0 else -1

    fors_msg_bits = c.k * c.a
    fors_msg_bytes = (fors_msg_bits + 7) // 8
    tree_bytes = (tree_bits + 7) // 8 if tree_bits >= 0 else -1
    leaf_bytes = (leaf_bits + 7) // 8 if leaf_bits >= 0 else -1
    hmsg_needed_bytes = (
        fors_msg_bytes + tree_bytes + leaf_bytes
        if tree_bytes >= 0 and leaf_bytes >= 0
        else -1
    )

    pk_bytes = 2 * c.n
    sk_bytes = 4 * c.n
    if wots_len < 0:
        sig_bytes = -1
    else:
        sig_bytes = (
            c.n
            + ((c.a + 1) * c.k * c.n)
            + (c.d * wots_len * c.n)
            + (c.h * c.n)
        )
    if sig_bytes <= 0:
        reasons.append("invalid_sig_formula_input")

    is_struct_pass = len(reasons) == 0
    reject_reason = "" if is_struct_pass else ";".join(reasons)

    return {
        "n": c.n,
        "h": c.h,
        "d": c.d,
        "k": c.k,
        "a": c.a,
        "w": c.w,
        "q": c.q,
        "tree_height": tree_height,
        "tree_bits": tree_bits,
        "leaf_bits": leaf_bits,
        "wots_logw": wlog,
        "wots_len1": len1,
        "wots_len2": len2,
        "wots_len": wots_len,
        "fors_msg_bits": fors_msg_bits,
        "fors_msg_bytes": fors_msg_bytes,
        "hmsg_needed_bytes": hmsg_needed_bytes,
        "pk_bytes": pk_bytes,
        "sk_bytes": sk_bytes,
        "sig_bytes": sig_bytes,
        "struct_pass": "1" if is_struct_pass else "0",
        "reject_reason": reject_reason,
    }


def iterate_candidates(
    ns: Sequence[int],
    hs: Sequence[int],
    ds: Sequence[int],
    ks: Sequence[int],
    a_s: Sequence[int],
    ws: Sequence[int],
    qs: Sequence[int],
) -> Iterable[Candidate]:
    for n in ns:
        for h in hs:
            for d in ds:
                for k in ks:
                    for a in a_s:
                        for w in ws:
                            for q in qs:
                                yield Candidate(n=n, h=h, d=d, k=k, a=a, w=w, q=q)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SPHINCS+ Poseidon2 parameter search (M2 structural filter)."
    )
    parser.add_argument("--n", default="16,24", help='n axis, e.g. "16,24,32"')
    parser.add_argument("--h", default="60-68", help='h axis, e.g. "60-68:2"')
    parser.add_argument("--d", default="6,7,8,11,22", help='d axis')
    parser.add_argument("--k", default="14,17,22,33", help='k axis')
    parser.add_argument("--a", default="6,8,10,12,14", help='a axis')
    parser.add_argument("--w", default="16,256", help='w axis')
    parser.add_argument("--q", default="2^16,2^20", help='q axis')
    parser.add_argument(
        "--raw-csv",
        default="logs/params-search-raw-v1.csv",
        help="raw output csv path (relative to ref/ or absolute)",
    )
    parser.add_argument(
        "--pass-csv",
        default="logs/params-search-struct-pass-v1.csv",
        help="struct-pass output csv path (relative to ref/ or absolute)",
    )
    return parser


def resolve_output_path(root_dir: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return root_dir / path


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[1]

    ns = parse_axis(args.n)
    hs = parse_axis(args.h)
    ds = parse_axis(args.d)
    ks = parse_axis(args.k)
    a_s = parse_axis(args.a)
    ws = parse_axis(args.w)
    qs = parse_axis(args.q)

    rows = []
    for idx, cand in enumerate(
        iterate_candidates(ns, hs, ds, ks, a_s, ws, qs), start=1
    ):
        row = evaluate(cand)
        row["candidate_id"] = idx
        rows.append(row)

    # Sort for easier inspection: structural pass first, then smaller signatures.
    rows.sort(
        key=lambda r: (
            0 if r["struct_pass"] == "1" else 1,
            r["sig_bytes"] if isinstance(r["sig_bytes"], int) else 10**18,
            r["n"],
            r["h"],
            r["d"],
            r["k"],
            r["a"],
            r["w"],
            r["q"],
        )
    )

    fieldnames = [
        "candidate_id",
        "n",
        "h",
        "d",
        "k",
        "a",
        "w",
        "q",
        "tree_height",
        "tree_bits",
        "leaf_bits",
        "wots_logw",
        "wots_len1",
        "wots_len2",
        "wots_len",
        "fors_msg_bits",
        "fors_msg_bytes",
        "hmsg_needed_bytes",
        "pk_bytes",
        "sk_bytes",
        "sig_bytes",
        "struct_pass",
        "reject_reason",
    ]

    raw_csv = resolve_output_path(root_dir, args.raw_csv)
    pass_csv = resolve_output_path(root_dir, args.pass_csv)
    pass_rows = [r for r in rows if r["struct_pass"] == "1"]

    write_csv(raw_csv, rows, fieldnames)
    write_csv(pass_csv, pass_rows, fieldnames)

    print(
        "[M2] done:",
        f"total={len(rows)}",
        f"struct_pass={len(pass_rows)}",
        f"raw_csv={raw_csv}",
        f"pass_csv={pass_csv}",
    )


if __name__ == "__main__":
    main()
