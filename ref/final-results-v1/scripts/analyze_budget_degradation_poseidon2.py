#!/usr/bin/env python3
"""M6: budget degradation analysis for recommended Poseidon2 parameter sets."""

from __future__ import annotations

import argparse
import csv
import math
import re
from pathlib import Path
from typing import Dict, List, Tuple


def resolve_path(root_dir: Path, s: str) -> Path:
    p = Path(s)
    return p if p.is_absolute() else root_dir / p


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def parse_recommended_ids(final_md_text: str) -> List[str]:
    ids = re.findall(r"candidate_id=(\d+)", final_md_text)
    out: List[str] = []
    for x in ids:
        if x not in out:
            out.append(x)
    return out


def log2_floor(x: int) -> int:
    if x <= 0:
        raise ValueError("log2 undefined for non-positive")
    return int(math.log2(x))


def parse_budget_expr(expr: str, q_base: int) -> Tuple[str, int]:
    s = expr.strip().lower()
    if s == "q":
        return "q", q_base
    if s == "2q":
        return "2q", 2 * q_base
    m = re.match(r"2\^(\d+)$", s)
    if m:
        n = int(m.group(1))
        return f"2^{n}", 2**n
    raise ValueError(f"unsupported budget expression: {expr}")


def evaluate_row(
    row: Dict[str, str],
    q_eval: int,
    *,
    target_bits: int,
    poseidon2_floor_bits: int,
) -> Dict[str, str]:
    n = int(row["n"])
    k = int(row["k"])
    a = int(row["a"])
    q_ref = int(row["q"])
    candidate_id = row["candidate_id"]

    hash_bits = 8 * n
    fors_bits = k * a
    comb_security_bits = min(hash_bits, fors_bits)

    if q_eval <= q_ref:
        penalty = 0
    else:
        penalty = max(0, log2_floor(q_eval) - log2_floor(q_ref))
    budget_security_bits = max(0, comb_security_bits - penalty)

    claimed = min(comb_security_bits, poseidon2_floor_bits, budget_security_bits)
    security_pass = claimed >= target_bits

    out = {
        "candidate_id": str(candidate_id),
        "n": str(n),
        "h": str(row["h"]),
        "d": str(row["d"]),
        "k": str(k),
        "a": str(a),
        "w": str(row["w"]),
        "q_reference": str(q_ref),
        "q_eval": str(q_eval),
        "comb_security_bits": str(comb_security_bits),
        "budget_penalty_bits": str(penalty),
        "budget_security_bits": str(budget_security_bits),
        "poseidon2_security_bits": str(poseidon2_floor_bits),
        "claimed_security_bits": str(claimed),
        "target_bits": str(target_bits),
        "security_pass": "1" if security_pass else "0",
    }
    return out


def build_md(
    rows: List[Dict[str, str]],
    out_md: Path,
    budgets: List[str],
    target_bits: int,
    poseidon2_floor_bits: int,
) -> None:
    out_md.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append("# M6 预算退化分析 v1")
    lines.append("")
    lines.append("## 1. 口径")
    lines.append("- 模型：`proxy-v1`（与 M3 一致）。")
    lines.append("- 公式：`claimed = min(comb, poseidon2_floor, budget)`。")
    lines.append("- 预算项：`budget = max(0, comb - max(0, floor(log2(q_eval)) - floor(log2(q_reference))))`。")
    lines.append(f"- 阈值：`target_bits={target_bits}`，`poseidon2_floor_bits={poseidon2_floor_bits}`。")
    lines.append(f"- 预算点：`{', '.join(budgets)}`。")
    lines.append("")
    lines.append("## 2. 推荐参数组在多预算点的下界变化")
    lines.append("")
    lines.append("| candidate_id | q_reference | budget_label | q_eval | comb_security_bits | budget_penalty_bits | budget_security_bits | claimed_security_bits | security_pass |")
    lines.append("|---:|---:|---|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        lines.append(
            f"| {r['candidate_id']} | {r['q_reference']} | {r['budget_label']} | {r['q_eval']} | {r['comb_security_bits']} | {r['budget_penalty_bits']} | {r['budget_security_bits']} | {r['claimed_security_bits']} | {r['security_pass']} |"
        )
    lines.append("")
    pass_points = sorted({r["budget_label"] for r in rows if r["security_pass"] == "1"})
    fail_points = sorted({r["budget_label"] for r in rows if r["security_pass"] == "0"})
    pass_text = ", ".join(pass_points) if pass_points else "无"
    fail_text = ", ".join(fail_points) if fail_points else "无"

    lines.append("## 3. 结论")
    lines.append(f"- 在当前推荐参数中，保持目标筛选达标的预算点：`{pass_text}`。")
    lines.append(f"- 出现低于目标阈值的预算点：`{fail_text}`。")
    lines.append("- 该结论用于“目标筛选达标”叙述，不替代严格证明口径。")

    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M6 budget degradation analysis")
    p.add_argument("--frontier-csv", default="logs/params-pareto-frontier-v1.csv")
    p.add_argument("--final-md", default="logs/params-final-candidates-v1.md")
    p.add_argument("--output-csv", default="logs/params-budget-degradation-v1.csv")
    p.add_argument("--output-md", default="logs/params-budget-degradation-v1.md")
    p.add_argument("--target-bits", type=int, default=128)
    p.add_argument("--poseidon2-floor-bits", type=int, default=128)
    p.add_argument("--budgets", default="q,2q,2^20,2^30")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    frontier_csv = resolve_path(root, args.frontier_csv)
    final_md = resolve_path(root, args.final_md)
    out_csv = resolve_path(root, args.output_csv)
    out_md = resolve_path(root, args.output_md)

    rows_frontier = load_csv(frontier_csv)
    by_id = {r["candidate_id"]: r for r in rows_frontier}
    rec_ids = parse_recommended_ids(read_text(final_md))
    budget_exprs = [x.strip() for x in args.budgets.split(",") if x.strip()]

    out_rows: List[Dict[str, str]] = []
    for cid in rec_ids:
        if cid not in by_id:
            continue
        row = by_id[cid]
        q_ref = int(row["q"])
        for expr in budget_exprs:
            label, q_eval = parse_budget_expr(expr, q_ref)
            ev = evaluate_row(
                row,
                q_eval,
                target_bits=args.target_bits,
                poseidon2_floor_bits=args.poseidon2_floor_bits,
            )
            ev["budget_label"] = label
            out_rows.append(ev)

    # stable output
    budget_rank = {"q": 0, "2q": 1, "2^20": 2, "2^30": 3}
    out_rows.sort(
        key=lambda x: (
            int(x["candidate_id"]),
            budget_rank.get(x["budget_label"], 99),
            x["budget_label"],
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
        "q_reference",
        "budget_label",
        "q_eval",
        "comb_security_bits",
        "budget_penalty_bits",
        "budget_security_bits",
        "poseidon2_security_bits",
        "claimed_security_bits",
        "target_bits",
        "security_pass",
    ]
    write_csv(out_csv, out_rows, fieldnames)
    build_md(
        out_rows,
        out_md,
        budgets=budget_exprs,
        target_bits=args.target_bits,
        poseidon2_floor_bits=args.poseidon2_floor_bits,
    )

    print(
        "[M6] done:",
        f"recommended={len(rec_ids)}",
        f"rows={len(out_rows)}",
        f"output_csv={out_csv}",
        f"output_md={out_md}",
    )


if __name__ == "__main__":
    main()
