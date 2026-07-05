#!/usr/bin/env python3
"""M5: global Pareto frontier and final recommendation generator.

Inputs:
- logs/params-security-pass-v1.csv
- logs/params-benchmark-v1-full.csv          (STARK metrics)
- logs/params-signverify-m4-ok-v1.csv        (full M4-ok sign/verify metrics)

Outputs:
- logs/params-m5-merged-v1.csv
- logs/params-pareto-frontier-v1.csv
- logs/params-pareto-nonfrontier-v1.csv
- logs/params-pareto-v1.md
- logs/params-final-candidates-v1.md
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


AXES = ("sig_bytes", "sign_ms", "verify_ms", "witness_rows")
CANONICAL_SECURITY_LEVELS = ("128", "192", "256")


def resolve_path(root_dir: Path, s: str) -> Path:
    p = Path(s)
    return p if p.is_absolute() else root_dir / p


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_rows(path: Path, rows: List[Dict[str, str]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def parse_int(v: str) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def parse_float(v: str) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None


def fmt_float(v: float) -> str:
    return f"{v:.3f}"


def total_time_ms(row: Dict[str, str]) -> float:
    return float(row["sign_ms"]) + float(row["verify_ms"])


def security_sort_key(v: str) -> Tuple[int, str]:
    try:
        return (0, f"{int(v):08d}")
    except Exception:
        return (1, v)


def ordered_security_levels(*collections: Iterable[str]) -> List[str]:
    seen = set()
    levels: List[str] = []
    for lvl in CANONICAL_SECURITY_LEVELS:
        seen.add(lvl)
        levels.append(lvl)
    for coll in collections:
        for lvl in sorted((x for x in coll if x and x not in seen), key=security_sort_key):
            seen.add(lvl)
            levels.append(lvl)
    return levels


def security_label(bits: str) -> str:
    mapping = {
        "128": "1级（128位）",
        "192": "3级（192位）",
        "256": "5级（256位）",
    }
    return mapping.get(bits, f"{bits}位")


def dominates(a: Dict[str, float], b: Dict[str, float], keys: Iterable[str]) -> bool:
    le_all = True
    lt_any = False
    for k in keys:
        av = a[k]
        bv = b[k]
        if av > bv:
            le_all = False
            break
        if av < bv:
            lt_any = True
    return le_all and lt_any


def first_dominator(rows: List[Dict[str, float]], idx: int, keys: Iterable[str]) -> Optional[Tuple[int, List[str]]]:
    target = rows[idx]
    for j, cand in enumerate(rows):
        if j == idx:
            continue
        if dominates(cand, target, keys):
            better_axes = [k for k in keys if cand[k] < target[k]]
            return j, better_axes
    return None


def choose_best(
    candidates: List[Dict[str, str]],
    key_fn,
) -> Optional[Dict[str, str]]:
    if not candidates:
        return None
    return sorted(candidates, key=key_fn)[0]


def build_markdown_table(rows: List[Dict[str, str]]) -> List[str]:
    lines = [
        "| candidate_id | sec_bits | n | h | d | k | a | w | q | sig_bytes | sign_ms | verify_ms | time_total_ms | witness_rows | prove_e2e_ms |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            "| {candidate_id} | {claimed_security_bits} | {n} | {h} | {d} | {k} | {a} | {w} | {q} | {sig_bytes} | {sign_ms} | {verify_ms} | {time_total_ms} | {witness_rows} | {prove_e2e_ms_median} |".format(
                **r
            )
        )
    return lines


def compute_frontier(
    rows: List[Dict[str, str]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    metric_rows: List[Dict[str, float]] = []
    for r in rows:
        metric_rows.append(
            {
                "sig_bytes": float(r["sig_bytes"]),
                "sign_ms": float(r["sign_ms"]),
                "verify_ms": float(r["verify_ms"]),
                "witness_rows": float(r["witness_rows"]),
            }
        )

    frontier_idx: List[int] = []
    nonfrontier_rows: List[Dict[str, str]] = []
    for i, r in enumerate(metric_rows):
        dom = first_dominator(metric_rows, i, AXES)
        if dom is None:
            frontier_idx.append(i)
        else:
            j, better_axes = dom
            nonfrontier_rows.append(
                {
                    **rows[i],
                    "dominated_by_candidate_id": rows[j]["candidate_id"],
                    "dominated_axes": ";".join(better_axes),
                    "drop_reason": "pareto_dominated",
                }
            )

    frontier_rows = [rows[i] for i in frontier_idx]
    frontier_rows.sort(
        key=lambda r: (
            security_sort_key(r.get("claimed_security_bits", "")),
            int(r["sig_bytes"]),
            float(r["sign_ms"]),
            float(r["verify_ms"]),
            int(r["witness_rows"]),
            int(r["candidate_id"]),
        )
    )
    return frontier_rows, nonfrontier_rows


def recommendation_label_map(bits: Optional[str]) -> List[Tuple[str, str]]:
    suffix = bits if bits else "128"
    return [
        ("最小时间", f"p2-{suffix}f"),
        ("最小约束", f"p2-{suffix}cs"),
        ("最小签名", f"p2-{suffix}s"),
        ("综合最优", f"p2-{suffix}"),
    ]


def compute_recommendations(
    frontier_rows: List[Dict[str, str]],
    *,
    bits: Optional[str] = None,
) -> Dict[str, Optional[Dict[str, str]]]:
    min_time = choose_best(
        frontier_rows,
        lambda r: (
            total_time_ms(r),
            int(r["sig_bytes"]),
            int(r["witness_rows"]),
            int(r["candidate_id"]),
        ),
    )
    min_sig = choose_best(
        frontier_rows,
        lambda r: (
            int(r["sig_bytes"]),
            total_time_ms(r),
            int(r["witness_rows"]),
            int(r["candidate_id"]),
        ),
    )
    min_constraints = choose_best(
        frontier_rows,
        lambda r: (
            int(r["witness_rows"]),
            float(r["prove_e2e_ms_median"]),
            total_time_ms(r),
            int(r["candidate_id"]),
        ),
    )

    balanced_axes = ("sig_bytes", "time_total_ms", "witness_rows")
    mins = {
        k: min((total_time_ms(r) if k == "time_total_ms" else float(r[k])) for r in frontier_rows)
        for k in balanced_axes
    } if frontier_rows else {}
    maxs = {
        k: max((total_time_ms(r) if k == "time_total_ms" else float(r[k])) for r in frontier_rows)
        for k in balanced_axes
    } if frontier_rows else {}

    def balanced_key(r: Dict[str, str]) -> Tuple[float, int]:
        score = 0.0
        for k in balanced_axes:
            lo = mins[k]
            hi = maxs[k]
            v = total_time_ms(r) if k == "time_total_ms" else float(r[k])
            if hi <= lo:
                score += 0.0
            else:
                score += (v - lo) / (hi - lo)
        return score, int(r["candidate_id"])

    balanced = choose_best(frontier_rows, balanced_key)
    label_pairs = recommendation_label_map(bits)
    return {
        f"{label}（{param_name}）": row
        for (label, param_name), row in zip(
            label_pairs,
            [min_time, min_constraints, min_sig, balanced],
        )
    }


def append_recommendation_lines(
    out_lines: List[str],
    picks: Dict[str, Optional[Dict[str, str]]],
) -> None:
    for name, row in picks.items():
        if row is None:
            out_lines.append(f"- {name}：无可用候选。")
        else:
            out_lines.append(
                f"- {name}：candidate_id={row['candidate_id']} "
                f"(安全等级={row['claimed_security_bits']} 位, "
                f"n={row['n']}, h={row['h']}, d={row['d']}, k={row['k']}, a={row['a']}, w={row['w']}, q={row['q']}; "
                f"sig_bytes={row['sig_bytes']}, sign_ms={row['sign_ms']}, verify_ms={row['verify_ms']}, "
                f"time_total_ms={row['time_total_ms']}, "
                f"witness_rows={row['witness_rows']}, prove_e2e_ms={row['prove_e2e_ms_median']})"
            )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M5 global Pareto frontier and recommendations")
    p.add_argument("--security-csv", default="logs/params-security-pass-v1.csv")
    p.add_argument("--stark-csv", default="logs/params-benchmark-v1-full.csv")
    p.add_argument("--signverify-csv", default="logs/params-signverify-m4-ok-v1.csv")
    p.add_argument("--merged-csv", default="logs/params-m5-merged-v1.csv")
    p.add_argument("--frontier-csv", default="logs/params-pareto-frontier-v1.csv")
    p.add_argument("--nonfrontier-csv", default="logs/params-pareto-nonfrontier-v1.csv")
    p.add_argument("--pareto-md", default="logs/params-pareto-v1.md")
    p.add_argument("--final-md", default="logs/params-final-candidates-v1.md")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root_dir = Path(__file__).resolve().parents[1]

    security_csv = resolve_path(root_dir, args.security_csv)
    stark_csv = resolve_path(root_dir, args.stark_csv)
    signverify_csv = resolve_path(root_dir, args.signverify_csv)
    merged_csv = resolve_path(root_dir, args.merged_csv)
    frontier_csv = resolve_path(root_dir, args.frontier_csv)
    nonfrontier_csv = resolve_path(root_dir, args.nonfrontier_csv)
    pareto_md = resolve_path(root_dir, args.pareto_md)
    final_md = resolve_path(root_dir, args.final_md)

    security_rows = load_rows(security_csv)
    stark_rows = load_rows(stark_csv)
    signverify_rows = load_rows(signverify_csv)

    security_pass = {r["candidate_id"] for r in security_rows if r.get("security_pass", "1") == "1"}
    stark_ok = {r["candidate_id"]: r for r in stark_rows if r.get("status") == "ok"}
    sign_ok = {r["candidate_id"]: r for r in signverify_rows if r.get("status") == "ok"}

    merged: List[Dict[str, str]] = []
    dropped: List[Dict[str, str]] = []
    candidate_ids = sorted(
        [cid for cid in security_pass if cid in stark_ok],
        key=int,
    )
    for cid in candidate_ids:
        if cid not in sign_ok:
            dropped.append({"candidate_id": cid, "drop_reason": "signverify_missing_or_not_ok"})
            continue

        sign = sign_ok[cid]
        stark = stark_ok[cid]
        sign_us = parse_float(sign.get("sign_us_median", ""))
        verify_us = parse_float(sign.get("verify_us_median", ""))
        witness_rows = parse_int(stark.get("witness_rows", ""))
        sig_bytes = parse_int(sign.get("sig_bytes", "")) or parse_int(stark.get("sig_bytes", ""))
        prove_e2e = parse_float(stark.get("prove_e2e_ms_median", ""))

        if (
            sign_us is None
            or verify_us is None
            or sign_us <= 0
            or verify_us <= 0
            or witness_rows is None
            or witness_rows <= 0
            or sig_bytes is None
            or sig_bytes <= 0
            or prove_e2e is None
            or prove_e2e <= 0
        ):
            dropped.append({"candidate_id": cid, "drop_reason": "invalid_or_zero_metrics"})
            continue

        row = {
            "candidate_id": cid,
            "n": sign["n"],
            "h": sign["h"],
            "d": sign["d"],
            "k": sign["k"],
            "a": sign["a"],
            "w": sign["w"],
            "q": sign["q"],
            "sig_bytes": str(sig_bytes),
            "sign_ms": fmt_float(sign_us / 1000.0),
            "verify_ms": fmt_float(verify_us / 1000.0),
            "time_total_ms": fmt_float((sign_us + verify_us) / 1000.0),
            "witness_rows": str(witness_rows),
            "prove_e2e_ms_median": fmt_float(prove_e2e),
            "proof_bytes": stark.get("proof_bytes", "0"),
            "claimed_security_bits": next(
                (s["claimed_security_bits"] for s in security_rows if s["candidate_id"] == cid),
                "",
            ),
        }
        merged.append(row)

    security_pass_counts: Dict[str, int] = {}
    for r in security_rows:
        if r.get("security_pass", "1") == "1":
            bits = r.get("claimed_security_bits", "")
            security_pass_counts[bits] = security_pass_counts.get(bits, 0) + 1

    merged_counts: Dict[str, int] = {}
    for r in merged:
        bits = r.get("claimed_security_bits", "")
        merged_counts[bits] = merged_counts.get(bits, 0) + 1

    frontier_rows, nonfrontier_rows = compute_frontier(merged)

    frontier_counts: Dict[str, int] = {}
    for r in frontier_rows:
        bits = r.get("claimed_security_bits", "")
        frontier_counts[bits] = frontier_counts.get(bits, 0) + 1

    security_levels = ordered_security_levels(
        security_pass_counts.keys(),
        merged_counts.keys(),
        frontier_counts.keys(),
    )

    merged_fields = [
        "candidate_id",
        "n",
        "h",
        "d",
        "k",
        "a",
        "w",
        "q",
        "sig_bytes",
        "sign_ms",
        "verify_ms",
        "time_total_ms",
        "witness_rows",
        "prove_e2e_ms_median",
        "proof_bytes",
        "claimed_security_bits",
    ]
    write_rows(merged_csv, merged, merged_fields)

    frontier_fields = merged_fields + ["frontier_tag"]
    write_rows(
        frontier_csv,
        [{**r, "frontier_tag": "pareto"} for r in frontier_rows],
        frontier_fields,
    )

    nonfrontier_fields = merged_fields + [
        "dominated_by_candidate_id",
        "dominated_axes",
        "drop_reason",
    ]
    write_rows(nonfrontier_csv, nonfrontier_rows + dropped, nonfrontier_fields)

    global_picks = compute_recommendations(frontier_rows)
    per_security_frontiers = {
        bits: [r for r in frontier_rows if r.get("claimed_security_bits", "") == bits]
        for bits in security_levels
    }
    per_security_picks = {
        bits: compute_recommendations(rows, bits=bits)
        for bits, rows in per_security_frontiers.items()
    }

    pareto_lines: List[str] = []
    pareto_lines.append("# M5 全局 Pareto 前沿结果 v1")
    pareto_lines.append("")
    pareto_lines.append("## 1. 输入与筛选")
    pareto_lines.append(f"- 安全通过候选数（M3）：{len(security_pass)}")
    pareto_lines.append(f"- 全量 STARK 可用候选数（M4）：{len(stark_ok)}")
    pareto_lines.append(f"- 全量 sign/verify 补跑可用候选数（M4-ok 子集）：{len(sign_ok)}")
    pareto_lines.append(f"- 合并后有效候选数：{len(merged)}")
    pareto_lines.append(f"- Pareto 前沿候选数：{len(frontier_rows)}")
    pareto_lines.append("")
    pareto_lines.append("### 1.1 按安全等级统计")
    pareto_lines.append("| 安全等级 | M3 安全通过 | M5 合并有效 | Pareto 前沿 |")
    pareto_lines.append("|---|---:|---:|---:|")
    for bits in security_levels:
        pareto_lines.append(
            f"| {security_label(bits)} | {security_pass_counts.get(bits, 0)} | {merged_counts.get(bits, 0)} | {frontier_counts.get(bits, 0)} |"
        )
    pareto_lines.append("")
    pareto_lines.append("## 2. 多目标轴（均为最小化）")
    pareto_lines.append("- `sig_bytes`")
    pareto_lines.append("- `sign_ms`")
    pareto_lines.append("- `verify_ms`")
    pareto_lines.append("- `time_total_ms = sign_ms + verify_ms`")
    pareto_lines.append("- `witness_rows`")
    pareto_lines.append("")
    pareto_lines.append("## 3. 全局 Pareto 前沿候选")
    if frontier_rows:
        pareto_lines.extend(build_markdown_table(frontier_rows))
    else:
        pareto_lines.append("- 无可用前沿候选（请检查输入数据）")
    pareto_lines.append("")
    pareto_lines.append("## 4. 分安全等级 Pareto 前沿")
    for bits in security_levels:
        pareto_lines.append("")
        pareto_lines.append(f"### {security_label(bits)}")
        if per_security_frontiers[bits]:
            pareto_lines.extend(build_markdown_table(per_security_frontiers[bits]))
        else:
            pareto_lines.append(f"- 当前 M5 结果中无 {security_label(bits)} 可用候选。")
    pareto_md.parent.mkdir(parents=True, exist_ok=True)
    pareto_md.write_text("\n".join(pareto_lines) + "\n", encoding="utf-8")

    final_lines: List[str] = []
    final_lines.append("# M5 最终推荐参数 v1")
    final_lines.append("")
    final_lines.append("## 1. 推荐规则")
    final_lines.append("- 最小时间：按 `time_total_ms = sign_ms + verify_ms` 升序，对应命名 `p2-128f`。")
    final_lines.append("- 最小约束：按 `witness_rows` 升序，对应命名 `p2-128cs`。")
    final_lines.append("- 最小签名：按 `sig_bytes` 升序，对应命名 `p2-128s`。")
    final_lines.append("- 综合最优：按 `sig_bytes`、`time_total_ms` 与 `witness_rows` 的归一化总分最小，对应命名 `p2-128`。")
    final_lines.append("")
    final_lines.append("## 2. 全局推荐结果")
    append_recommendation_lines(final_lines, global_picks)
    final_lines.append("")
    final_lines.append("## 3. 分安全等级推荐")
    for bits in security_levels:
        final_lines.append(f"### {security_label(bits)}")
        if per_security_frontiers[bits]:
            append_recommendation_lines(final_lines, per_security_picks[bits])
        else:
            final_lines.append(f"- 当前 M5 结果中无 {security_label(bits)} 可用候选。")
        final_lines.append("")
    final_lines.append("## 4. 说明")
    final_lines.append("- 推荐候选均来自全局 Pareto 前沿，并且满足 M3 安全通过 + M4 实测可用 + sign/verify 补跑可用。")
    final_lines.append("- 若某一安全等级在 M5 中没有有效候选，文档会明确标注为空，而不是与其他安全等级混合汇报。")
    final_lines.append("- 详细候选与淘汰原因见配套 CSV 与 Pareto 文档。")
    final_md.parent.mkdir(parents=True, exist_ok=True)
    final_md.write_text("\n".join(final_lines) + "\n", encoding="utf-8")

    print(
        "[M5] done:",
        f"merged={len(merged)}",
        f"frontier={len(frontier_rows)}",
        f"nonfrontier={len(nonfrontier_rows)}",
        f"dropped={len(dropped)}",
        f"pareto_md={pareto_md}",
        f"final_md={final_md}",
    )


if __name__ == "__main__":
    main()
