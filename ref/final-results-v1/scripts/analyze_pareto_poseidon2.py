#!/usr/bin/env python3
"""M5: Pareto frontier and final recommendation generator.

Inputs:
- logs/params-security-pass-v1.csv
- logs/params-benchmark-v1-full.csv          (STARK metrics)
- logs/params-signverify-finalists.csv       (sign/verify metrics)

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


def choose_distinct(
    candidates: List[Dict[str, str]],
    key_fn,
    used: set[str],
) -> Optional[Dict[str, str]]:
    for r in sorted(candidates, key=key_fn):
        cid = r["candidate_id"]
        if cid not in used:
            used.add(cid)
            return r
    return None


def build_markdown_table(rows: List[Dict[str, str]]) -> List[str]:
    lines = [
        "| candidate_id | n | h | d | k | a | w | q | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in rows:
        lines.append(
            "| {candidate_id} | {n} | {h} | {d} | {k} | {a} | {w} | {q} | {sig_bytes} | {sign_ms} | {verify_ms} | {witness_rows} | {prove_e2e_ms_median} |".format(
                **r
            )
        )
    return lines


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M5 Pareto frontier and recommendations")
    p.add_argument("--security-csv", default="logs/params-security-pass-v1.csv")
    p.add_argument("--stark-csv", default="logs/params-benchmark-v1-full.csv")
    p.add_argument("--signverify-csv", default="logs/params-signverify-finalists.csv")
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
    for cid, sign in sorted(sign_ok.items(), key=lambda kv: int(kv[0])):
        if cid not in security_pass:
            dropped.append({"candidate_id": cid, "drop_reason": "security_not_pass"})
            continue
        if cid not in stark_ok:
            dropped.append({"candidate_id": cid, "drop_reason": "stark_missing_or_not_ok"})
            continue

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
            "witness_rows": str(witness_rows),
            "prove_e2e_ms_median": fmt_float(prove_e2e),
            "proof_bytes": stark.get("proof_bytes", "0"),
            "claimed_security_bits": next(
                (s["claimed_security_bits"] for s in security_rows if s["candidate_id"] == cid),
                "",
            ),
        }
        merged.append(row)

    metric_rows: List[Dict[str, float]] = []
    for r in merged:
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
                    **merged[i],
                    "dominated_by_candidate_id": merged[j]["candidate_id"],
                    "dominated_axes": ";".join(better_axes),
                    "drop_reason": "pareto_dominated",
                }
            )

    frontier_rows = [merged[i] for i in frontier_idx]
    frontier_rows.sort(
        key=lambda r: (
            int(r["sig_bytes"]),
            float(r["sign_ms"]),
            float(r["verify_ms"]),
            int(r["witness_rows"]),
            int(r["candidate_id"]),
        )
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

    # recommendations from frontier
    used: set[str] = set()
    min_sig = choose_distinct(
        frontier_rows,
        lambda r: (
            int(r["sig_bytes"]),
            float(r["sign_ms"]),
            int(r["witness_rows"]),
            int(r["candidate_id"]),
        ),
        used,
    )
    min_constraints = choose_distinct(
        frontier_rows,
        lambda r: (
            int(r["witness_rows"]),
            float(r["prove_e2e_ms_median"]),
            int(r["sig_bytes"]),
            int(r["candidate_id"]),
        ),
        used,
    )

    # balanced score: normalized sum on 4 axes inside frontier.
    mins = {k: min(float(r[k]) for r in frontier_rows) for k in AXES} if frontier_rows else {}
    maxs = {k: max(float(r[k]) for r in frontier_rows) for k in AXES} if frontier_rows else {}

    def balanced_key(r: Dict[str, str]) -> Tuple[float, int]:
        score = 0.0
        for k in AXES:
            lo = mins[k]
            hi = maxs[k]
            v = float(r[k])
            if hi <= lo:
                score += 0.0
            else:
                score += (v - lo) / (hi - lo)
        return score, int(r["candidate_id"])

    balanced = choose_distinct(frontier_rows, balanced_key, used)

    pareto_lines: List[str] = []
    pareto_lines.append("# M5 Pareto 前沿结果 v1")
    pareto_lines.append("")
    pareto_lines.append("## 1. 输入与筛选")
    pareto_lines.append(f"- 安全通过候选数（M3）：{len(security_pass)}")
    pareto_lines.append(f"- 全量 STARK 可用候选数（M4）：{len(stark_ok)}")
    pareto_lines.append(f"- sign/verify 补跑可用候选数：{len(sign_ok)}")
    pareto_lines.append(f"- 合并后有效候选数：{len(merged)}")
    pareto_lines.append(f"- Pareto 前沿候选数：{len(frontier_rows)}")
    pareto_lines.append("")
    pareto_lines.append("## 2. 多目标轴（均为最小化）")
    pareto_lines.append("- `sig_bytes`")
    pareto_lines.append("- `sign_ms`")
    pareto_lines.append("- `verify_ms`")
    pareto_lines.append("- `witness_rows`")
    pareto_lines.append("")
    pareto_lines.append("## 3. Pareto 前沿候选")
    if frontier_rows:
        pareto_lines.extend(build_markdown_table(frontier_rows))
    else:
        pareto_lines.append("- 无可用前沿候选（请检查输入数据）")
    pareto_md.parent.mkdir(parents=True, exist_ok=True)
    pareto_md.write_text("\n".join(pareto_lines) + "\n", encoding="utf-8")

    final_lines: List[str] = []
    final_lines.append("# M5 最终推荐参数 v1")
    final_lines.append("")
    final_lines.append("## 1. 推荐规则")
    final_lines.append("- 最小签名：按 `sig_bytes` 升序。")
    final_lines.append("- 最小约束：按 `witness_rows` 升序。")
    final_lines.append("- 综合平衡：按四目标归一化总分最小。")
    final_lines.append("")
    final_lines.append("## 2. 推荐结果")

    picks: List[Tuple[str, Optional[Dict[str, str]]]] = [
        ("最小签名", min_sig),
        ("最小约束", min_constraints),
        ("综合平衡", balanced),
    ]
    for name, row in picks:
        if row is None:
            final_lines.append(f"- {name}：无可用候选。")
        else:
            final_lines.append(
                f"- {name}：candidate_id={row['candidate_id']} "
                f"(n={row['n']}, h={row['h']}, d={row['d']}, k={row['k']}, a={row['a']}, w={row['w']}, q={row['q']}; "
                f"sig_bytes={row['sig_bytes']}, sign_ms={row['sign_ms']}, verify_ms={row['verify_ms']}, witness_rows={row['witness_rows']}, prove_e2e_ms={row['prove_e2e_ms_median']})"
            )
    final_lines.append("")
    final_lines.append("## 3. 说明")
    final_lines.append("- 推荐候选均来自 Pareto 前沿，并且满足 M3 安全通过 + M4 实测可用。")
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
