#!/usr/bin/env python3
"""Generate multi-metric comparison charts and final recommendations."""

from __future__ import annotations

import argparse
import csv
import math
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt


COMMON_AXES = ("sig_bytes", "sign_ms", "verify_ms")
CANDIDATE_AXES = ("sig_bytes", "sign_ms", "verify_ms", "witness_rows", "prove_e2e_ms")


def resolve_path(root_dir: Path, s: str) -> Path:
    p = Path(s)
    return p if p.is_absolute() else root_dir / p


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_recommended_ids(final_md: str) -> List[str]:
    ids = re.findall(r"candidate_id=(\d+)", final_md)
    out: List[str] = []
    for x in ids:
        if x not in out:
            out.append(x)
    return out


def parse_benchmark_4way(md_text: str) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for line in md_text.splitlines():
        if "case1_baseline_sign" in line or "case2_poseidon2_sign" in line:
            parts = [x.strip() for x in line.strip().strip("|").split("|")]
            if len(parts) < 9:
                continue
            case = parts[1]
            params = parts[2]
            sign_us = float(parts[4])
            verify_us = float(parts[7])
            out[case] = {
                "label": params,
                "sign_ms": sign_us / 1000.0,
                "verify_ms": verify_us / 1000.0,
            }
    return out


def parse_define_int(text: str, key: str) -> Optional[int]:
    m = re.search(rf"^\s*#define\s+{re.escape(key)}\s+(\d+)\s*$", text, flags=re.MULTILINE)
    return int(m.group(1)) if m else None


def wots_len(n: int, w: int) -> int:
    logw = int(math.log2(w))
    len1 = math.ceil((8 * n) / logw)
    len2 = math.floor(math.log(len1 * (w - 1), w)) + 1
    return len1 + len2


def calc_sig_bytes_from_params_h(path: Path) -> Optional[int]:
    text = read_text(path)
    n = parse_define_int(text, "SPX_N")
    h = parse_define_int(text, "SPX_FULL_HEIGHT")
    d = parse_define_int(text, "SPX_D")
    a = parse_define_int(text, "SPX_FORS_HEIGHT")
    k = parse_define_int(text, "SPX_FORS_TREES")
    w = parse_define_int(text, "SPX_WOTS_W")
    if None in (n, h, d, a, k, w):
        return None
    wl = wots_len(n, w)
    return n + ((a + 1) * k * n) + (d * wl * n) + (h * n)


def save_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def norm_minmax(values: Iterable[float]) -> Tuple[float, float]:
    vals = list(values)
    return min(vals), max(vals)


def normalize(v: float, lo: float, hi: float) -> float:
    if hi <= lo:
        return 0.0
    return (v - lo) / (hi - lo)


def plot_bar_log(
    labels: List[str],
    values: List[float],
    title: str,
    ylabel: str,
    out_png: Path,
    highlight_labels: Optional[set[str]] = None,
) -> None:
    out_png.parent.mkdir(parents=True, exist_ok=True)
    colors = []
    for lbl in labels:
        if highlight_labels and lbl in highlight_labels:
            colors.append("#d62728")
        elif "192s" in lbl:
            colors.append("#1f77b4")
        else:
            colors.append("#7f7f7f")

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(labels, values, color=colors)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_yscale("log")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_scatter(frontier_rows: List[Dict[str, str]], out_png: Path, rec_ids: set[str]) -> None:
    out_png.parent.mkdir(parents=True, exist_ok=True)
    xs: List[float] = []
    ys: List[float] = []
    labels: List[str] = []
    colors: List[str] = []
    for r in frontier_rows:
        x = float(r["sign_ms"])
        y = float(r["prove_e2e_ms_median"])
        cid = r["candidate_id"]
        xs.append(x)
        ys.append(y)
        labels.append(f"id={cid}")
        colors.append("#d62728" if cid in rec_ids else "#7f7f7f")

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.scatter(xs, ys, c=colors, s=60)
    for x, y, label in zip(xs, ys, labels):
        ax.annotate(label, (x, y), textcoords="offset points", xytext=(4, 4), fontsize=8)
    ax.set_xlabel("sign_ms (lower is better)")
    ax.set_ylabel("prove_e2e_ms (lower is better)")
    ax.set_title("Pareto Frontier: Sign vs STARK Prove E2E")
    ax.grid(True, linestyle="--", alpha=0.35)
    fig.tight_layout()
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_common_multimetric(rows: List[Dict[str, str]], out_png: Path) -> None:
    # Lower is better; convert to 0-1 normalized cost.
    data: Dict[str, Dict[str, float]] = {}
    for r in rows:
        try:
            data[r["group"]] = {k: float(r[k]) for k in COMMON_AXES}
        except Exception:
            continue
    labels = list(data.keys())
    if not labels:
        return

    mins = {k: norm_minmax(data[g][k] for g in labels)[0] for k in COMMON_AXES}
    maxs = {k: norm_minmax(data[g][k] for g in labels)[1] for k in COMMON_AXES}

    x = list(range(len(labels)))
    width = 0.22
    fig, ax = plt.subplots(figsize=(13, 5))
    for idx, metric in enumerate(COMMON_AXES):
        vals = [normalize(data[g][metric], mins[metric], maxs[metric]) for g in labels]
        offset = (idx - 1) * width
        ax.bar([xi + offset for xi in x], vals, width=width, label=f"{metric} (norm)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("normalized cost (lower is better)")
    ax.set_title("Multi-metric Comparison (Common Axes)")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend()
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def plot_candidate_heatmap(frontier_rows: List[Dict[str, str]], rec_ids: set[str], out_png: Path) -> None:
    # Candidate-only five-axis normalized heatmap.
    rows = []
    for r in frontier_rows:
        rows.append(
            {
                "id": r["candidate_id"],
                "sig_bytes": float(r["sig_bytes"]),
                "sign_ms": float(r["sign_ms"]),
                "verify_ms": float(r["verify_ms"]),
                "witness_rows": float(r["witness_rows"]),
                "prove_e2e_ms": float(r["prove_e2e_ms_median"]),
            }
        )
    rows.sort(key=lambda x: int(x["id"]))
    if not rows:
        return

    mins = {k: min(r[k] for r in rows) for k in CANDIDATE_AXES}
    maxs = {k: max(r[k] for r in rows) for k in CANDIDATE_AXES}

    matrix: List[List[float]] = []
    ylabels: List[str] = []
    for r in rows:
        matrix.append([normalize(r[k], mins[k], maxs[k]) for k in CANDIDATE_AXES])
        ylabels.append(f"id={r['id']}" + (" (rec)" if r["id"] in rec_ids else ""))

    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(range(len(CANDIDATE_AXES)))
    ax.set_xticklabels(CANDIDATE_AXES, rotation=20, ha="right")
    ax.set_yticks(range(len(ylabels)))
    ax.set_yticklabels(ylabels)
    ax.set_title("Candidate Multi-metric Heatmap (normalized cost)")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("normalized cost (lower is better)")
    fig.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_png, dpi=150)
    plt.close(fig)


def rank_candidates(frontier_rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    items = []
    for r in frontier_rows:
        items.append(
            {
                "candidate_id": r["candidate_id"],
                "sig_bytes": float(r["sig_bytes"]),
                "sign_ms": float(r["sign_ms"]),
                "verify_ms": float(r["verify_ms"]),
                "witness_rows": float(r["witness_rows"]),
                "prove_e2e_ms": float(r["prove_e2e_ms_median"]),
            }
        )
    mins = {k: min(r[k] for r in items) for k in CANDIDATE_AXES}
    maxs = {k: max(r[k] for r in items) for k in CANDIDATE_AXES}

    # equal-weight and performance-first scores
    perf_w = {
        "sig_bytes": 0.10,
        "sign_ms": 0.35,
        "verify_ms": 0.20,
        "witness_rows": 0.15,
        "prove_e2e_ms": 0.20,
    }
    for r in items:
        eq = 0.0
        pf = 0.0
        for k in CANDIDATE_AXES:
            nv = normalize(r[k], mins[k], maxs[k])
            eq += nv
            pf += perf_w[k] * nv
        r["score_equal"] = eq
        r["score_perf"] = pf

    items.sort(key=lambda x: (x["score_perf"], int(x["candidate_id"])))
    out: List[Dict[str, str]] = []
    for rank, r in enumerate(items, start=1):
        out.append(
            {
                "rank_perf": str(rank),
                "candidate_id": str(r["candidate_id"]),
                "score_perf": f"{r['score_perf']:.6f}",
                "score_equal": f"{r['score_equal']:.6f}",
                "sig_bytes": str(int(r["sig_bytes"])),
                "sign_ms": f"{r['sign_ms']:.3f}",
                "verify_ms": f"{r['verify_ms']:.3f}",
                "witness_rows": str(int(r["witness_rows"])),
                "prove_e2e_ms": f"{r['prove_e2e_ms']:.3f}",
            }
        )
    return out


def percent_improve(new: float, old: float) -> float:
    return (old - new) / old * 100.0


def pick_axis_best(frontier_rows: List[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    rows = []
    for r in frontier_rows:
        rows.append(
            {
                "candidate_id": r["candidate_id"],
                "sig_bytes": float(r["sig_bytes"]),
                "sign_ms": float(r["sign_ms"]),
                "verify_ms": float(r["verify_ms"]),
                "witness_rows": float(r["witness_rows"]),
                "prove_e2e_ms": float(r["prove_e2e_ms_median"]),
            }
        )
    out: Dict[str, Dict[str, str]] = {}
    for axis in CANDIDATE_AXES:
        best = min(rows, key=lambda x: (x[axis], int(x["candidate_id"])))
        out[axis] = {
            "candidate_id": str(best["candidate_id"]),
            "value": f"{best[axis]:.3f}" if "ms" in axis else str(int(best[axis])),
        }
    return out


def build_delta_rows(frontier_rows: List[Dict[str, str]], primary_id: str) -> List[Dict[str, str]]:
    idx = {r["candidate_id"]: r for r in frontier_rows}
    if primary_id not in idx:
        return []
    base = idx[primary_id]
    b_sig = float(base["sig_bytes"])
    b_sign = float(base["sign_ms"])
    b_verify = float(base["verify_ms"])
    b_wit = float(base["witness_rows"])
    b_prove = float(base["prove_e2e_ms_median"])

    rows: List[Dict[str, str]] = []
    for r in frontier_rows:
        cid = r["candidate_id"]
        sig = float(r["sig_bytes"])
        sign = float(r["sign_ms"])
        verify = float(r["verify_ms"])
        wit = float(r["witness_rows"])
        prove = float(r["prove_e2e_ms_median"])
        rows.append(
            {
                "candidate_id": cid,
                "sig_bytes": f"{sig:.0f}",
                "sign_ms": f"{sign:.3f}",
                "verify_ms": f"{verify:.3f}",
                "witness_rows": f"{wit:.0f}",
                "prove_e2e_ms": f"{prove:.3f}",
                "delta_sig_pct_vs_primary": f"{(sig - b_sig) / b_sig * 100.0:.2f}",
                "delta_sign_pct_vs_primary": f"{(sign - b_sign) / b_sign * 100.0:.2f}",
                "delta_verify_pct_vs_primary": f"{(verify - b_verify) / b_verify * 100.0:.2f}",
                "delta_witness_pct_vs_primary": f"{(wit - b_wit) / b_wit * 100.0:.2f}",
                "delta_prove_pct_vs_primary": f"{(prove - b_prove) / b_prove * 100.0:.2f}",
            }
        )
    rows.sort(key=lambda x: int(x["candidate_id"]))
    return rows


def build_report(
    rows: List[Dict[str, str]],
    rec_ids: set[str],
    rank_rows: List[Dict[str, str]],
    axis_best: Dict[str, Dict[str, str]],
    delta_rows: List[Dict[str, str]],
    primary_id: str,
    out_md: Path,
    figs: Dict[str, Path],
) -> None:
    out_md.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    lines.append("# 参数组多指标对比与结论（含 192s 基线）")
    lines.append("")
    lines.append("## 1. 对比对象与指标")
    lines.append("- 基线：`sphincs-sha2-192s`、`sphincs-poseidon2-192s`。")
    lines.append("- 候选：M5 Pareto 前沿（6 组）与三组推荐高亮。")
    lines.append("- 指标：`sig_bytes`、`sign_ms`、`verify_ms`、`witness_rows`、`prove_e2e_ms`。")
    lines.append("")
    lines.append("## 2. 全量指标表")
    lines.append("")
    lines.append("| group | candidate_id | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms | source |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---|")
    for r in rows:
        lines.append(
            f"| {r['group']} | {r['candidate_id']} | {r['sig_bytes']} | {r['sign_ms']} | {r['verify_ms']} | {r['witness_rows']} | {r['prove_e2e_ms']} | {r['source']} |"
        )
    lines.append("")
    lines.append("## 3. 候选综合评分（性能优先）")
    lines.append("- 权重：`sig_bytes 0.10 + sign_ms 0.35 + verify_ms 0.20 + witness_rows 0.15 + prove_e2e_ms 0.20`。")
    lines.append("")
    lines.append("| rank_perf | candidate_id | score_perf | score_equal | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rank_rows:
        lines.append(
            f"| {r['rank_perf']} | {r['candidate_id']} | {r['score_perf']} | {r['score_equal']} | {r['sig_bytes']} | {r['sign_ms']} | {r['verify_ms']} | {r['witness_rows']} | {r['prove_e2e_ms']} |"
        )
    lines.append("")
    lines.append("## 4. 各维度最优参数组（候选内）")
    lines.append("| 维度 | 最优 candidate_id | 最优值 |")
    lines.append("|---|---:|---:|")
    lines.append(
        f"| sig_bytes | {axis_best['sig_bytes']['candidate_id']} | {axis_best['sig_bytes']['value']} |"
    )
    lines.append(
        f"| sign_ms | {axis_best['sign_ms']['candidate_id']} | {axis_best['sign_ms']['value']} |"
    )
    lines.append(
        f"| verify_ms | {axis_best['verify_ms']['candidate_id']} | {axis_best['verify_ms']['value']} |"
    )
    lines.append(
        f"| witness_rows | {axis_best['witness_rows']['candidate_id']} | {axis_best['witness_rows']['value']} |"
    )
    lines.append(
        f"| prove_e2e_ms | {axis_best['prove_e2e_ms']['candidate_id']} | {axis_best['prove_e2e_ms']['value']} |"
    )
    lines.append("")
    lines.append(f"## 5. 主推荐组（candidate_id={primary_id}）与其它组全维度差值")
    lines.append("- 说明：`delta_*_pct_vs_primary` 为相对主推荐组百分比，负值代表该维度优于主推荐组。")
    lines.append("")
    lines.append("| candidate_id | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms | delta_sig_pct_vs_primary | delta_sign_pct_vs_primary | delta_verify_pct_vs_primary | delta_witness_pct_vs_primary | delta_prove_pct_vs_primary |")
    lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in delta_rows:
        lines.append(
            f"| {r['candidate_id']} | {r['sig_bytes']} | {r['sign_ms']} | {r['verify_ms']} | {r['witness_rows']} | {r['prove_e2e_ms']} | {r['delta_sig_pct_vs_primary']} | {r['delta_sign_pct_vs_primary']} | {r['delta_verify_pct_vs_primary']} | {r['delta_witness_pct_vs_primary']} | {r['delta_prove_pct_vs_primary']} |"
        )
    lines.append("")

    posei = next((r for r in rows if r["group"] == "poseidon2-192s baseline"), None)
    best = rank_rows[0] if rank_rows else None
    if posei and best:
        best_sign = float(best["sign_ms"])
        best_verify = float(best["verify_ms"])
        base_sign = float(posei["sign_ms"])
        base_verify = float(posei["verify_ms"])
        dsign = percent_improve(best_sign, base_sign)
        dverify = percent_improve(best_verify, base_verify)
        lines.append("## 6. 最终结论与参数组")
        lines.append(
            f"- 主推荐参数组：`candidate_id={best['candidate_id']}`（性能优先综合评分第 1）。"
        )
        lines.append(
            f"- 相比 `poseidon2-192s`：`sign_ms` 改善约 `{dsign:.2f}%`，`verify_ms` 改善约 `{dverify:.2f}%`。"
        )
        lines.append("- 若你更看重最小签名大小：保持 `candidate_id=41`。")
        lines.append("- 若你更看重最小约束规模：保持 `candidate_id=9`。")
    lines.append("")
    lines.append("## 7. 图表清单")
    lines.append(f"- 签名时间对比：`{figs['sign'].name}`")
    lines.append(f"- 验签时间对比：`{figs['verify'].name}`")
    lines.append(f"- Sign vs ZK 散点：`{figs['scatter'].name}`")
    lines.append(f"- 通用三指标归一化柱状图：`{figs['common_multi'].name}`")
    lines.append(f"- 候选五指标热力图：`{figs['candidate_heatmap'].name}`")
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot comparison with multi-metric outputs")
    p.add_argument("--frontier-csv", default="logs/params-pareto-frontier-v1.csv")
    p.add_argument("--final-md", default="logs/params-final-candidates-v1.md")
    p.add_argument("--bench-md", default="logs/benchmark-4way-local.md")
    p.add_argument("--sha2-params-h", default="params/params-sphincs-sha2-192s.h")
    p.add_argument("--poseidon2-params-h", default="params/params-sphincs-poseidon2-192s.h")
    p.add_argument("--out-csv", default="logs/params-compare-with-192s-v1.csv")
    p.add_argument("--out-rank-csv", default="logs/params-candidate-rank-v1.csv")
    p.add_argument("--out-delta-csv", default="logs/params-primary-delta-v1.csv")
    p.add_argument("--out-md", default="logs/params-compare-with-192s-v1.md")
    p.add_argument("--sign-png", default="logs/fig-compare-sign-ms-v1.png")
    p.add_argument("--verify-png", default="logs/fig-compare-verify-ms-v1.png")
    p.add_argument("--scatter-png", default="logs/fig-compare-sign-vs-zk-v1.png")
    p.add_argument("--common-multi-png", default="logs/fig-compare-multimetric-common-v1.png")
    p.add_argument("--candidate-heatmap-png", default="logs/fig-compare-candidate-heatmap-v1.png")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]

    frontier_csv = resolve_path(root, args.frontier_csv)
    final_md = resolve_path(root, args.final_md)
    bench_md = resolve_path(root, args.bench_md)
    sha2_h = resolve_path(root, args.sha2_params_h)
    poseidon2_h = resolve_path(root, args.poseidon2_params_h)
    out_csv = resolve_path(root, args.out_csv)
    out_rank = resolve_path(root, args.out_rank_csv)
    out_delta = resolve_path(root, args.out_delta_csv)
    out_md = resolve_path(root, args.out_md)
    sign_png = resolve_path(root, args.sign_png)
    verify_png = resolve_path(root, args.verify_png)
    scatter_png = resolve_path(root, args.scatter_png)
    common_multi_png = resolve_path(root, args.common_multi_png)
    candidate_heatmap_png = resolve_path(root, args.candidate_heatmap_png)

    frontier_rows = load_csv(frontier_csv)
    rec_ids = set(parse_recommended_ids(read_text(final_md)))
    baseline = parse_benchmark_4way(read_text(bench_md))
    sha2_sig = calc_sig_bytes_from_params_h(sha2_h)
    posei_sig = calc_sig_bytes_from_params_h(poseidon2_h)

    rows: List[Dict[str, str]] = []
    for r in frontier_rows:
        cid = r["candidate_id"]
        rows.append(
            {
                "group": f"cand_{cid}" + (" (rec)" if cid in rec_ids else ""),
                "candidate_id": cid,
                "sig_bytes": r["sig_bytes"],
                "sign_ms": r["sign_ms"],
                "verify_ms": r["verify_ms"],
                "witness_rows": r["witness_rows"],
                "prove_e2e_ms": r["prove_e2e_ms_median"],
                "source": "M5 frontier",
            }
        )

    if "case1_baseline_sign" in baseline:
        b = baseline["case1_baseline_sign"]
        rows.append(
            {
                "group": "sha2-192s baseline",
                "candidate_id": "-",
                "sig_bytes": str(sha2_sig) if sha2_sig is not None else "N/A",
                "sign_ms": f"{b['sign_ms']:.3f}",
                "verify_ms": f"{b['verify_ms']:.3f}",
                "witness_rows": "N/A",
                "prove_e2e_ms": "N/A",
                "source": "benchmark-4way+params",
            }
        )
    if "case2_poseidon2_sign" in baseline:
        b = baseline["case2_poseidon2_sign"]
        rows.append(
            {
                "group": "poseidon2-192s baseline",
                "candidate_id": "-",
                "sig_bytes": str(posei_sig) if posei_sig is not None else "N/A",
                "sign_ms": f"{b['sign_ms']:.3f}",
                "verify_ms": f"{b['verify_ms']:.3f}",
                "witness_rows": "N/A",
                "prove_e2e_ms": "N/A",
                "source": "benchmark-4way+params",
            }
        )

    def row_key(r: Dict[str, str]) -> Tuple[float, str]:
        return float(r["sign_ms"]), r["group"]

    rows.sort(key=row_key)
    save_csv(
        out_csv,
        rows,
        ["group", "candidate_id", "sig_bytes", "sign_ms", "verify_ms", "witness_rows", "prove_e2e_ms", "source"],
    )

    rank_rows = rank_candidates(frontier_rows)
    primary_id = rank_rows[0]["candidate_id"] if rank_rows else ""
    axis_best = pick_axis_best(frontier_rows)
    delta_rows = build_delta_rows(frontier_rows, primary_id)
    save_csv(
        out_rank,
        rank_rows,
        ["rank_perf", "candidate_id", "score_perf", "score_equal", "sig_bytes", "sign_ms", "verify_ms", "witness_rows", "prove_e2e_ms"],
    )
    save_csv(
        out_delta,
        delta_rows,
        [
            "candidate_id",
            "sig_bytes",
            "sign_ms",
            "verify_ms",
            "witness_rows",
            "prove_e2e_ms",
            "delta_sig_pct_vs_primary",
            "delta_sign_pct_vs_primary",
            "delta_verify_pct_vs_primary",
            "delta_witness_pct_vs_primary",
            "delta_prove_pct_vs_primary",
        ],
    )

    labels = [r["group"] for r in rows]
    sign_vals = [float(r["sign_ms"]) for r in rows]
    verify_vals = [float(r["verify_ms"]) for r in rows]
    highlight = {r["group"] for r in rows if r["candidate_id"] in rec_ids}

    plot_bar_log(labels, sign_vals, "Sign Time Comparison (ms, log scale)", "sign_ms", sign_png, highlight)
    plot_bar_log(labels, verify_vals, "Verify Time Comparison (ms, log scale)", "verify_ms", verify_png, highlight)
    plot_scatter(frontier_rows, scatter_png, rec_ids)
    plot_common_multimetric(rows, common_multi_png)
    plot_candidate_heatmap(frontier_rows, rec_ids, candidate_heatmap_png)

    figs = {
        "sign": sign_png,
        "verify": verify_png,
        "scatter": scatter_png,
        "common_multi": common_multi_png,
        "candidate_heatmap": candidate_heatmap_png,
    }
    build_report(rows, rec_ids, rank_rows, axis_best, delta_rows, primary_id, out_md, figs)

    print(
        "[COMPARE] done:",
        f"rows={len(rows)}",
        f"rec_ids={sorted(rec_ids)}",
        f"best_perf={rank_rows[0]['candidate_id'] if rank_rows else 'N/A'}",
        f"csv={out_csv}",
        f"rank_csv={out_rank}",
        f"delta_csv={out_delta}",
        f"md={out_md}",
    )


if __name__ == "__main__":
    main()
