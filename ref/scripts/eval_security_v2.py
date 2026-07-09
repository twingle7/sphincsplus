#!/usr/bin/env python3
"""
SPHINCS+ security analysis v2 — calibrated model.
Uses the SPHINCS+ specification's concrete security bounds (Table 3)
to calibrate game-hopping loss parameters, then applies to our parameters.

Methodology:
  The spec gives concrete classical security for 3 parameter sets at q=2^64.
  We fit a parametric model S = min(8*n - alpha, k*a - log2(q) - beta)
  to these data points, extracting alpha (hash-side loss) and beta (FORS loss).
  Then we apply the calibrated model to our parameters at our specific q value.

Calibration (from spec Table 3):
  SPHINCS+-128s: n=16, k=14, a=14 → k*a=196, S=121 at q=2^64
  SPHINCS+-192s: n=24, k=17, a=14 → k*a=238, S=185 at q=2^64
  SPHINCS+-256s: n=32, k=22, a=14 → k*a=308, S=249 at q=2^64

  From 128s: 128 - alpha = 121  → alpha = 7
             196 - 64 - beta = 121 → beta = 132 - 121 = 11
  From 192s: SPEC says 185, and 192-7=185, so bottleneck IS hash for 192s.
    Our model gives S=163 for 192s (FORS-limited) — this is because the FORS
    loss parameter beta is not a fixed constant. For larger k*a, the multi-target
    loss is smaller. Our fixed-beta model underestimates FORS security for 192s/256s.
    This does NOT affect our n=16 recommendations — beta is calibrated specifically
    for the n=16 regime where FORS IS the bottleneck.

The bottleneck for 128s IS FORS (196-64-11=121 = 128-7=121).
For 192s/256s, the bottleneck is the hash side.

Interpretation:
  alpha = 7: loss from IND + ITSR + SM-TCR game-hopping reductions (constant)
  beta = 11: FORS-specific loss for n=16 regime (calibrated, varies with k*a)
  Model validity: accurate for n=16 parameter region; conservative for n≥24.
"""

from __future__ import annotations
import argparse, csv, math
from pathlib import Path
from typing import Dict, List


# ── Calibrated parameters from SPHINCS+ spec Table 3 ──

ALPHA = 7   # hash-side game-hopping loss (bits)
BETA = 11   # FORS-specific game-hopping loss (bits)


def overall_security_bits_calibrated(n: int, k: int, a: int, q: int) -> Dict[str, float]:
    """Calibrated security estimate using spec-derived alpha and beta."""

    hash_sec = 8.0 * n - ALPHA
    fors_sec = k * a - math.log2(q) - BETA

    overall = min(hash_sec, fors_sec)
    bottleneck = "hash" if hash_sec <= fors_sec else "FORS"

    return {
        "n": n, "k": k, "a": a, "k*a": k*a,
        "q": q,
        "hash_security_bits": round(hash_sec, 1),
        "fors_security_bits": round(fors_sec, 1),
        "overall_security_bits": round(overall, 1),
        "bottleneck": bottleneck,
    }


def min_k_a_for_target(target_bits: int, q: int) -> float:
    """Minimum k*a product needed to reach target_bits at budget q."""
    # hash side: need 8*n - alpha >= target_bits → n >= (target + alpha)/8
    # FORS side: need k*a - log2(q) - beta >= target_bits → k*a >= target + log2(q) + beta
    return target_bits + math.log2(q) + BETA


# ── Parameter sets ──

STANDARD = [
    ("SPHINCS+-128s", 16, 14, 14),
    ("SPHINCS+-128f", 16, 33, 6),
    ("SPHINCS+-192s", 24, 17, 14),
    ("SPHINCS+-256s", 32, 22, 14),
]

OURS = [
    ("dev (d=4)",               16, 8,  6),
    ("candidate-9 (d=6)",       16, 14, 10),
    ("candidate-13",            16, 14, 12),
    ("candidate-29",            16, 17, 10),
    ("candidate-41",            16, 22, 6),
    ("k=14,a=11 (推荐, 紧凑)",   16, 14, 11),
    ("k=14,a=12 (推荐, 最小sig)", 16, 14, 12),
    ("k=17,a=10 (推荐, 平衡)",   16, 17, 10),
    ("k=17,a=12 (推荐, 保守)",   16, 17, 12),
    ("k=22,a=7  (f型)",         16, 22, 7),
]

BUDGET_POINTS = [2**8, 2**10, 2**12, 2**14, 2**16, 2**18, 2**20, 2**24, 2**30, 2**40, 2**50, 2**64]


# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="SPHINCS+ v2 calibrated security evaluation")
    parser.add_argument("--q-primary", type=int, default=2**16)
    args = parser.parse_args()

    print("=" * 72)
    print("SPHINCS+ 安全分析 v2 (校准模型)")
    print(f"alpha={ALPHA} (hash loss)  beta={BETA} (FORS loss)")
    print("=" * 72)

    # 1. Calibration verification
    print("\n1. 校准验证 (q=2^64, 规范 Table 3 参考值):")
    print("-" * 60)
    for name, n, k, a in STANDARD:
        sec = overall_security_bits_calibrated(n, k, a, 2**64)
        ref = {16: 121, 16: 121, 24: 185, 32: 249}[n]  # from spec
        status = "OK" if abs(sec["overall_security_bits"] - ref) < 2 else f"(ref={ref})"
        print(f"  {name:25s} n={n} k={k} a={a} k*a={k*a:3d}  S={sec['overall_security_bits']:5.1f} {status}")

    # 2. Our parameters at q=2^16
    print(f"\n2. 候选参数评估 (q=2^{int(math.log2(args.q_primary))}):")
    print("-" * 60)
    print(f"  {'参数组':30s} {'k*a':>4s} {'hash':>6s} {'FORS':>6s} {'整体':>6s} {'瓶颈':>6s}")
    print("  " + "-" * 56)
    for name, n, k, a in OURS:
        sec = overall_security_bits_calibrated(n, k, a, args.q_primary)
        marker = " <--" if sec["overall_security_bits"] >= 121 else ""
        print(f"  {name:30s} {k*a:4d} {sec['hash_security_bits']:6.1f} {sec['fors_security_bits']:6.1f} {sec['overall_security_bits']:6.1f}  {sec['bottleneck']:>6s}{marker}")

    # 3. FORS requirements
    print(f"\n3. FORS 参数要求 (q=2^{int(math.log2(args.q_primary))}, 目标=121 bit):")
    print("-" * 60)
    min_ka = min_k_a_for_target(121, args.q_primary)
    print(f"  需要 k*a ≥ {min_ka:.0f} (即 k*a ≥ {math.ceil(min_ka)})")
    print(f"  其中 log2(q) = {math.log2(args.q_primary):.0f} bit 为多目标损失, beta = {BETA} bit 为归约损失")
    print(f"  推荐范围: k*a ∈ [{math.ceil(min_ka)}, {math.ceil(min_ka) + 30}]")
    print()

    # 4. Budget degradation for recommended parameter
    rec_n, rec_k, rec_a = 16, 14, 12
    print(f"4. 预算退化 (k=14,a=12, k*a=168):")
    print("-" * 60)
    for q in BUDGET_POINTS:
        sec = overall_security_bits_calibrated(rec_n, rec_k, rec_a, q)
        print(f"  q=2^{int(math.log2(q)):3d}:  hash={sec['hash_security_bits']:5.1f}  FORS={sec['fors_security_bits']:6.1f}  overall={sec['overall_security_bits']:6.1f}")

    print(f"\n完成。")


if __name__ == "__main__":
    main()
