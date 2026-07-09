#!/usr/bin/env python3
"""
Full-AIR STARK cost model for SPHINCS+ Poseidon2 parameter search.

Estimates STARK proving cost from parameters without running the prover.
Based on analytical formulas derived from the trace builder implementation.

Key outputs per candidate:
  - total_permutations: estimated Poseidon2 permutations
  - trace_rows: next power of 2
  - estimated_prove_seconds: projected STARK proving time
  - estimated_proof_bytes: projected proof size

These estimates enable rapid screening of thousands of candidates.
Only top finalists need actual STARK benchmarking.
"""

from __future__ import annotations
import argparse, csv, math
from pathlib import Path
from typing import Dict, List


# ── Poseidon2 per-THASH cost (from trace_builder analysis) ──

def thash_perms(inblocks: int) -> int:
    """Poseidon2 permutations per THASH call.
    For n=16: each rate block is 48 bytes.
    THASH input = domain(1) + pub_seed(n) + addr(32) + inblocks*n
    Each 48-byte rate block → 1 permutation. Plus 1 finalize.
    """
    n = 16  # SPX_N
    input_bytes = 1 + n + 32 + inblocks * n  # total absorbed bytes
    rate = 48  # POSEIDON2_RATE_BYTES
    absorb_perms = (input_bytes + rate - 1) // rate
    return absorb_perms + 1  # +1 for finalize permutation


def estimate_total_permutations(n: int, h: int, d: int, k: int, a: int, w: int) -> float:
    """Estimate total Poseidon2 permutations for one SPHINCS+ verification."""
    logw = int(math.log2(w))
    wots_len1 = 8 * n // logw
    wots_len2 = 3 if w == 16 and n <= 136 else (2 if w == 256 else 0)
    wots_len = wots_len1 + wots_len2
    tree_height = h // d

    # H_msg: absorbs R(n) + PK(2n) + m(n) + domain
    h_msg_perms = thash_perms(4)  # approx: n+2n+n = 4n bytes in 3 blocks

    # FORS: k trees with (1 leaf + a auth) each, plus 1 pk hash
    fors_perms = k * (thash_perms(1) + a * thash_perms(2)) + thash_perms(k)

    # Per HT layer:
    # - WOTS chains: len chains, avg (w-1)/2 steps per chain, each step THASH(inblocks=1)
    avg_chain_steps = (w - 1) / 2.0
    wots_perms_per_layer = wots_len * avg_chain_steps * thash_perms(1)
    # - WOTS pk: THASH(wots_len)
    # - Leaf hash: THASH(wots_len)
    # - Merkle auth: tree_height × THASH(2)
    fixed_perms_per_layer = 2 * thash_perms(wots_len) + tree_height * thash_perms(2)
    ht_perms = d * (wots_perms_per_layer + fixed_perms_per_layer)

    total = h_msg_perms + fors_perms + ht_perms
    return total


def estimate_trace_rows(total_perms: float) -> int:
    """Trace rows = total_perms × 32, padded to next power of 2."""
    rows = int(total_perms * 32)  # PERM_PERIOD = 32 rows per permutation
    return 1 << (rows - 1).bit_length()  # next power of 2


def estimate_prove_seconds(trace_rows: int) -> float:
    """Estimate STARK proving time based on empirical calibration.

    Calibrated from dev params: 131,072 rows → 127 seconds.
    Proving time scales as O(N log N) where N = trace_rows.
    """
    baseline_rows = 131072
    baseline_seconds = 127.0
    # O(N log N) scaling
    ratio = (trace_rows / baseline_rows) * (math.log2(trace_rows) / math.log2(baseline_rows))
    return baseline_seconds * ratio


def estimate_proof_bytes(trace_rows: int) -> int:
    """Estimate proof size based on empirical calibration.

    Calibrated from dev params: 131,072 rows → 95,000 bytes.
    Proof size scales roughly as O(sqrt(N)) for FRI proofs.
    """
    baseline_rows = 131072
    baseline_bytes = 95000
    ratio = math.sqrt(trace_rows / baseline_rows)
    return int(baseline_bytes * ratio)


def evaluate_candidate(
    row: Dict[str, str],
    q: int = 2**16,
    target_bits: int = 121,
) -> Dict[str, str]:
    """Evaluate one parameter candidate: security + cost."""
    n = int(row["n"])
    h = int(row["h"])
    d = int(row["d"])
    k = int(row["k"])
    a = int(row["a"])
    w = int(row["w"])

    # Security check (THF-based, following SPHINCS+ spec methodology)
    # Hash security: 8*n bits (ROM). n=16 provides 128-bit.
    hash_sec = 8 * n
    # FORS: the dominant multi-target constraint
    fors_sec = k * a - math.log2(q * k)
    # HT+WOTS: address-separated via ADRS, security ≈ hash security in ROM
    # (The spec's ITSR property gives tight bounds; no naive union bound needed)
    ht_sec = 8 * n  # ROM with ADRS isolation
    overall_sec = min(hash_sec, fors_sec, ht_sec)
    security_pass = overall_sec >= target_bits and n >= 16

    # Cost estimates
    total_perms = estimate_total_permutations(n, h, d, k, a, w)
    trace_rows = estimate_trace_rows(total_perms)
    prove_s = estimate_prove_seconds(trace_rows)
    proof_b = estimate_proof_bytes(trace_rows)

    out = dict(row)
    out["security_model"] = "THF-based (SPHINCS+ spec)"
    out["q"] = str(q)
    out["target_bits"] = str(target_bits)
    out["hash_sec"] = f"{hash_sec:.1f}"
    out["fors_sec"] = f"{fors_sec:.1f}"
    out["ht_sec"] = f"{ht_sec:.1f}"
    out["overall_sec"] = f"{overall_sec:.1f}"
    out["security_pass"] = "1" if security_pass else "0"
    out["total_perms_est"] = f"{total_perms:.0f}"
    out["trace_rows_est"] = str(trace_rows)
    out["prove_s_est"] = f"{prove_s:.0f}"
    out["proof_b_est"] = str(proof_b)
    return out


def main():
    parser = argparse.ArgumentParser(description="Full-AIR cost model for parameter search")
    parser.add_argument("--input-csv", default="logs/params-search-struct-pass-v1.csv")
    parser.add_argument("--output-csv", default="logs/params-cost-model-v2.csv")
    parser.add_argument("--q", type=int, default=2**16)
    parser.add_argument("--target-bits", type=int, default=121)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    in_csv = root / args.input_csv
    out_csv = root / args.output_csv

    rows = []
    with open(in_csv, "r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    evaluated = [evaluate_candidate(r, args.q, args.target_bits) for r in rows]
    passed = [r for r in evaluated if r["security_pass"] == "1"]

    # Sort by proving time
    passed.sort(key=lambda r: int(r["prove_s_est"]))

    if passed:
        fieldnames = list(passed[0].keys())
    else:
        fieldnames = list(evaluated[0].keys()) if evaluated else []

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(passed)

    print(f"[cost-model] total={len(evaluated)} security_pass={len(passed)}")
    print(f"[cost-model] saved to {out_csv}")
    if passed:
        top = passed[0]
        print(f"[cost-model] fastest candidate: id={top.get('candidate_id','?')} "
              f"n={top['n']} d={top['d']} k={top['k']} a={top['a']} "
              f"perms={top['total_perms_est']} rows={top['trace_rows_est']} "
              f"prove~{top['prove_s_est']}s proof~{top['proof_b_est']}B")


if __name__ == "__main__":
    main()
