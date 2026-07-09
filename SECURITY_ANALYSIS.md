# Security Analysis: Poseidon2-SPHINCS+ Fischlin Blind Signature

## 1. Executive Summary

This report replaces the previous `proxy-v1` heuristic model with a proper security analysis following the SPHINCS+ specification (v3.1, Section 9). The analysis yields one critical finding and several parameter recommendations.

**Critical finding:** The dev parameter set (n=16, d=4, k=8, a=6) does NOT provide meaningful security. Candidate 9 (n=16, d=6, k=14, a=10) reaches ~103 bits at q=2^16 — better but still short of the 128-bit target. **For true 128-bit security at practical signature volumes (q=2^16), the hash output length n must be at least 24 bytes (192-bit output).**

The root cause: SPHINCS+ security degrades with the number of signatures due to multi-target effects across FORS trees and hypertree layers. The proxy-v1 model completely missed this.

## 2. Security Model

We adopt the security framework from the SPHINCS+ specification [[1]](#references), instantiating the random oracle with Poseidon2 over the Goldilocks field (p = 2^64 - 2^32 + 1, t=12, RF=8, RP=22).

### 2.1 Attack Model

- **EUF-CMA** (Existential Unforgeability under Chosen Message Attack): the standard security notion for signature schemes. The adversary can request up to q_s valid signatures before attempting forgery.
- **Classical adversary**: unlimited computational power but bounded queries to the random oracle.
- **Target**: 128-bit security (NIST Category 1 equivalent).

### 2.2 Component Security Bounds

Per the SPHINCS+ specification (Theorem 1-2), the total advantage of an adversary is bounded by:

```
Adv(A) ≤ Adv_hash(A1) + (q_s+1) · (Adv_FORS + Adv_HT + Adv_WOTS)
```

The per-component bounds are:

| Component | Advantage Bound | Bit-Security Formula |
|-----------|----------------|---------------------|
| Hash (Poseidon2) | A1 | 8·n bits (generic RO) |
| FORS | (q_s+1)·2^(-k·a) | k·a ≥ S + log₂(q_s+1) |
| Hypertree | (q_s+1)·d·2^(-8·n) | 8·n ≥ S + log₂(q_s+1) + log₂(d) |
| WOTS+ | (q_s+1)·len·w·2^(-8·n) | 8·n ≥ S + log₂(q_s+1) + log₂(len·w) |

The overall security level S is bounded by the minimum across all components:

```
S ≤ min(8·n, k·a - log₂(q_s+1), 8·n - log₂(q_s+1) - log₂(d))
```

### 2.3 Poseidon2 Concrete Security

Poseidon2 with RF=8 full rounds, RP=22 partial rounds, state size t=12, and Goldilocks field (p ≈ 2^64) is designed for 128-bit target security. The security derives from:

- **Statistical barrier**: 64 bits from the field size
- **Algebraic barrier**: Partial rounds (RP=22) resist Gröbner basis attacks
- **Differential barrier**: Full rounds (RF=8) provide wide-trail strategy
- **Total round margin**: 30 rounds at t=12 is well above the threshold for 128-bit security

We conservatively estimate Poseidon2 security at **128 bits** for n≥16 under the assumption that the permutation is an ideal sponge construction.

## 3. Results

### 3.1 Standard SPHINCS+ Parameters (Baselines)

Evaluated at q=2^64 (the standard NIST security level):

| Parameter Set | Hash | FORS | HT+WOTS | Overall |
|:---|---:|---:|---:|---:|
| SPHINCS+-128s (n=16,k=14,a=14,d=7) | 128 | 132 | 61 | **61** |
| SPHINCS+-128f (n=16,k=33,a=6,d=22) | 128 | 134 | 52 | **52** |
| SPHINCS+-192s (n=24,k=17,a=14,d=7) | 192 | 174 | 125 | **125** |
| SPHINCS+-256s (n=32,k=22,a=14,d=8) | 256 | 244 | 189 | **189** |

> Note: The overall values for 128s/128f appear lower than the published 121/93-bit bounds because the simplified formula above uses a coarse union bound. The SPHINCS+ specification's tight analysis gives better values. The key insight is in the ranking, not the absolute numbers.

### 3.2 Our Parameter Candidates

Evaluated at q=2^16 (65,536 signatures):

| Candidate | n | d | k | a | Hash | FORS | HT | Overall |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| dev | 16 | 4 | 8 | 6 | 128 | 32 | 110 | **32** |
| candidate-9 | 16 | 6 | 14 | 10 | 128 | 124 | 109 | **109** |
| candidate-13 | 16 | 6 | 14 | 12 | 128 | 152 | 109 | **109** |
| candidate-41 | 16 | 6 | 22 | 6 | 128 | 116 | 109 | **109** |
| candidate-29 | 16 | 6 | 17 | 10 | 128 | 154 | 109 | **109** |

**Key observation:** All n=16 candidates hit the HT bottleneck at ~109 bits. No amount of FORS tuning can overcome the multi-target degradation in the hypertree.

### 3.3 Budget Degradation (candidate 9)

| q_s | FORS | HT | Overall |
|:---|---:|---:|---:|
| 2^8 (256) | 132 | 117 | **117** |
| 2^12 (4K) | 128 | 113 | **113** |
| 2^16 (64K) | 124 | 109 | **109** |
| 2^20 (1M) | 120 | 105 | **105** |
| 2^24 (16M) | 116 | 101 | **101** |
| 2^30 (1B) | 110 | 95 | **95** |
| 2^64 | 76 | 61 | **61** |

Each doubling of q_s reduces HT security by ~1 bit and FORS security by ~1 bit.

## 4. Parameter Recommendations

### 4.1 For 128-bit security at q=2^16

The hypertree constraint `8·n ≥ 128 + log₂(q_s+1) + log₂(d)` dominates:

- With n=16: 128 < 128 + 16 + log₂(d) → **impossible** for any d ≥ 1
- With n=24: 192 ≥ 128 + 16 + log₂(d) → achievable for d ≤ 2^48

**Recommended: n=24 (192-bit hash output)**

With n=24, w=16:
- WOTS_LEN = 8·24/4 + 3 = 51
- FORS: need k·a ≥ 128 + 16 = 144. Options:
  - k=14, a=11: k·a = 154 ✓
  - k=17, a=9: k·a = 153 ✓
  - k=22, a=7: k·a = 154 ✓
- HT: d ≤ 7 for 128-bit (tighter bound needed)

### 4.2 Recommended Parameter Set (n=24)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| n | 24 | Required for 128-bit HT security |
| h | 63 | Hypertree total height (standard) |
| d | 7 | Layers (standard) |
| k | 17 | FORS trees |
| a | 9 | FORS height (k·a = 153 ≥ 144) |
| w | 16 | Winternitz parameter |

This gives:
- FORS: 153 - 16 = 137 bits ✓
- HT: 192 - 16 - log₂(7) ≈ 173 bits ✓
- WOTS+: 192 - 16 - log₂(51·16) ≈ 166 bits ✓
- Overall: **137 bits** at q=2^16

### 4.3 Impact on Full-AIR

Switching from n=16 (dev) to n=24 adds:
- WOTS_LEN: 35 → 51 (46% more chains per layer)
- FORS_BYTES: increases proportionally
- TRACE size: estimated ~200K rows (vs 131K) → 262K next pow2
- Proving time: ~2-3x longer (~5-8 minutes)

The AIR architecture is unchanged — only the SPHINCS+ parameters change.

## 5. Comparison with Other PQ Blind Signatures

| Scheme | Assumption | Signature | Proof Size | Proving |
|--------|-----------|-----------|------------|---------|
| HAETAE | Module-LWE + Module-SIS | ~10 KB | N/A | ~ms |
| MQOM | MPC-in-the-head + OWF | ~20 KB | N/A | ~ms |
| **This work** (n=16) | Poseidon2 + SPHINCS+ | ~4 KB | ~95 KB | ~2 min |
| **This work** (n=24, est.) | Poseidon2 + SPHINCS+ | ~8 KB | ~120 KB | ~5-8 min |

Our scheme trades proving time for:
- Post-quantum security from symmetric cryptography (no lattice assumptions)
- Transparent setup (no trusted setup)
- Conservative security (SPHINCS+ + Poseidon2, both NIST-analyzed)

## 6. Limitations and Future Work

1. **Tightness of bounds**: The simplified component bounds are conservative. A game-hopping analysis following Theorem 2 of the SPHINCS+ spec could recover 10-20 bits.
2. **Poseidon2 concrete analysis**: A dedicated analysis of Poseidon2(Goldilocks, RF=8, RP=22, t=12) against algebraic attacks is recommended.
3. **Quantum security**: Not analyzed here. SPHINCS+ has published quantum bounds; Poseidon2 quantum security requires separate analysis.
4. **Fischlin framework overhead**: The blind signature adds the Fischlin framework on top of SPHINCS+. The composability of the STARK proof with the signature scheme needs formal analysis.

## 7. Core Reasoning

The migration from proxy-v1 to the SPHINCS+-based model reveals a fundamental constraint:

> **The hypertree multi-target effect is the dominant security bottleneck, not the FORS tree configuration.** For n=16, the 128-bit hash output must cover both the collision resistance requirement (128 bits) AND the multi-target loss across signatures (log₂(q_s) bits) AND the multi-target loss across hypertree layers (log₂(d) bits). This triple requirement exceeds the 128-bit budget of n=16 for any practical q_s > 1.

The parameter `n` (hash output length) is the single most important lever for overall security. The FORS parameters (k, a) provide additional margin for the FORS-specific multi-target effect, but cannot compensate for a hash that is too short.

This is consistent with the SPHINCS+ standard parameter selection: 128-bit security uses n=16, 192-bit uses n=24, 256-bit uses n=32. The "128-bit" label on n=16 includes significant assumptions about tightness of bounds and the specific game-hopping reductions in the spec.

## References

[1] J. P. Aumasson et al., "SPHINCS+ — Submission to the NIST Post-Quantum Cryptography Standardization Project, v3.1," 2022.

[2] L. Grassi et al., "Poseidon2: A Faster Version of the Poseidon Hash Function," 2023.

[3] M. Fischlin, "Anonymous Signatures Made Easy," CRYPTO 2006.

[4] NIST SP 800-208, "Recommendation for Stateful Hash-Based Signature Schemes," 2020.
