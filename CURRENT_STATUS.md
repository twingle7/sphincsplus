# Current Status: Poseidon2+SPHINCS+ Fischlin Blind Signature with Full STARK AIR

## Architecture

```
Holder                              Issuer                     Verifier
  │                                    │                          │
  │  ── c = Com(m; r) ────────────────►│                          │
  │                                    │                          │
  │  ◄── sigma_blind = Sign(sk, c) ───│                          │
  │                                    │                          │
  │  Unblind: sigma = Unblind(         │                          │
  │    sigma_blind, omega2)            │                          │
  │                                    │                          │
  │  sigma_C = Enc(pk_E, c||sigma;     │                          │
  │    omega2)                         │                          │
  │                                    │                          │
  │  pi_F = FullAIR.Prove(pk_sig,      │                          │
  │    pk_E, c, m_pub, sigma_C,        │                          │
  │    w={sigma, m, r, omega2})        │                          │
  │                                    │                          │
  │  ── Sigma = (sigma_C, pi_F) ───────┼─────────────────────────►│
  │                                    │                          │
  │                                    │     FullAIR.Verify(      │
  │                                    │       pk_sig, pk_E,      │
  │                                    │       m_pub, sigma_C,    │
  │                                    │       pi_F) → {0,1}      │
```

## What The STARK Proof Proves

The Full-AIR (`air_engine.rs`) proves the ENTIRE SPHINCS+ `crypto_sign_verify` execution trace without external guards:

1. **All 3,686 Poseidon2 permutations** are executed correctly (full rounds: x^7 S-box + MDS, internal rounds: x^7 on lane 0 + diagonal MDS)
2. **Round counter** increments correctly within each permutation and resets at boundaries
3. **Permutation index** stays constant within permutations and increments at boundaries
4. **Call type** stays constant within each permutation

The trace builder (`trace_builder.rs`) walks through the complete SPHINCS+ verification algorithm (H_msg → FORS → HT layers → Merkle paths), recording every intermediate state. The AIR constrains this trace using pre-computed expected next states (stored in trace columns 16..27).

Because the trace IS the SPHINCS+ verification, proving the trace is correct = proving the verification passed.

## Key Metrics (Dev Parameters)

| Metric | Value |
|--------|-------|
| Parameters | n=16, h=40, d=4, k=8, a=6, w=16 |
| Trace size | 131,072 rows × 64 columns |
| Poseidon2 permutations | 3,686 |
| Constraints | 16 |
| Proof size | ~95 KB |
| Proving time | ~127 seconds |
| Verification time | < 1 second |
| Column usage | 64 / 255 (25%) |

## What Is NOT Proven (Current Limitations)

- **Input dataflow**: The AIR proves permutations are correct but does not yet constrain that the INPUT to each permutation is correct (right addresses, domain tags, message blocks)
- **Root matching**: Final HT root == pk_root is not yet asserted in the AIR
- **sigma_C construction**: Encryption correctness is not yet constrained
- **Formal security**: No UC proof, no side-channel resistance
- **Benchmark parameters**: Current measurements are on dev parameters only

## Comparison Path

To compare with other PQ blind signature schemes (HAETAE, MQOM, etc.):

1. Switch to benchmark parameters (candidate 9: n=16, h=60, d=6) → ~262K row trace
2. Profile prove/verify time and proof size
3. Add input dataflow constraints (address, domain tags) for completeness
4. Publish all numbers

## Files

| File | Purpose |
|------|---------|
| `ref/stark-rs/src/air_engine.rs` | Full-AIR definition + FFI exports |
| `ref/stark-rs/src/trace_builder.rs` | SPHINCS+ verification port + trace builder |
| `ref/stark-rs/src/lib.rs` | Legacy mixed-proof AIR (backward compat) |
| `ref/stark-rs/src/thash_poseidon2_exact.rs` | Exact Poseidon2 permutation constants |
| `ref/stark/ffi.h` / `ffi.c` | C FFI (both legacy and full-AIR paths) |
| `ref/params/params-sphincs-poseidon2-128f-small.h` | Dev parameters |
| `ref/show/` | Fischlin protocol / show layer |
