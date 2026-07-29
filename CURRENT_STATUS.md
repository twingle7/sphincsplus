# Current Status: Poseidon2+SPHINCS+ Fischlin Blind Signature with Full STARK AIR

## Architecture

```
Holder                              Issuer                     Verifier
  │                                    │                          │
  │  ── c = Com(m; r) ────────────────►│                          │
  │                                    │                          │
  │  ◄── sigma_blind = Sign(sk, c) ───│                          │
  │                                    │                          │
  │  Finalize: store credential         │                          │
  │    sigma_com = sigma_blind (verbatim)│                        │
  │    (no mathematical unblinding)     │                          │
  │                                    │                          │
  │  sigma_C = Bind(pk_E, c||sigma_com; │                          │
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

1. **All 2,091 Poseidon2 permutations** are executed correctly (full rounds: x^7 S-box + MDS, internal rounds: x^7 on lane 0 + diagonal MDS)
2. **Round counter** increments correctly within each permutation and resets at boundaries
3. **Permutation index** stays constant within permutations and increments at boundaries
4. **Call type** stays constant within each permutation

The trace builder (`trace_builder.rs`) walks through the complete SPHINCS+ verification algorithm (H_msg → FORS → HT layers → Merkle paths), recording every intermediate state. The AIR constrains this trace using pre-computed expected next states (stored in trace columns 16..27).

Because the trace IS the SPHINCS+ verification, proving the trace is correct = proving the verification passed.

## Key Metrics (128-bit Parameters)

| Metric | Value |
|--------|-------|
| Parameters | n=16, h=63, d=7, k=10, a=12, w=16 |
| Trace size | 23,861 rows × 64 columns (next pow2: 32,768) |
| Poseidon2 calls | 2,091 |
| Constraints | 53 (16 core + 12 absorption + 12 state carry + 8 THASH absorb + 4 boolean + 3 copies) |
| Proof size | ~85 KB (blowup=16, queries=27, ~108-bit conjectured security) |
| Proving time | ~37 seconds (WSL, blowup=16) |
| Verification time | ~4 ms |
| Memory peak | ~4.6 GB |
| Column usage | 58 / 64 (91%) |

## What Is NOT Proven (Current Limitations)

- ~~**Input dataflow**~~ → **FIXED 2026-07-22** (THASH absorb[0..5] bound to domain+pub_seed+addr, constraints 45-52)
- ~~**Sponge state carry**~~ → **FIXED 2026-07-21**
- ~~**m_pub vs com semantic gap**~~ → **FIXED 2026-07-21**
- ~~**pk_root not asserted in AIR**~~ → **FIXED 2026-07-22** (boundary assertion at root_row)
- **Call type sequencing**: The sequence of call types is not yet AIR-constrained (indirectly covered by root assertion)
- **Hardcoded N=16**: n=16 is sufficient for 128-bit target; parameterization for n=24 deferred
- **Formal security**: No UC proof, no side-channel resistance

**Now proven** (since 2026-07-21):
- ✅ All 12 Poseidon2 state lanes constrained (full + internal rounds)
- ✅ pk_root bound to actual public key pk[N..2*N] (not self-referential; cross-check ensures trace builder correctness)
- ✅ Trace builder bugs resolved (2026-07-29): FORS interleaved layout, message_to_indices, bytes_to_u64 BE, chain_lengths checksum
- ✅ Commit and Sigma.C computations are endogenous (in-trace, CallType::Commit + CallType::SigmaC)
- ✅ Commit output bound to public input `com` via boundary assertions at row 30
- ✅ OOM resolved: blowup_factor 32→16, num_queries 32→27 (~4x memory reduction)
- ✅ Public input context binding: ctx_hash = Blake3(pk ‖ pk_e ‖ com ‖ m_pub ‖ public_ctx ‖ sigma_c) in proof header (296 bytes), verified on verification
- ✅ C-level signature guard: spx_p2_verify_com rejects invalid sigma_com before Rust prover
- ✅ Proof format: magic "PFP2" + version=2 for format detection
- ✅ **Sponge state continuity**: Rust trace builder now carries Poseidon2 sponge state across permutation blocks within each hash operation, matching C's poseidon2_inc_* semantics. AIR enforces continuity via carries_from_prev/carries_to_next flags and init_state columns (cols 39-52)
- ✅ **Padding fixed**: Extra empty padding block removed; now matches C's pad10*1 exactly
- ✅ **Domain tags corrected**: THASH_F=0x11, THASH_H=0x12, THASH_TL=0x13 now match C layer
- ✅ **m_pub→com_output**: hash_message now signs the commitment (com_output), matching C's crypto_sign_verify(com, ...)
- ✅ All 9 strict regression tests passing (7.7s prove, 5.6ms verify, ~71KB proof)

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
