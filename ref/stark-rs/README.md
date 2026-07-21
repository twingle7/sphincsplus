# stark-rs — Rust STARK Backend

Full-AIR STARK prover/verifier for SPHINCS+ Poseidon2 Fischlin blind signatures.

## Architecture

Two AIRs coexist:

| AIR | File | Status |
|-----|------|--------|
| **Full-AIR** | `air_engine.rs` + `trace_builder.rs` | ✅ Active — self-contained, no external C guards |
| Legacy mixed-proof | `lib.rs` (WorkAir) | ⚠️ Compat — delegates sig verification to C guards |

## Full-AIR

- Proves ALL Poseidon2 permutations in the SPHINCS+ verification trace
- 23,861 rows × 64 columns (128-bit params), 2,091 permutations
- Pre-computed expected-next-state approach (trace cols 16..27) + sponge continuity + input binding
- 53 constraints: rate/capacity + round/perm/call/pad + carry + THASH absorb + root assertion
- Proof: ~85 KB, ~37 seconds (128-bit, blowup=16)
- C FFI: `spx_p2_rust_generate_pi_f_full_air` / `verify_pi_f_full_air`

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test air_engine::tests::test_e2e -- --nocapture
cargo test air_engine::tests::test_tamper -- --nocapture
cargo test air_engine::tests::test_ffi -- --nocapture
```

## Dependencies

- winterfell 0.13.1 (STARK proving system)
- Goldilocks field (p = 2^64 - 2^32 + 1)
