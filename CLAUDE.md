# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment

Development happens on WSL or MinGW64. All paths assume `ref/` as the working directory:

```bash
cd /d/Desktop/sphincsplus/ref
export PARAMS=sphincs-poseidon2-128f-small  # dev params
export THASH=simple
export CC=gcc
```

For benchmark/safe params use `PARAMS=sphincs-poseidon2-192s` or candidate 9 from param search.

## Build

### C reference implementation

The C code builds via GNU Make. The two critical variables are:

| Variable | Purpose |
|----------|---------|
| `PARAMS` | Selects the parameter set, e.g. `sphincs-poseidon2-192s`. Resolves to `params/params-$(PARAMS).h`. |
| `THASH` | Selects the tweakable-hash variant: `simple` or `robust`. |
| `EXTRA_CFLAGS` | Optional flags. For the final Fischlin path, always include `-DSPX_P2_USE_RUST_STARK`. |

The Makefile auto-detects the hash backend from `PARAMS` and sets the corresponding C defines (`SPX_BACKEND_SHAKE`, `SPX_BACKEND_HARAKA`, `SPX_BACKEND_SHA2`, `SPX_BACKEND_POSEIDON2`). It also conditionally compiles `stark/` and `show/` sources when the Poseidon2 backend is detected.

Build the KAT (Known Answer Test) binary:
```bash
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc
```

Build all tests and benchmarks:
```bash
make all PARAMS=$PARAMS THASH=$THASH CC=$CC
```

### Rust STARK backend

```bash
cd stark-rs && cargo build --release && cd ..
```

Then build C tests linked against the Rust static library:
```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/<target>
```

The Makefile auto-links `stark-rs/target/release/libsphincsplus_stark_rs.a` when `SPX_P2_USE_RUST_STARK` is set.

## Testing

### Run a single test

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC test/<name>
./test/<name>
```

Or use the `.exec` suffix for a build-and-run shorthand:
```bash
make test/<name>.exec PARAMS=$PARAMS THASH=$THASH
```

### Basic SPHINCS+ correctness

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC test/spx test/fors
```

### Full strict regression (recommended primary gate)

```bash
bash scripts/run_strict_regression.sh
```

This builds the Rust backend, then compiles and runs the core correctness/security test suite.

### Additional strict-core negative-case test

Not covered by the regression script, important for paper-level validation:

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_stark_strict_core_enforcement
./test/poseidon2_stark_strict_core_enforcement
```

### Cross-backend comparison

```bash
make PARAMS=sphincs-sha2-192s THASH=simple CC=$CC test/hash_profile_verify
./test/hash_profile_verify

make PARAMS=sphincs-poseidon2-192s THASH=simple CC=$CC test/hash_profile_verify
./test/hash_profile_verify
```

### Benchmarking

Protocol benchmarks:
```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_protocol_benchmark
```

Batch collection scripts:
```bash
RUNS=30 bash scripts/collect_benchmark_v2.sh
RUNS=20 bash scripts/collect_benchmark_4way.sh
```

## High-Level Architecture

### Repository purpose

This is a fork of the [SPHINCS+](https://sphincs.org/) post-quantum signature scheme reference implementation, extended with:

1. **Poseidon2 hash function** over the Goldilocks prime field (`p = 2^64 - 2^32 + 1`) — replacing SHA2/SHAKE as the tweakable hash backend.
2. **Fischlin blind-signature protocol** — a `Commit → Issue → FinalizeCredential → Show → Verify` flow that lets a holder prove knowledge of a valid issuer signature without revealing the full signature.
3. **STARK-based zero-knowledge proofs** — the Show step generates a STARK proof (via Winterfell) that the holder knows a valid opening. The Verifier checks the STARK proof against public statements only.

### Directory layout

```
ref/
├── *.c, *.h           # Core SPHINCS+ C reference implementation (sign, wots, fors, merkle, utils)
├── hash_*.c           # Hash backends: sha2, shake, haraka, poseidon2
├── thash_*.c          # Tweakable hash instantiations (per-backend × simple/robust)
├── poseidon2.[ch]     # Poseidon2 permutation over Goldilocks field (t=12, capacity=6, rate=6)
├── hash_poseidon2_adapter.[ch]  # Adapter layer mapping SPHINCS+ hash calls to Poseidon2
├── hash_profile.[ch]  # Verify-path hash-call profiling infrastructure
├── params/            # Parameter header files (one per named instance)
├── show/              # Final Fischlin protocol layer
│   ├── show_poseidon2.[ch]    # Show proof generation / verification (single-step)
│   └── protocol_poseidon2.[ch] # Multi-party protocol flow (issue request, respond, finalize)
├── stark/             # C-side witness builder, AIR evaluators, FFI, format, stats
│   ├── witness_builder.c      # Builds execution trace from protocol witness
│   ├── air_*.c                # AIR constraint evaluators (perm, sponge, hashcall, verify)
│   ├── pi_f_format*.c         # Binary proof format encoding (pi_F v1/v2)
│   ├── ffi.[ch]               # Public FFI: generate/verify STARK proofs (calls Rust)
│   ├── prover_v1.c            # C fallback prover (placeholder; real proving via Rust)
│   ├── verifier_v1.c          # C fallback verifier (placeholder)
│   ├── relation_migration*.c  # Statement/witness relation validation
│   └── stats.[ch]             # Proof-size and witness statistics collection
├── stark-rs/          # Rust STARK backend crate (sphincsplus-stark-rs)
│   ├── Cargo.toml              # Depends on winterfell 0.13.1; builds staticlib + rlib
│   └── src/
│       ├── lib.rs              # Main STARK AIR definition, Winterfell prover/verifier, C FFI exports
│       ├── thash_poseidon2_exact.rs  # Exact Poseidon2 permutation trace for Thash
│       ├── thash_sha2_exact.rs       # Exact SHA2-256 trace for cross-backend comparison
│       ├── thash_sha2_f_exact.rs     # Exact SHA2-256 compression-function trace
│       └── thash_bench.rs           # Benchmarking utilities
├── test/              # Test programs (one .c per test target)
├── scripts/           # Python + Bash scripts for param search, benchmarking, analysis
├── logs/              # Runtime logs (gitignored except README)
└── final-results-v1/  # Delivered results snapshot (gitignored)
```

`_archive/` at the repo root contains paper materials, historical logs, staged results, and non-mainline code. Not needed for active development.

### Protocol architecture: Fischlin strict chain

The multi-party blind-signature protocol runs in four phases:

1. **Prepare + Issue request** (`spx_p2_prepare_issue_request`) — Holder blinds message `m` with randomness `r`, producing a commitment `com` sent to the Issuer.
2. **Issue / respond** (`spx_p2_issue_sign` / `spx_p2_issue_respond`) — Issuer signs the blinded commitment with their SPHINCS+ secret key, producing `sigma_blind`.
3. **Finalize credential** (`spx_p2_finalize_credential`) — Holder unblinds the signature and builds the internal credential (includes full witness trace for STARK proving).
4. **Show** (`spx_p2_show_prove` / `spx_p2_show_verify`) — Holder generates a STARK proof `pi_f` that they know a valid opening. Verifier checks the proof against only public statements (`pk_sig`, `pk_E`, `com`, `m_pub`, `public_ctx`, `sigma_C`).

There are two statement modes:
- **Statement-unbound** (legacy): verifier sees `pk_sig` and proof.
- **Statement-bound** (current recommended): verifier additionally sees `pk_E`, `m_pub` — binding the proof to explicit public statements.

### Rust STARK backend (Winterfell)

The Rust crate `sphincsplus-stark-rs` implements TWO AIRs:

**Legacy mixed-proof AIR** (in `lib.rs`): The original `WorkAir` that proves commitment opening and ciphertext construction, but delegates SPHINCS+ signature verification to external C guards. Trace: 256 rows × 255 columns.

**Full-AIR** (in `air_engine.rs` + `trace_builder.rs`): Self-contained proof of the ENTIRE SPHINCS+ verification trace. No external guards needed.
- Trace: 131,072 rows × 64 columns (dev params), 3,686 Poseidon2 permutations
- Approach: trace builder walks through `crypto_sign_verify`, pre-computes expected next state using `poseidon2_round`, stores in trace columns 16..27. AIR checks `nxt == expected` via simple equality constraints.
- 16 constraints: 6 rate lanes + round counter + perm index + call type + pad flag
- Proof: ~95 KB, ~127 seconds (dev params)
- C FFI exports for full-AIR:
  - `spx_p2_rust_generate_pi_f_full_air` — Generate STARK proof
  - `spx_p2_rust_verify_pi_f_full_air` — Verify STARK proof
  - `spx_p2_rust_get_abi_version_full_air` — ABI version check
- C FFI exports (legacy):
  - `spx_p2_rust_generate_pi_f_v1` / `verify_pi_f_v1` — mixed-proof path (deprecated)
  - `spx_p2_rust_validate_strict_relation_inputs_v1` — external guard (not needed by full-AIR)
  - `spx_p2_rust_validate_strict_witness_relation_v1` — external guard (not needed by full-AIR)

The C side calls the Rust FFI through `stark/ffi.c`. There are now TWO paths:
- `spx_p2_ffi_generate_pi_f` / `spx_p2_ffi_verify_pi_f` — legacy mixed-proof
- `spx_p2_ffi_generate_pi_f_full_air` / `spx_p2_ffi_verify_pi_f_full_air` — full-AIR (recommended)

### Key naming conventions

- `spx_p2_*` prefix — all Poseidon2/Fischlin/STARK extensions (distinct from upstream SPHINCS+ `crypto_sign_*`).
- Files with `_v1` suffix — implementation artifacts; the public API headers (`ffi.h`, `show_poseidon2.h`, `protocol_poseidon2.h`) are unversioned and are the only canonical entry points.
- `_strict_public` and `_statement_bound` suffixes in Make targets — compatibility aliases sharing the same test source.
- The `SPX_NAMESPACE(s)` macro wraps all public symbols for link-time namespacing.

### Parameter sets

The primary development parameter set is `sphincs-poseidon2-192s`:
- `n = 24` (192-bit security)
- `h = 63`, `d = 7` (hypertree)
- `log(t) = 14`, `k = 17` (FORS)
- `w = 16` (WOTS+ Winternitz)
- Poseidon2: `t = 12` state words, `capacity = 6`, `rate = 6`, Goldilocks field, `RF = 8`, `RP = 22`, `x^7` S-box

Other parameter files exist for SHA2, SHAKE, and Haraka backends across security levels 128/192/256 but are not the active development focus.

### Typical workflow for verifying a change

1. Edit C or Rust source.
2. If Rust changed: `cd stark-rs && cargo build --release && cd ..`
3. Run strict regression: `bash scripts/run_strict_regression.sh`
4. Run strict-core negative test: `make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_strict_core_enforcement && ./test/poseidon2_stark_strict_core_enforcement`
