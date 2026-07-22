# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Companion documents

These files at the repo root provide critical context — read them when starting new work:

| File | Purpose |
|------|---------|
| `MAINLINE.md` | Which files are mainline vs archived; where to start reading |
| `CURRENT_STATUS.md` | Architecture diagram, what the STARK proof proves, current limitations, key metrics |
| `SECURITY_ANALYSIS.md` | Modular THF security methodology; why Poseidon2 satisfies SPHINCS+ security bounds |
| `PARAMETER_SEARCH_PLAN.md` | Cost-model-based parameter search plan (replaces old full-benchmark pipeline) |
| `ref/TESTING.md` | Canonical test catalog: correctness, format/FFI, benchmark, and param-search scripts |
| `ref/README.md` | Canonical public API entry points (`show/`, `stark/`, `stark-rs/`) |

`_archive/` at the repo root holds paper materials, historical logs, staged results, and non-mainline code — read `_archive/README.md` if you need history, but do not modify archived files during active development.

## Environment

Development happens on WSL or MinGW64. All paths assume `ref/` as the working directory:

```bash
cd /d/Desktop/sphincsplus/ref
export PARAMS=sphincs-poseidon2-128f-small  # dev params (n=16, h=40, d=4)
export THASH=simple
export CC=gcc
```

For benchmark/safe params use `PARAMS=sphincs-poseidon2-192s` (n=24) or candidate 9 from param search.

Note: some scripts (e.g., `run_strict_regression.sh`) use both `CC` and `CC_BIN` variables. Set both to the same compiler unless cross-compiling.

## Build

### C reference implementation

The C code builds via GNU Make. The critical variables are:

| Variable | Purpose |
|----------|---------|
| `PARAMS` | Selects the parameter set, e.g. `sphincs-poseidon2-192s`. Resolves to `params/params-$(PARAMS).h`. |
| `THASH` | Selects the tweakable-hash variant: `simple` or `robust`. |
| `EXTRA_CFLAGS` | Optional flags. For the final Fischlin path, always include `-DSPX_P2_USE_RUST_STARK`. |

The Makefile auto-detects the hash backend from `PARAMS` and sets the corresponding C defines (`SPX_BACKEND_SHAKE`, `SPX_BACKEND_HARAKA`, `SPX_BACKEND_SHA2`, `SPX_BACKEND_POSEIDON2`). It also conditionally compiles `stark/` and `show/` sources when the Poseidon2 backend is detected.

Key Makefile targets:

| Target | Description |
|--------|-------------|
| `default` (`PQCgenKAT_sign`) | Build KAT binary |
| `all` | Build KAT + all tests + all benchmarks |
| `tests` | Build all test binaries only |
| `test` | Build and run all tests (`.exec` suffix) |
| `benchmarks` | Build all benchmark binaries only |
| `benchmark` | Build and run all benchmarks |
| `clean` | Remove all built binaries |

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

The Makefile auto-links `stark-rs/target/release/libsphincsplus_stark_rs.a` when `SPX_P2_USE_RUST_STARK` is set. The Rust crate depends on `winterfell 0.13.1` and builds as both `staticlib` and `rlib`.

### CI/CD

GitHub Actions CI exists (`.github/workflows/`) but tests **only upstream backends** (SHA2, SHAKE, Haraka) across 128/192/256 parameter sets. There is **no CI coverage** for Poseidon2, Fischlin protocol, or STARK proving — local testing via `run_strict_regression.sh` is the sole gate.

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

This builds the Rust backend, then compiles and runs the core correctness/security test suite:
`poseidon2_protocol_flow`, `poseidon2_fischlin_statement_spec`, `poseidon2_verify_full_guard`,
`poseidon2_cross_backend_consistency`, `poseidon2_statement_binding`, `poseidon2_trace_replay_binding`,
`poseidon2_roles_interaction`, `poseidon2_fischlin_blind_e2e`, `poseidon2_stark_stats`.

### Additional strict-core negative-case test

Not covered by the regression script, important for paper-level validation:

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_stark_strict_core_enforcement
./test/poseidon2_stark_strict_core_enforcement
```

This is the strict witness / public statement / tamper-rejection negative-case test.

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

For a complete test catalog including AIR/witness tests, FFI tests, statement-binding tests, and the recommended verification order, see `ref/TESTING.md`.

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
│       ├── air_engine.rs       # Full-AIR: self-contained proof of entire SPHINCS+ verification
│       ├── trace_builder.rs    # Builds verification trace by walking crypto_sign_verify
│       ├── lib.rs              # Legacy mixed-proof AIR (backward compat)
│       ├── thash_poseidon2_exact.rs  # Exact Poseidon2 permutation constants/trace
│       ├── thash_sha2_exact.rs       # Exact SHA2-256 trace for cross-backend comparison
│       ├── thash_sha2_f_exact.rs     # Exact SHA2-256 compression-function trace
│       └── thash_bench.rs           # Benchmarking utilities
├── test/              # Test programs (one .c per test target)
├── scripts/           # Python + Bash scripts for param search, benchmarking, analysis
│   ├── run_strict_regression.sh        # Primary correctness gate
│   ├── collect_benchmark_v2.sh         # Protocol benchmark collection
│   ├── collect_benchmark_4way.sh       # 4-way parallel benchmark collection
│   ├── search_params_poseidon2.py      # Parameter candidate generation
│   ├── eval_security_poseidon2.py      # THF security evaluation
│   ├── eval_security_v2.py            # Updated security model evaluation
│   ├── cost_model_full_air.py          # Full-AIR cost model (replaces full benchmark)
│   ├── analyze_pareto_poseidon2.py     # Pareto-frontier analysis
│   ├── collect_benchmark_params.sh     # Batch parameter benchmark
│   ├── resume_param_search.sh          # Resume interrupted param search
│   └── package_final_results.sh        # Results packaging
├── logs/              # Runtime logs (gitignored except README)
└── final-results-v1/  # Delivered results snapshot (gitignored)
```

### Protocol architecture: Fischlin strict chain

The multi-party blind-signature protocol runs in four phases:

1. **Prepare + Issue request** (`spx_p2_prepare_issue_request`) — Holder blinds message `m` with randomness `r`, producing a commitment `com` sent to the Issuer.
2. **Issue / respond** (`spx_p2_issue_sign` / `spx_p2_issue_respond`) — Issuer signs the blinded commitment with their SPHINCS+ secret key, producing `sigma_blind`.
3. **Finalize credential** (`spx_p2_finalize_credential`) — Holder packages the blinded signature (stored verbatim — there is no mathematical unblinding in Fischlin for hash-based signatures) together with message, randomness, and binding factor into the internal credential witness.
4. **Show** (`spx_p2_show_prove` / `spx_p2_show_verify`) — Holder generates a STARK proof `pi_f` that they know a valid opening. Verifier checks the proof against only public statements (`pk_sig`, `pk_E`, `com`, `m_pub`, `public_ctx`, `sigma_C`).

There are two statement modes:
- **Statement-unbound** (legacy): verifier sees `pk_sig` and proof.
- **Statement-bound** (current recommended): verifier additionally sees `pk_E`, `m_pub` — binding the proof to explicit public statements.

The canonical public API entry points are documented in `ref/README.md`.

### Rust STARK backend (Winterfell)

The Rust crate `sphincsplus-stark-rs` implements TWO AIRs — always prefer full-AIR for new work:

**Full-AIR** (in `air_engine.rs` + `trace_builder.rs`) — **current recommended path.** Self-contained proof of the ENTIRE SPHINCS+ verification trace. No external C guards needed.
- Trace: 23,861 rows × 64 columns (128-bit params), 2,091 Poseidon2 permutations
- Approach: trace builder walks through `crypto_sign_verify`, pre-computes expected next state using `poseidon2_round`, stores in trace columns 16..27. AIR checks `nxt == expected` via simple equality constraints. Sponge state continuity, input binding, and root assertion also enforced.
- 53 constraints: rate/capacity lanes + round counter + perm index + call type + pad flag + sponge continuity + THASH absorb binding + root assertion
- Proof: ~85 KB, ~37 seconds (128-bit, blowup=16, WSL)
- C FFI: `spx_p2_ffi_generate_pi_f_full_air` / `spx_p2_ffi_verify_pi_f_full_air`
- Rust FFI: `spx_p2_rust_generate_pi_f_full_air` / `spx_p2_rust_verify_pi_f_full_air` / `spx_p2_rust_get_abi_version_full_air`

**Legacy mixed-proof AIR** (in `lib.rs`) — **deprecated for new work.** Proves commitment opening and ciphertext construction, but delegates SPHINCS+ signature verification to external C guards. Trace: 256 rows × 255 columns. C FFI: `spx_p2_ffi_generate_pi_f` / `spx_p2_ffi_verify_pi_f`.

### Key naming conventions

- `spx_p2_*` prefix — all Poseidon2/Fischlin/STARK extensions (distinct from upstream SPHINCS+ `crypto_sign_*`).
- Files with `_v1` suffix — implementation artifacts; the public API headers (`ffi.h`, `show_poseidon2.h`, `protocol_poseidon2.h`) are unversioned and are the only canonical entry points.
- `_strict_public` and `_statement_bound` suffixes in Make targets — compatibility aliases sharing the same test source (not independent tests).
- The `SPX_NAMESPACE(s)` macro wraps all public symbols for link-time namespacing.

### Parameter sets and search

Active Poseidon2 parameter files:

| File | n | Purpose |
|------|---|---------|
| `params-sphincs-poseidon2-128f-small.h` | 16 | Development (fastest prove/verify cycle) |
| `params-sphincs-poseidon2-192s.h` | 24 | Benchmark/safe (192-bit security target) |
| `params-sphincs-poseidon2-128f-bench.h` | 16 | Benchmark candidate |

Other parameter files exist for SHA2, SHAKE, and Haraka backends across security levels 128/192/256 but are not the active development focus.

**Parameter search workflow** (see `PARAMETER_SEARCH_PLAN.md` for full details):

The current approach uses a **cost model** to avoid benchmarking every candidate:
```
Generate candidates → THF security filter → Cost model estimate → Sort → Benchmark top 3-5 only
```

Key scripts:
```bash
python3 scripts/search_params_poseidon2.py      # Generate candidates
python3 scripts/eval_security_v2.py             # THF security evaluation
python3 scripts/cost_model_full_air.py          # Estimate prove time/proof size
python3 scripts/analyze_pareto_poseidon2.py     # Pareto-frontier analysis
```

The cost model estimates `total_perms` from structure parameters (k, a, d, h, w, n), then derives `trace_rows = next_pow2(total_perms × 32)` and `prove_seconds ≈ 127 × (trace_rows/131072) × (log₂(trace_rows)/17)`. It achieves ~3.5% error on dev params.

### Security model

The security analysis follows SPHINCS+'s modular THF framework (see `SECURITY_ANALYSIS.md`):
- Poseidon2 (Goldilocks field, t=12, RF=8, RP=22) instantiates the THF in ROM
- Security bounds inherit directly from SPHINCS+ spec theorems — no recalibration needed
- Key: SM-TCR, SM-DSPR, SM-PRE, SM-UD properties all hold for Poseidon2 in ROM

### Typical workflow for verifying a change

1. Edit C or Rust source.
2. If Rust changed: `cd stark-rs && cargo build --release && cd ..`
3. Run strict regression: `bash scripts/run_strict_regression.sh`
4. Run strict-core negative test: `make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_strict_core_enforcement && ./test/poseidon2_stark_strict_core_enforcement`

For paper-level validation, also run the full test sequence described in `ref/TESTING.md` §8 (Recommended verification order).

## License

This repository inherits the upstream SPHINCS+ licensing: CC0 (public domain dedication) for the reference implementation, with some files under 0BSD, MIT-0, or MIT. See `README.md` (repo root) for the full license table.
