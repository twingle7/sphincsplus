# Experimental Results — SPHINCS+-Poseidon2 Fischlin Blind Signature

All measurements on Windows 11 Home China, MinGW64, Rust 1.85+, gcc (MinGW).

## Parameter Sets

| Name | n | h | d | k | a | FORS security | Trace rows | Permutations |
|------|---|---|---|---|---|--------------|-------------|-------------|
| Dev (small) | 16 | 40 | 4 | 8 | 6 | ~48-bit | ~13K | ~1,150 |
| **128-bit** | **16** | **63** | **7** | **10** | **12** | **~120-bit** | **~50K** | **~4,534** |

## STARK Proof Metrics (128-bit params, blowup=16, queries=27)

| Metric | Value |
|--------|-------|
| Trace dimensions | ~50K rows × 64 columns |
| Trace domain size | 262,144 (next power of 2) |
| Poseidon2 permutations | ~4,534 |
| AIR constraints | 53 |
| Proof size | ~71 KB |
| Prove time | ~246 seconds (single thread) |
| Verify time | ~5.6 ms |
| Conjectured STARK security | ~108-bit |
| Memory peak | ~5 GB RSS |

## Constraint Breakdown (53 total)

| Indices | Category | Count |
|---------|----------|-------|
| 0-5 | Rate lane checks | 6 |
| 6-11 | Capacity lane copies | 6 |
| 12-15 | Round counter | 4 |
| 16 | Perm index | 1 |
| 17 | Call type const | 1 |
| 18 | Pad flag boolean | 1 |
| 19-24 | Rate absorption (state = init + absorb) | 6 |
| 25-30 | Capacity init check | 6 |
| 31 | carries_from_prev boolean | 1 |
| 32 | carries_to_next boolean | 1 |
| 33-44 | State carry at is_last | 12 |
| 45 | is_thash boolean | 1 |
| 46 | THASH absorb[0] Lagrange | 1 |
| 47 | THASH absorb[1] = pub_seed_hi | 1 |
| 48 | THASH domain membership | 1 |
| 49-52 | THASH absorb[2..5] = expected | 4 |

## Proof Header Format (296 bytes)

```
[4 magic "PFP2"] [4 version=2] [8 total_perms] [8 root_perm]
[96 start_state (12×8)] [96 result_state (12×8)]
[16 pk_root] [16 com] [16 pub_seed] [32 ctx_hash]
```

## Comparison: Dev vs 128-bit vs Blowup

| Config | Prove | Verify | Proof | Security |
|--------|-------|--------|-------|----------|
| Dev (blowup=8) | ~72s | ~5.6ms | ~71KB | ~80-bit |
| 128-bit (blowup=8) | ~156s | ~5.6ms | ~71KB | ~80-bit |
| **128-bit (blowup=16)** | **~246s** | **~5.6ms** | **~71KB** | **~108-bit** |

## WSL Benchmark Commands

```bash
# Setup
cd /mnt/d/Desktop/sphincsplus/ref
export PARAMS=sphincs-poseidon2-128f-small
export THASH=simple
export CC=gcc

# Build Rust backend
cd stark-rs && cargo build --release && cd ..

# Full strict regression (all 9 tests)
bash scripts/run_strict_regression.sh

# Individual protocol benchmark
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_protocol_benchmark
./test/poseidon2_protocol_benchmark

# Batch benchmark (30 runs)
RUNS=30 bash scripts/collect_benchmark_v2.sh

# STARK stats
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_stark_stats
./test/poseidon2_stark_stats
```

## Rust Unit Tests

```bash
cd /mnt/d/Desktop/sphincsplus/ref/stark-rs

# Air engine tests (E2E prove+verify + tamper rejection)
cargo test --lib air_engine

# All lib tests
cargo test --lib

# With release build
cargo test --lib --release
```
