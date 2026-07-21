# Experimental Results — SPHINCS+-Poseidon2 Fischlin Blind Signature

All measurements on WSL2 (Ubuntu), 8GB RAM, Intel Core i7.

## Parameter Sets

| Name | n | h | d | k | a | FORS security | SPX_BYTES | Trace rows | Poseidon2 calls |
|------|---|---|---|---|---|--------------|-----------|-------------|-----------------|
| Dev (128f-small) | 16 | 40 | 4 | 8 | 6 | ~48-bit | 3,792 | ~13K | 1,121 |
| **128f** | **16** | **63** | **7** | **10** | **12** | **~120-bit** | **7,024** | **~50K** | **~4,534** |

## Dev Parameters (h=40, blowup=16, queries=27) — WSL Measured

| Metric | Run 1 (cold) | Run 2 (warm) |
|--------|-------------|-------------|
| Prove (core) | 38.5s | **36.0s** |
| Verify | 10.7ms | **4.6ms** |
| Preprocess | 22.6ms | 21.3ms |
| Proof size | 86,061 B | 85,996 B |
| Peak RSS | 4.6 GB | 4.6 GB |
| Poseidon2 calls | 1,121 | 1,121 |
| Trace rows | 12,793 | 12,793 |

All 9 regression tests: PASS ✅ | Magic: 0x32504650, Version: 2 ✅

## 128-bit Parameters (h=63, blowup=16, queries=27) — WSL Measured

| Metric | Dev (h=40) | **128-bit (h=63)** | Ratio |
|--------|-----------|-------------------|-------|
| SPX_BYTES | 3,792 | **7,024** | 1.85× |
| Poseidon2 calls | 1,121 | **2,091** | 1.87× |
| Trace rows | 12,793 | **23,861** | 1.87× |
| Trace domain | 16,384 | **32,768** | 2× |
| Preprocess | 21ms | **40ms** | 1.9× |
| **Prove (core)** | **36.0s** | **36.9s** | **1.03×** |
| **Verify** | **4.6ms** | **4.2ms** | 0.91× |
| Proof size | ~86 KB | **~85 KB** | ~1× |
| Peak RSS | 4.6 GB | **4.6 GB** | ~1× |
| Conjectured STARK security | ~108-bit | ~108-bit | — |

**Key finding**: Prove time barely increased (36.0→36.9s) despite 1.87× more trace rows, because both fit in adjacent pow2 domains (16K→32K) and FRI query cost dominates over constraint evaluation.

Paper-ready numbers: **prove=37s, verify=4ms, proof=85KB, memory=4.6GB, 128-bit SPHINCS+ security, ~108-bit STARK security**.

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

## Regression Test Results (Dev params, 9/9 PASS)

```
=== Poseidon2 Fischlin Protocol Flow Demo ===       OK
poseidon2_fischlin_statement_spec test:              OK
poseidon2_verify_full_guard test:                    OK (49976 constraints, 1 violation)
poseidon2_cross_backend_consistency test:            OK
poseidon2_statement_binding test:                    OK (pi_f_len=85999)
poseidon2_trace_replay_binding test:                 OK (pi_f_len=85421)
poseidon2_roles_interaction test:                    OK (pi_f_len=85166)
poseidon2_fischlin_blind_e2e test:                   OK (pi_f_len=86320)
poseidon2_stark_stats:                               OK
[strict] regression: PASS
```

## WSL Benchmark Commands

```bash
# Setup — 128-bit params
cd /mnt/d/Desktop/sphincsplus/ref
export PARAMS=sphincs-poseidon2-128f      # 128-bit params (h=63,d=7,k=10,a=12)
export THASH=simple
export CC=gcc

# Build Rust backend
cd stark-rs && cargo build --release && cd ..

# Full strict regression
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

# Dev params (fast iteration)
export PARAMS=sphincs-poseidon2-128f-small
```

## Rust Unit Tests

```bash
cd /mnt/d/Desktop/sphincsplus/ref/stark-rs
cargo test --lib air_engine
cargo test --lib
```
