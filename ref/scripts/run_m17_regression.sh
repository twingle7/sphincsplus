#!/usr/bin/env bash
set -euo pipefail

PARAMS="${PARAMS:-sphincs-poseidon2-192s}"
THASH="${THASH:-simple}"
CC_BIN="${CC_BIN:-gcc}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[M17] build rust backend"
(cd stark-rs && cargo build --release)

echo "[M17] build regression tests"
make PARAMS="$PARAMS" THASH="$THASH" CC="$CC_BIN" EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_verify_full_guard \
  test/poseidon2_cross_backend_consistency \
  test/poseidon2_statement_binding \
  test/poseidon2_trace_replay_binding \
  test/poseidon2_roles_interaction \
  test/poseidon2_fischlin_blind_e2e \
  test/poseidon2_stark_stats

echo "[M17] run regression tests"
./test/poseidon2_verify_full_guard
./test/poseidon2_cross_backend_consistency
./test/poseidon2_statement_binding
./test/poseidon2_trace_replay_binding
./test/poseidon2_roles_interaction
./test/poseidon2_fischlin_blind_e2e
./test/poseidon2_stark_stats

echo "[M17] regression: PASS"
