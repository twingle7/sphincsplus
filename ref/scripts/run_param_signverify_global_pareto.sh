#!/usr/bin/env bash
set -euo pipefail

# Full post-M4 flow:
# 1. Extract all M4-ok candidates from the full STARK results.
# 2. Rerun sign/verify for the full M4-ok set.
# 3. Run global M5 Pareto on M3 pass ∩ M4 ok ∩ sign/verify ok.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SECURITY_CSV="${SECURITY_CSV:-logs/params-security-pass-v1.csv}"
STARK_CSV="${STARK_CSV:-logs/params-benchmark-v1-full.csv}"
M4_OK_CSV="${M4_OK_CSV:-logs/params-m4-ok-for-signverify-v1.csv}"
SIGNVERIFY_CSV="${SIGNVERIFY_CSV:-logs/params-signverify-m4-ok-v1.csv}"

RUNS_SIGNVERIFY="${RUNS_SIGNVERIFY:-1}"
CC_BIN="${CC_BIN:-gcc}"
THASH="${THASH:-simple}"
BENCH_TIMEOUT_SEC="${BENCH_TIMEOUT_SEC:-1800}"
HEARTBEAT_SEC="${HEARTBEAT_SEC:-15}"

echo "[FLOW] extract full M4-ok candidate subset"
python3 scripts/select_m4_ok_for_signverify.py \
  --security-csv "$SECURITY_CSV" \
  --stark-csv "$STARK_CSV" \
  --output-csv "$M4_OK_CSV"

echo "[FLOW] rerun sign/verify on full M4-ok subset"
INPUT_CSV="$M4_OK_CSV" \
OUT_CSV="$SIGNVERIFY_CSV" \
TOP_K=0 \
ENABLE_STARK=0 \
ENABLE_SIGNVERIFY=1 \
RUNS_SIGNVERIFY="$RUNS_SIGNVERIFY" \
CC_BIN="$CC_BIN" \
THASH="$THASH" \
BENCH_TIMEOUT_SEC="$BENCH_TIMEOUT_SEC" \
HEARTBEAT_SEC="$HEARTBEAT_SEC" \
bash scripts/collect_benchmark_params.sh

echo "[FLOW] run global Pareto analysis"
python3 scripts/analyze_pareto_poseidon2.py \
  --security-csv "$SECURITY_CSV" \
  --stark-csv "$STARK_CSV" \
  --signverify-csv "$SIGNVERIFY_CSV"

echo "[DONE] full M4-ok sign/verify rerun + global Pareto finished"
