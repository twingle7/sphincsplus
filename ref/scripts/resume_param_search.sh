#!/usr/bin/env bash
set -euo pipefail

# Resume helper for long-running parameter benchmarks.
#
# Modes:
# - stark:      resume full M4 STARK collection
# - signverify: resume M4-ok sign/verify collection
#
# This wrapper keeps the existing OUT_CSV and skips already written candidate_ids.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-}"
CC_BIN="${CC_BIN:-gcc}"
THASH="${THASH:-simple}"
TOP_K="${TOP_K:-0}"
RUNS_STARK="${RUNS_STARK:-1}"
RUNS_SIGNVERIFY="${RUNS_SIGNVERIFY:-1}"
BENCH_TIMEOUT_SEC="${BENCH_TIMEOUT_SEC:-1800}"
STARK_TIMEOUT_SEC="${STARK_TIMEOUT_SEC:-1800}"
HEARTBEAT_SEC="${HEARTBEAT_SEC:-15}"
RUN_PARETO_AFTER="${RUN_PARETO_AFTER:-1}"

case "$MODE" in
  stark)
    INPUT_CSV="${INPUT_CSV:-logs/params-security-pass-v1.csv}"
    OUT_CSV="${OUT_CSV:-logs/params-benchmark-v1-full.csv}"
    ENABLE_STARK=1
    ENABLE_SIGNVERIFY=0
    ;;
  signverify)
    SECURITY_CSV="${SECURITY_CSV:-logs/params-security-pass-v1.csv}"
    STARK_CSV="${STARK_CSV:-logs/params-benchmark-v1-full.csv}"
    INPUT_CSV="${INPUT_CSV:-logs/params-m4-ok-for-signverify-v1.csv}"
    OUT_CSV="${OUT_CSV:-logs/params-signverify-m4-ok-v1.csv}"
    ENABLE_STARK=0
    ENABLE_SIGNVERIFY=1

    if [[ ! -f "$INPUT_CSV" ]]; then
      echo "[RESUME] build missing M4-ok input csv: $INPUT_CSV"
      python3 scripts/select_m4_ok_for_signverify.py \
        --security-csv "$SECURITY_CSV" \
        --stark-csv "$STARK_CSV" \
        --output-csv "$INPUT_CSV"
    fi
    ;;
  *)
    echo "usage: bash scripts/resume_param_search.sh [stark|signverify]" >&2
    exit 1
    ;;
esac

REMAINING_CSV="logs/.resume-remaining-$(basename "${OUT_CSV%.*}").csv"

echo "[RESUME] inspect progress"
python3 scripts/report_resume_progress.py \
  --input-csv "$INPUT_CSV" \
  --output-csv "$OUT_CSV" \
  --remaining-csv "$REMAINING_CSV"

echo "[RESUME] continue benchmark collection"
INPUT_CSV="$INPUT_CSV" \
OUT_CSV="$OUT_CSV" \
TOP_K="$TOP_K" \
ENABLE_STARK="$ENABLE_STARK" \
ENABLE_SIGNVERIFY="$ENABLE_SIGNVERIFY" \
RUNS_STARK="$RUNS_STARK" \
RUNS_SIGNVERIFY="$RUNS_SIGNVERIFY" \
CC_BIN="$CC_BIN" \
THASH="$THASH" \
BENCH_TIMEOUT_SEC="$BENCH_TIMEOUT_SEC" \
STARK_TIMEOUT_SEC="$STARK_TIMEOUT_SEC" \
HEARTBEAT_SEC="$HEARTBEAT_SEC" \
RESUME=1 \
bash scripts/collect_benchmark_params.sh

if [[ "$MODE" == "signverify" && "$RUN_PARETO_AFTER" == "1" ]]; then
  echo "[RESUME] run global Pareto analysis"
  python3 scripts/analyze_pareto_poseidon2.py \
    --security-csv "${SECURITY_CSV:-logs/params-security-pass-v1.csv}" \
    --stark-csv "${STARK_CSV:-logs/params-benchmark-v1-full.csv}" \
    --signverify-csv "$OUT_CSV"
fi

echo "[RESUME] done"
