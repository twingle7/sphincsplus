#!/usr/bin/env bash
set -euo pipefail

PYTHON_CMD="${PYTHON_CMD:-python3}"
OUTPUT_ROOT="final-results-v1"
CLEAN_OUTPUT_FIRST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python-cmd)
      PYTHON_CMD="${2:?missing value for --python-cmd}"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="${2:?missing value for --output-root}"
      shift 2
      ;;
    --clean-output-first)
      CLEAN_OUTPUT_FIRST=1
      shift
      ;;
    *)
      echo "[ERROR] Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REF_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REF_DIR}"

echo "[STEP] M6 budget degradation"
"${PYTHON_CMD}" "scripts/analyze_budget_degradation_poseidon2.py"

echo "[STEP] Multi-metric comparison refresh"
if ! "${PYTHON_CMD}" "scripts/plot_param_comparison.py"; then
  echo "[WARN] plot_param_comparison.py failed. Continue packaging with existing comparison artifacts."
  echo "[WARN] If needed, install deps in WSL: ${PYTHON_CMD} -m pip install matplotlib"
fi

echo "[STEP] Package final results"
pkg_args=(--output-root "${OUTPUT_ROOT}")
if [[ "${CLEAN_OUTPUT_FIRST}" -eq 1 ]]; then
  pkg_args+=(--clean-output-first)
fi
bash "scripts/package_final_results.sh" "${pkg_args[@]}"

echo "[DONE] M6 + bundle finished."
