#!/usr/bin/env bash
set -euo pipefail

OUTPUT_ROOT="final-results-v1"
CLEAN_OUTPUT_FIRST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
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
REPO_DIR="$(cd "${REF_DIR}/.." && pwd)"
OUT_DIR="${REF_DIR}/${OUTPUT_ROOT}"

if [[ "${CLEAN_OUTPUT_FIRST}" -eq 1 && -d "${OUT_DIR}" ]]; then
  rm -rf "${OUT_DIR}"
fi
mkdir -p "${OUT_DIR}"

copy_if_exists() {
  local rel_src="$1"
  local rel_dst="$2"
  local src="${REF_DIR}/${rel_src}"
  local dst="${OUT_DIR}/${rel_dst}"
  if [[ ! -e "${src}" ]]; then
    echo "[WARN] Missing: ${rel_src}"
    return 0
  fi
  mkdir -p "$(dirname "${dst}")"
  cp -f "${src}" "${dst}"
  echo "[COPY] ${rel_src} -> ${rel_dst}"
}

param_files=(
  "logs/poseidon2-instantiation-spec-v1.md"
  "logs/params-search-raw-v1.csv"
  "logs/params-search-struct-pass-v1.csv"
  "logs/params-security-eval-v1.csv"
  "logs/params-security-pass-v1.csv"
  "logs/params-benchmark-v1-full.csv"
  "logs/params-signverify-finalists.csv"
  "logs/params-m5-merged-v1.csv"
  "logs/params-pareto-frontier-v1.csv"
  "logs/params-pareto-nonfrontier-v1.csv"
  "logs/params-pareto-v1.md"
  "logs/params-final-candidates-v1.md"
  "logs/params-budget-degradation-v1.csv"
  "logs/params-budget-degradation-v1.md"
  "logs/params-security-claim-template-v1.md"
  "logs/params-compare-with-192s-v1.csv"
  "logs/params-candidate-rank-v1.csv"
  "logs/params-primary-delta-v1.csv"
  "logs/fig-compare-sign-ms-v1.png"
  "logs/fig-compare-verify-ms-v1.png"
  "logs/fig-compare-sign-vs-zk-v1.png"
  "logs/fig-compare-multimetric-common-v1.png"
  "logs/fig-compare-candidate-heatmap-v1.png"
)
for f in "${param_files[@]}"; do
  copy_if_exists "${f}" "param-search/$(basename "${f}")"
done

core_files=(
  "logs/benchmark-4way-local.md"
  "logs/benchmark-stark-v2-local.md"
  "logs/benchmark-stark-v2.md"
  "logs/blind-sign-e2e-v2.md"
  "logs/cross-backend-consistency-v1.md"
  "logs/m17-consistency-report-v2.md"
  "logs/release-checklist-v2.md"
  "logs/thesis-notes-stark-v2.md"
  "logs/project-final-summary-v1.md"
)
for f in "${core_files[@]}"; do
  copy_if_exists "${f}" "core-experiments/$(basename "${f}")"
done

copy_if_exists "logs/final-results-readme-template-v1.md" "README.md"

script_files=(
  "scripts/search_params_poseidon2.py"
  "scripts/eval_security_poseidon2.py"
  "scripts/collect_benchmark_params.sh"
  "scripts/analyze_pareto_poseidon2.py"
  "scripts/plot_param_comparison.py"
  "scripts/analyze_budget_degradation_poseidon2.py"
  "scripts/collect_benchmark_4way.sh"
  "scripts/collect_benchmark_v2.sh"
  "scripts/run_m17_regression.sh"
)
for f in "${script_files[@]}"; do
  copy_if_exists "${f}" "scripts/$(basename "${f}")"
done

manifest="${OUT_DIR}/MANIFEST.txt"
{
  echo "Final Results Bundle"
  echo "Generated at: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Repo root: ${REPO_DIR}"
  echo
  echo "Files:"
  (cd "${OUT_DIR}" && find . -type f | sed 's#^\./##' | sort)
} > "${manifest}"

echo "[DONE] Bundle directory: ${OUT_DIR}"
echo "[DONE] Manifest: ${manifest}"
