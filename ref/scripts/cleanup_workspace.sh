#!/usr/bin/env bash
set -euo pipefail

APPLY=0
AGGRESSIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --aggressive)
      AGGRESSIVE=1
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

targets=(
  "logs/.params_bench_tmp"
  "logs/.bench4_tmp"
  "__pycache__"
  "scripts/__pycache__"
)

if [[ "${AGGRESSIVE}" -eq 1 ]]; then
  targets+=("params/params-sphincs-poseidon2-searchtmp.h")
fi

if [[ "${APPLY}" -eq 1 ]]; then
  echo "Cleanup mode: APPLY (will delete)"
else
  echo "Cleanup mode: DRY-RUN (no deletion)"
fi
echo "Aggressive mode: ${AGGRESSIVE}"
echo

for rel in "${targets[@]}"; do
  abs="${REF_DIR}/${rel}"
  if [[ -e "${abs}" ]]; then
    echo "[TARGET] ${rel}"
    if [[ "${APPLY}" -eq 1 ]]; then
      rm -rf "${abs}"
      echo "  -> deleted"
    fi
  else
    echo "[SKIP] ${rel} (not found)"
  fi
done

echo
if [[ "${APPLY}" -ne 1 ]]; then
  echo "Dry-run finished. Re-run with --apply to execute deletion."
fi
