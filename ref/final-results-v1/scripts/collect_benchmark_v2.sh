#!/usr/bin/env bash
set -euo pipefail

PARAMS="${PARAMS:-sphincs-poseidon2-192s}"
THASH="${THASH:-simple}"
CC_BIN="${CC_BIN:-gcc}"
RUNS="${RUNS:-30}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT_DIR/logs/benchmark-stark-v2-local.md"
cd "$ROOT_DIR"

echo "[bench] build rust backend"
(cd stark-rs && cargo build --release)

echo "[bench] build stats test"
make PARAMS="$PARAMS" THASH="$THASH" CC="$CC_BIN" EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_stats

calc_stats() {
  local series="$1"
  printf "%s\n" "$series" | awk '
    NF{
      a[n++]=$1;
      sum+=$1;
      sumsq+=($1*$1);
    }
    END{
      if(n==0){ print "0 0 0"; exit; }
      for(i=0;i<n;i++){
        for(j=i+1;j<n;j++){
          if(a[j] < a[i]){
            t=a[i]; a[i]=a[j]; a[j]=t;
          }
        }
      }
      if(n%2==1){ median=a[int(n/2)]; }
      else { median=(a[n/2-1]+a[n/2])/2.0; }
      p95_idx=int((n-1)*0.95 + 0.999999);
      if(p95_idx<0){ p95_idx=0; }
      if(p95_idx>=n){ p95_idx=n-1; }
      p95=a[p95_idx];
      mean=sum/n;
      var=(sumsq/n)-(mean*mean);
      if(var<0){ var=0; }
      std=sqrt(var);
      printf "%.3f %.3f %.3f\n", median, p95, std;
    }'
}

echo "[bench] run stats test (runs=$RUNS)"
PREPROCESS_SERIES=""
PROVE_CORE_SERIES=""
PROVE_E2E_SERIES=""
VERIFY_SERIES=""
LAST_LINE=""
for i in $(seq 1 "$RUNS"); do
  STATS_LINE="$(./test/poseidon2_stark_stats | tail -n 1)"
  echo "[$i/$RUNS] $STATS_LINE"
  LAST_LINE="$STATS_LINE"
  PREPROCESS_MS="$(echo "$STATS_LINE" | sed -n 's/.*preprocess_ms=\([0-9.]\+\).*/\1/p')"
  PROVE_CORE_MS="$(echo "$STATS_LINE" | sed -n 's/.*prove_core_ms=\([0-9.]\+\).*/\1/p')"
  PROVE_E2E_MS="$(echo "$STATS_LINE" | sed -n 's/.*prove_e2e_ms=\([0-9.]\+\).*/\1/p')"
  VERIFY_MS="$(echo "$STATS_LINE" | sed -n 's/.*verify_ms=\([0-9.]\+\).*/\1/p')"
  PREPROCESS_SERIES="${PREPROCESS_SERIES}${PREPROCESS_MS}"$'\n'
  PROVE_CORE_SERIES="${PROVE_CORE_SERIES}${PROVE_CORE_MS}"$'\n'
  PROVE_E2E_SERIES="${PROVE_E2E_SERIES}${PROVE_E2E_MS}"$'\n'
  VERIFY_SERIES="${VERIFY_SERIES}${VERIFY_MS}"$'\n'
done

CALLS="$(echo "$LAST_LINE" | sed -n 's/.*calls=\([0-9]\+\).*/\1/p')"
LANES="$(echo "$LAST_LINE" | sed -n 's/.*lanes=\([0-9]\+\).*/\1/p')"
ROWS="$(echo "$LAST_LINE" | sed -n 's/.*rows=\([0-9]\+\).*/\1/p')"
PROOF="$(echo "$LAST_LINE" | sed -n 's/.*proof=\([0-9]\+\).*/\1/p')"
MAGIC="$(echo "$LAST_LINE" | sed -n 's/.*magic=\(0x[0-9a-fA-F]\+\).*/\1/p')"
VER="$(echo "$LAST_LINE" | sed -n 's/.*ver=\([0-9]\+\).*/\1/p')"
read -r PREPROCESS_MED PREPROCESS_P95 PREPROCESS_STD <<< "$(calc_stats "$PREPROCESS_SERIES")"
read -r PROVE_CORE_MED PROVE_CORE_P95 PROVE_CORE_STD <<< "$(calc_stats "$PROVE_CORE_SERIES")"
read -r PROVE_E2E_MED PROVE_E2E_P95 PROVE_E2E_STD <<< "$(calc_stats "$PROVE_E2E_SERIES")"
read -r VERIFY_MED VERIFY_P95 VERIFY_STD <<< "$(calc_stats "$VERIFY_SERIES")"
DATE_STR="$(date +%F)"

cat > "$OUT_FILE" <<EOF
# benchmark-stark-v2 local result

| date | params | backend | runs | trace_calls | trace_lanes | witness_rows | proof_bytes | proof_magic | proof_version | preprocess_ms_median | preprocess_ms_p95 | preprocess_ms_stddev | prove_core_ms_median | prove_core_ms_p95 | prove_core_ms_stddev | prove_e2e_ms_median | prove_e2e_ms_p95 | prove_e2e_ms_stddev | verify_ms_median | verify_ms_p95 | verify_ms_stddev |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| $DATE_STR | $PARAMS | Rust-stark | $RUNS | $CALLS | $LANES | $ROWS | $PROOF | $MAGIC | $VER | $PREPROCESS_MED | $PREPROCESS_P95 | $PREPROCESS_STD | $PROVE_CORE_MED | $PROVE_CORE_P95 | $PROVE_CORE_STD | $PROVE_E2E_MED | $PROVE_E2E_P95 | $PROVE_E2E_STD | $VERIFY_MED | $VERIFY_P95 | $VERIFY_STD |
EOF

echo "[bench] wrote $OUT_FILE"
