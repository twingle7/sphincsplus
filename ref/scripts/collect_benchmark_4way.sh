#!/usr/bin/env bash
set -euo pipefail

# Four-way benchmark collector with minimal repository impact.
# Cases:
# 1) baseline SPHINCS+ sign/verify
# 2) Poseidon2 SPHINCS+ sign/verify
# 3) baseline SPHINCS+ + Fischlin blind-sign (optional external command)
# 4) Poseidon2 SPHINCS+ + Fischlin + STARK show (current path)

RUNS="${RUNS:-20}"
CC_BIN="${CC_BIN:-gcc}"
THASH="${THASH:-simple}"
PARAMS_BASELINE="${PARAMS_BASELINE:-sphincs-sha2-192s}"
PARAMS_POSEIDON2="${PARAMS_POSEIDON2:-sphincs-poseidon2-192s}"
CASE3_CMD="${CASE3_CMD:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT_DIR/logs/benchmark-4way-local.md"
TMP_DIR="$ROOT_DIR/logs/.bench4_tmp"
mkdir -p "$TMP_DIR"
cd "$ROOT_DIR"

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

run_sign_verify_case() {
  local case_name="$1"
  local params="$2"
  local sign_series=""
  local verify_series=""
  local i
  local out
  local sign_us
  local verify_us

  echo "[bench:$case_name] build benchmark (PARAMS=$params)"
  make PARAMS="$params" THASH="$THASH" CC="$CC_BIN" test/benchmark >/dev/null

  for i in $(seq 1 "$RUNS"); do
    out="$(./test/benchmark)"
    sign_us="$(printf "%s\n" "$out" | awk '/^Signing\.\./ {for(i=1;i<=NF;i++) if($i=="us"){print $(i-1); exit}}')"
    verify_us="$(printf "%s\n" "$out" | awk '/^Verifying\.\./ {for(i=1;i<=NF;i++) if($i=="us"){print $(i-1); exit}}')"
    sign_series="${sign_series}${sign_us}"$'\n'
    verify_series="${verify_series}${verify_us}"$'\n'
    echo "[bench:$case_name][$i/$RUNS] sign_us=$sign_us verify_us=$verify_us"
  done

  read -r sign_med sign_p95 sign_std <<< "$(calc_stats "$sign_series")"
  read -r verify_med verify_p95 verify_std <<< "$(calc_stats "$verify_series")"
  printf "%s|%s|%s|%s|%s|%s\n" "$case_name" "$sign_med" "$sign_p95" "$sign_std" "$verify_med" "$verify_p95" > "$TMP_DIR/$case_name.row"
}

run_case4_stark() {
  local case_name="case4_poseidon2_fischlin_stark"
  local params="$PARAMS_POSEIDON2"
  local preprocess_series=""
  local prove_core_series=""
  local prove_e2e_series=""
  local verify_series=""
  local i
  local line
  local preprocess_ms
  local prove_core_ms
  local prove_e2e_ms
  local verify_ms

  echo "[bench:$case_name] build rust backend + stats test"
  (cd stark-rs && cargo build --release >/dev/null)
  make PARAMS="$params" THASH="$THASH" CC="$CC_BIN" EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_stats >/dev/null

  for i in $(seq 1 "$RUNS"); do
    line="$(./test/poseidon2_stark_stats | tail -n 1)"
    preprocess_ms="$(echo "$line" | sed -n 's/.*preprocess_ms=\([0-9.]\+\).*/\1/p')"
    prove_core_ms="$(echo "$line" | sed -n 's/.*prove_core_ms=\([0-9.]\+\).*/\1/p')"
    prove_e2e_ms="$(echo "$line" | sed -n 's/.*prove_e2e_ms=\([0-9.]\+\).*/\1/p')"
    verify_ms="$(echo "$line" | sed -n 's/.*verify_ms=\([0-9.]\+\).*/\1/p')"
    preprocess_series="${preprocess_series}${preprocess_ms}"$'\n'
    prove_core_series="${prove_core_series}${prove_core_ms}"$'\n'
    prove_e2e_series="${prove_e2e_series}${prove_e2e_ms}"$'\n'
    verify_series="${verify_series}${verify_ms}"$'\n'
    echo "[bench:$case_name][$i/$RUNS] preprocess_ms=$preprocess_ms prove_core_ms=$prove_core_ms prove_e2e_ms=$prove_e2e_ms verify_ms=$verify_ms"
  done

  read -r pre_med pre_p95 pre_std <<< "$(calc_stats "$preprocess_series")"
  read -r core_med core_p95 core_std <<< "$(calc_stats "$prove_core_series")"
  read -r e2e_med e2e_p95 e2e_std <<< "$(calc_stats "$prove_e2e_series")"
  read -r ver_med ver_p95 ver_std <<< "$(calc_stats "$verify_series")"
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
    "$case_name" "$pre_med" "$pre_p95" "$pre_std" "$core_med" "$core_p95" "$core_std" "$e2e_med" "$e2e_p95" "$e2e_std" "$ver_med" "$ver_p95" > "$TMP_DIR/$case_name.row"
}

run_case3_optional() {
  local case_name="case3_baseline_fischlin_blind"
  if [[ -z "$CASE3_CMD" ]]; then
    printf "%s|N/A|N/A|N/A\n" "$case_name" > "$TMP_DIR/$case_name.row"
    echo "[bench:$case_name] CASE3_CMD is empty, mark as N/A"
    return
  fi
  local issue_series=""
  local prove_series=""
  local verify_series=""
  local i
  local line
  local issue_s
  local prove_s
  local verify_s
  for i in $(seq 1 "$RUNS"); do
    line="$(eval "$CASE3_CMD" | tail -n 1)"
    issue_s="$(echo "$line" | sed -n 's/.*issue=\([0-9.]\+\) s.*/\1/p')"
    prove_s="$(echo "$line" | sed -n 's/.*prove=\([0-9.]\+\) s.*/\1/p')"
    verify_s="$(echo "$line" | sed -n 's/.*verify=\([0-9.]\+\) s.*/\1/p')"
    issue_series="${issue_series}${issue_s}"$'\n'
    prove_series="${prove_series}${prove_s}"$'\n'
    verify_series="${verify_series}${verify_s}"$'\n'
    echo "[bench:$case_name][$i/$RUNS] issue_s=$issue_s prove_s=$prove_s verify_s=$verify_s"
  done
  read -r issue_med issue_p95 issue_std <<< "$(calc_stats "$issue_series")"
  read -r prove_med prove_p95 prove_std <<< "$(calc_stats "$prove_series")"
  read -r verify_med verify_p95 verify_std <<< "$(calc_stats "$verify_series")"
  printf "%s|%s|%s|%s|%s|%s|%s|%s|%s\n" \
    "$case_name" "$issue_med" "$issue_p95" "$issue_std" "$prove_med" "$prove_p95" "$prove_std" "$verify_med" "$verify_p95" > "$TMP_DIR/$case_name.row"
}

DATE_STR="$(date +%F)"
echo "[bench] start 4-way benchmark (runs=$RUNS)"

run_sign_verify_case "case1_baseline_sign" "$PARAMS_BASELINE"
run_sign_verify_case "case2_poseidon2_sign" "$PARAMS_POSEIDON2"
run_case3_optional
run_case4_stark

cat > "$OUT_FILE" <<EOF
# benchmark-4way local result

> Note:
> - case1/2 采集 \`test/benchmark\` 的 sign/verify 平均 us，并做 RUNS 轮统计。
> - case3 默认不强行绑定仓库内部实现，需通过 \`CASE3_CMD\` 注入盲签基准命令；未提供则记为 N/A。
> - case4 采集当前 Poseidon2 + Fischlin + STARK 路径分段时间统计。

## A. Sign/Verify（case1/case2）

| date | case | params | runs | sign_us_median | sign_us_p95 | sign_us_stddev | verify_us_median | verify_us_p95 |
|---|---|---|---:|---:|---:|---:|---:|---:|
EOF

IFS='|' read -r c1 s1m s1p s1std v1m v1p < "$TMP_DIR/case1_baseline_sign.row"
IFS='|' read -r c2 s2m s2p s2std v2m v2p < "$TMP_DIR/case2_poseidon2_sign.row"
{
  echo "| $DATE_STR | $c1 | $PARAMS_BASELINE | $RUNS | $s1m | $s1p | $s1std | $v1m | $v1p |"
  echo "| $DATE_STR | $c2 | $PARAMS_POSEIDON2 | $RUNS | $s2m | $s2p | $s2std | $v2m | $v2p |"
} >> "$OUT_FILE"

cat >> "$OUT_FILE" <<EOF

## B. Blind/Fischlin（case3）

| date | case | runs | issue_s_median | issue_s_p95 | issue_s_stddev | prove_s_median | prove_s_p95 | verify_s_median |
|---|---|---:|---:|---:|---:|---:|---:|---:|
EOF

IFS='|' read -r c3 i3m i3p i3std p3m p3p p3std v3m v3p < "$TMP_DIR/case3_baseline_fischlin_blind.row"
if [[ "$i3m" == "N/A" ]]; then
  echo "| $DATE_STR | $c3 | $RUNS | N/A | N/A | N/A | N/A | N/A | N/A |" >> "$OUT_FILE"
else
  echo "| $DATE_STR | $c3 | $RUNS | $i3m | $i3p | $i3std | $p3m | $p3p | $v3m |" >> "$OUT_FILE"
fi

cat >> "$OUT_FILE" <<EOF

## C. Current Poseidon2 + Fischlin + STARK（case4）

| date | case | runs | preprocess_ms_median | preprocess_ms_p95 | preprocess_ms_stddev | prove_core_ms_median | prove_core_ms_p95 | prove_core_ms_stddev | prove_e2e_ms_median | prove_e2e_ms_p95 | prove_e2e_ms_stddev | verify_ms_median | verify_ms_p95 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
EOF

IFS='|' read -r c4 pre4m pre4p pre4std core4m core4p core4std e24m e24p e24std ver4m ver4p < "$TMP_DIR/case4_poseidon2_fischlin_stark.row"
echo "| $DATE_STR | $c4 | $RUNS | $pre4m | $pre4p | $pre4std | $core4m | $core4p | $core4std | $e24m | $e24p | $e24std | $ver4m | $ver4p |" >> "$OUT_FILE"

echo "[bench] wrote $OUT_FILE"
