#!/usr/bin/env bash
set -euo pipefail

# M4: batch benchmark collector for M3-passed candidates.
#
# Input:
#   logs/params-security-pass-v1.csv
# Output:
#   logs/params-benchmark-v1.csv
#
# Notes:
# - This script generates a temporary parameter header:
#     params/params-sphincs-poseidon2-searchtmp.h
#   and rebuilds test binaries per candidate.
# - It records per-candidate status and error, then continues.

INPUT_CSV="${INPUT_CSV:-logs/params-security-pass-v1.csv}"
OUT_CSV="${OUT_CSV:-logs/params-benchmark-v1.csv}"
CC_BIN="${CC_BIN:-gcc}"
THASH="${THASH:-simple}"
TOP_K="${TOP_K:-20}"
RUNS_SIGNVERIFY="${RUNS_SIGNVERIFY:-1}"
RUNS_STARK="${RUNS_STARK:-1}"
ENABLE_STARK="${ENABLE_STARK:-1}"
ENABLE_SIGNVERIFY="${ENABLE_SIGNVERIFY:-1}"
BENCH_TIMEOUT_SEC="${BENCH_TIMEOUT_SEC:-900}"
STARK_TIMEOUT_SEC="${STARK_TIMEOUT_SEC:-300}"
HEARTBEAT_SEC="${HEARTBEAT_SEC:-15}"
PARAMS_NAME="sphincs-poseidon2-searchtmp"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$ROOT_DIR/logs/.params_bench_tmp"
mkdir -p "$TMP_DIR"
PARAMS_FILE="$ROOT_DIR/params/params-$PARAMS_NAME.h"

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

write_params_header() {
  local n="$1"
  local h="$2"
  local d="$3"
  local k="$4"
  local a="$5"
  local w="$6"
  local wots_len1="$7"
  local wots_len2="$8"
  local tree_height="$9"
  local wots_logw

  if [[ "$w" == "16" ]]; then
    wots_logw=4
  elif [[ "$w" == "256" ]]; then
    wots_logw=8
  else
    echo "[M4] unsupported w=$w for header generation" >&2
    return 1
  fi

  cat > "$PARAMS_FILE" <<EOF
#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

#define SPX_NAMESPACE(s) SPX_##s

/* Hash output length in bytes. */
#define SPX_N $n
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT $h
/* Number of subtree layer. */
#define SPX_D $d
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT $a
#define SPX_FORS_TREES $k
/* Winternitz parameter. */
#define SPX_WOTS_W $w

/* Poseidon2 backend flag. */
#define SPX_POSEIDON2 1

/* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters (frozen from M2 derived metrics). */
#define SPX_WOTS_LOGW $wots_logw
#define SPX_WOTS_LEN1 $wots_len1
#define SPX_WOTS_LEN2 $wots_len2
#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT $tree_height

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + \
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Reuse the SHAKE layout for address offsets. */
#include "../shake_offsets.h"

#endif
EOF
}

append_row() {
  local row="$1"
  printf "%s\n" "$row" >> "$OUT_CSV"
}

run_with_timeout() {
  local cmd="$1"
  local timeout_sec="$2"
  local out_file="$3"
  local tag="$4"
  local start_ts
  local now_ts
  local elapsed=0
  local next_heartbeat
  local pid

  start_ts="$(date +%s)"
  next_heartbeat="$HEARTBEAT_SEC"

  bash -lc "$cmd" >"$out_file" 2>&1 &
  pid=$!

  while kill -0 "$pid" 2>/dev/null; do
    sleep 1
    now_ts="$(date +%s)"
    elapsed=$((now_ts - start_ts))
    if (( elapsed >= next_heartbeat )); then
      echo "[M4][$tag] still running (${elapsed}s)"
      next_heartbeat=$((next_heartbeat + HEARTBEAT_SEC))
    fi
    if (( elapsed >= timeout_sec )); then
      echo "[M4][$tag] timeout after ${elapsed}s"
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
  done

  wait "$pid"
}

extract_bench_value() {
  local text="$1"
  local label="$2"
  printf "%s\n" "$text" | awk -v label="$label" '
    index($0, label)==1 {
      for (i=1; i<=NF; i++) {
        if ($i=="us") { print $(i-1); exit }
      }
    }'
}

extract_size_value() {
  local text="$1"
  local label="$2"
  printf "%s\n" "$text" | awk -v label="$label" '
    index($0, label)==1 { print $3; exit }'
}

extract_stats_value() {
  local line="$1"
  local key="$2"
  echo "$line" | sed -n "s/.*${key}=\\([^ ]*\\).*/\\1/p"
}

cat > "$OUT_CSV" <<EOF
candidate_id,n,h,d,k,a,w,q,keygen_us_median,keygen_us_p95,keygen_us_stddev,sign_us_median,sign_us_p95,sign_us_stddev,verify_us_median,verify_us_p95,verify_us_stddev,pk_bytes,sk_bytes,sig_bytes,trace_calls,trace_lanes,witness_rows,proof_bytes,proof_magic,proof_version,preprocess_ms_median,preprocess_ms_p95,preprocess_ms_stddev,prove_core_ms_median,prove_core_ms_p95,prove_core_ms_stddev,prove_e2e_ms_median,prove_e2e_ms_p95,prove_e2e_ms_stddev,stark_verify_ms_median,stark_verify_ms_p95,stark_verify_ms_stddev,status,error
EOF

if [[ ! -f "$INPUT_CSV" ]]; then
  echo "[M4] input csv not found: $INPUT_CSV" >&2
  exit 1
fi

if [[ "$ENABLE_STARK" == "1" ]]; then
  echo "[M4] build rust backend once"
  (cd stark-rs && cargo build --release >/dev/null)
fi

echo "[M4] collecting benchmarks from: $INPUT_CSV"
echo "[M4] top_k=$TOP_K sign_runs=$RUNS_SIGNVERIFY stark_runs=$RUNS_STARK enable_stark=$ENABLE_STARK enable_signverify=$ENABLE_SIGNVERIFY"
echo "[M4] timeout(benchmark/stark)=${BENCH_TIMEOUT_SEC}s/${STARK_TIMEOUT_SEC}s heartbeat=${HEARTBEAT_SEC}s"

line_no=0
while IFS=, read -r candidate_id n h d k a w q tree_height tree_bits leaf_bits wots_logw wots_len1 wots_len2 wots_len fors_msg_bits fors_msg_bytes hmsg_needed_bytes pk_ref sk_ref sig_ref struct_pass reject_reason security_model target_bits poseidon2_floor_bits q_reference comb_security_bits budget_penalty_bits budget_security_bits poseidon2_security_bits claimed_security_bits security_pass security_reject_reason; do
  line_no=$((line_no + 1))
  if [[ $line_no -eq 1 ]]; then
    continue
  fi
  if [[ -z "${candidate_id:-}" ]]; then
    continue
  fi
  if [[ "$line_no" -gt $((TOP_K + 1)) ]]; then
    break
  fi

  status="ok"
  err=""

  keygen_med="0"; keygen_p95="0"; keygen_std="0"
  sign_med="0"; sign_p95="0"; sign_std="0"
  verify_med="0"; verify_p95="0"; verify_std="0"
  pk_bytes="$pk_ref"; sk_bytes="$sk_ref"; sig_bytes="$sig_ref"
  trace_calls="0"; trace_lanes="0"; witness_rows="0"; proof_bytes="0"; proof_magic="N/A"; proof_version="0"
  pre_med="0"; pre_p95="0"; pre_std="0"
  core_med="0"; core_p95="0"; core_std="0"
  e2e_med="0"; e2e_p95="0"; e2e_std="0"
  sver_med="0"; sver_p95="0"; sver_std="0"

  echo "[M4][$candidate_id] n=$n h=$h d=$d k=$k a=$a w=$w q=$q"

  if ! write_params_header "$n" "$h" "$d" "$k" "$a" "$w" "$wots_len1" "$wots_len2" "$tree_height"; then
    status="fail"
    err="write_params_header_failed"
  fi

  if [[ "$status" == "ok" && "$ENABLE_SIGNVERIFY" == "1" ]]; then
    if ! make -B PARAMS="$PARAMS_NAME" THASH="$THASH" CC="$CC_BIN" test/benchmark >/dev/null 2>&1; then
      status="fail"
      err="build_benchmark_failed"
    fi
  fi

  if [[ "$status" == "ok" && "$ENABLE_SIGNVERIFY" == "1" ]]; then
    keygen_series=""
    sign_series=""
    verify_series=""
    for i in $(seq 1 "$RUNS_SIGNVERIFY"); do
      bench_log="$TMP_DIR/bench_${candidate_id}_${i}.log"
      if run_with_timeout "./test/benchmark" "$BENCH_TIMEOUT_SEC" "$bench_log" "${candidate_id}:benchmark:${i}/${RUNS_SIGNVERIFY}"; then
        rc=0
      else
        rc=$?
      fi
      if [[ $rc -ne 0 ]]; then
        if [[ $rc -eq 124 ]]; then
          status="fail"
          err="benchmark_timeout"
        else
          status="fail"
          err="run_benchmark_failed"
        fi
        break
      fi
      out="$(cat "$bench_log")"
      if [[ -z "$out" ]]; then
        status="fail"
        err="run_benchmark_failed"
        break
      fi

      keygen_us="$(extract_bench_value "$out" "Generating keypair.. ")"
      sign_us="$(extract_bench_value "$out" "Signing..            ")"
      verify_us="$(extract_bench_value "$out" "Verifying..          ")"
      pk_bytes="$(extract_size_value "$out" "Public key size:")"
      sk_bytes="$(extract_size_value "$out" "Secret key size:")"
      sig_bytes="$(extract_size_value "$out" "Signature size:")"

      keygen_series="${keygen_series}${keygen_us}"$'\n'
      sign_series="${sign_series}${sign_us}"$'\n'
      verify_series="${verify_series}${verify_us}"$'\n'
    done

    if [[ "$status" == "ok" ]]; then
      read -r keygen_med keygen_p95 keygen_std <<< "$(calc_stats "$keygen_series")"
      read -r sign_med sign_p95 sign_std <<< "$(calc_stats "$sign_series")"
      read -r verify_med verify_p95 verify_std <<< "$(calc_stats "$verify_series")"
    fi
  fi

  if [[ "$status" == "ok" && "$ENABLE_SIGNVERIFY" != "1" ]]; then
    err="signverify_disabled"
  fi

  if [[ "$status" == "ok" && "$ENABLE_STARK" == "1" ]]; then
    if ! make -B PARAMS="$PARAMS_NAME" THASH="$THASH" CC="$CC_BIN" EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_stats >/dev/null 2>&1; then
      status="fail"
      err="build_stark_stats_failed"
    fi
  fi

  if [[ "$status" == "ok" && "$ENABLE_STARK" == "1" ]]; then
    pre_series=""
    core_series=""
    e2e_series=""
    sver_series=""
    for i in $(seq 1 "$RUNS_STARK"); do
      stark_log="$TMP_DIR/stark_${candidate_id}_${i}.log"
      if run_with_timeout "./test/poseidon2_stark_stats" "$STARK_TIMEOUT_SEC" "$stark_log" "${candidate_id}:stark:${i}/${RUNS_STARK}"; then
        rc=0
      else
        rc=$?
      fi
      if [[ $rc -ne 0 ]]; then
        if [[ $rc -eq 124 ]]; then
          status="fail"
          err="stark_timeout"
        else
          status="fail"
          err="run_stark_stats_failed"
        fi
        break
      fi
      line="$(tail -n 1 "$stark_log")"
      if [[ -z "$line" ]]; then
        status="fail"
        err="run_stark_stats_failed"
        break
      fi
      trace_calls="$(extract_stats_value "$line" "calls")"
      trace_lanes="$(extract_stats_value "$line" "lanes")"
      witness_rows="$(extract_stats_value "$line" "rows")"
      proof_bytes="$(extract_stats_value "$line" "proof")"
      proof_magic="$(extract_stats_value "$line" "magic")"
      proof_version="$(extract_stats_value "$line" "ver")"
      pre_ms="$(extract_stats_value "$line" "preprocess_ms")"
      core_ms="$(extract_stats_value "$line" "prove_core_ms")"
      e2e_ms="$(extract_stats_value "$line" "prove_e2e_ms")"
      sver_ms="$(extract_stats_value "$line" "verify_ms")"

      pre_series="${pre_series}${pre_ms}"$'\n'
      core_series="${core_series}${core_ms}"$'\n'
      e2e_series="${e2e_series}${e2e_ms}"$'\n'
      sver_series="${sver_series}${sver_ms}"$'\n'
    done
    if [[ "$status" == "ok" ]]; then
      read -r pre_med pre_p95 pre_std <<< "$(calc_stats "$pre_series")"
      read -r core_med core_p95 core_std <<< "$(calc_stats "$core_series")"
      read -r e2e_med e2e_p95 e2e_std <<< "$(calc_stats "$e2e_series")"
      read -r sver_med sver_p95 sver_std <<< "$(calc_stats "$sver_series")"
    fi
  fi

  if [[ "$status" == "ok" && "$ENABLE_STARK" != "1" ]]; then
    proof_magic="N/A"
    err="stark_disabled"
  fi

  append_row "$candidate_id,$n,$h,$d,$k,$a,$w,$q,$keygen_med,$keygen_p95,$keygen_std,$sign_med,$sign_p95,$sign_std,$verify_med,$verify_p95,$verify_std,$pk_bytes,$sk_bytes,$sig_bytes,$trace_calls,$trace_lanes,$witness_rows,$proof_bytes,$proof_magic,$proof_version,$pre_med,$pre_p95,$pre_std,$core_med,$core_p95,$core_std,$e2e_med,$e2e_p95,$e2e_std,$sver_med,$sver_p95,$sver_std,$status,$err"
done < "$INPUT_CSV"

echo "[M4] wrote $OUT_CSV"
echo "[M4] generated temp params file: $PARAMS_FILE"
