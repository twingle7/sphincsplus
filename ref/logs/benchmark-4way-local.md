# benchmark-4way local result

> Note:
> - case1/2 采集 `test/benchmark` 的 sign/verify 平均 us，并做 RUNS 轮统计。
> - case3 默认不强行绑定仓库内部实现，需通过 `CASE3_CMD` 注入盲签基准命令；未提供则记为 N/A。
> - case4 采集当前 Poseidon2 + Fischlin + STARK 路径分段时间统计。

## A. Sign/Verify（case1/case2）

| date | case | params | runs | sign_us_median | sign_us_p95 | sign_us_stddev | verify_us_median | verify_us_p95 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 2026-04-23 | case1_baseline_sign | sphincs-sha2-192s | 1 | 1089731.240 | 1089731.240 | 0.000 | 943.160 | 943.160 |
| 2026-04-23 | case2_poseidon2_sign | sphincs-poseidon2-192s | 1 | 35402570.440 | 35402570.440 | 0.000 | 27016.300 | 27016.300 |

## B. Blind/Fischlin（case3）

| date | case | runs | issue_s_median | issue_s_p95 | issue_s_stddev | prove_s_median | prove_s_p95 | verify_s_median |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 2026-04-23 | case3_baseline_fischlin_blind | 1 | N/A | N/A | N/A | N/A | N/A | N/A |

## C. Current Poseidon2 + Fischlin + STARK（case4）

| date | case | runs | preprocess_ms_median | preprocess_ms_p95 | preprocess_ms_stddev | prove_core_ms_median | prove_core_ms_p95 | prove_core_ms_stddev | prove_e2e_ms_median | prove_e2e_ms_p95 | prove_e2e_ms_stddev | verify_ms_median | verify_ms_p95 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2026-04-23 | case4_poseidon2_fischlin_stark | 1 | 28.999 | 28.999 | 0.000 | 3.467 | 3.467 | 0.000 | 32.469 | 32.469 | 0.000 | 0.447 | 0.447 |
