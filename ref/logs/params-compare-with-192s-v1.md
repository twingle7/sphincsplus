# 参数组多指标对比与结论（含 192s 基线）

## 1. 对比对象与指标
- 基线：`sphincs-sha2-192s`、`sphincs-poseidon2-192s`。
- 候选：M5 Pareto 前沿（6 组）与三组推荐高亮。
- 指标：`sig_bytes`、`sign_ms`、`verify_ms`、`witness_rows`、`prove_e2e_ms`。

## 2. 全量指标表

| group | candidate_id | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms | source |
|---|---:|---:|---:|---:|---:|---:|---|
| sha2-192s baseline | - | 16224 | 1089.731 | 0.943 | N/A | N/A | benchmark-4way+params |
| cand_41 (rec) | 41 | 6800 | 32652.622 | 19.275 | 21910 | 22.169 | M5 frontier |
| cand_61 | 61 | 8032 | 32833.710 | 18.636 | 20436 | 21.675 | M5 frontier |
| cand_29 | 29 | 7328 | 33461.011 | 18.509 | 21844 | 22.637 | M5 frontier |
| cand_9 (rec) | 9 | 6800 | 34229.064 | 19.105 | 19930 | 22.654 | M5 frontier |
| cand_13 (rec) | 13 | 7248 | 34348.821 | 18.663 | 20294 | 22.540 | M5 frontier |
| poseidon2-192s baseline | - | 16224 | 35402.570 | 27.016 | N/A | N/A | benchmark-4way+params |
| cand_2425 | 2425 | 6880 | 66153.005 | 18.861 | 19995 | 21.800 | M5 frontier |

## 3. 候选综合评分（性能优先）
- 权重：`sig_bytes 0.10 + sign_ms 0.35 + verify_ms 0.20 + witness_rows 0.15 + prove_e2e_ms 0.20`。

| rank_perf | candidate_id | score_perf | score_equal | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 61 | 0.173385 | 1.426757 | 8032 | 32833.710 | 18.636 | 20436 | 21.675 |
| 2 | 13 | 0.298580 | 1.682706 | 7248 | 34348.821 | 18.663 | 20294 | 22.540 |
| 3 | 9 | 0.372084 | 1.825125 | 6800 | 34229.064 | 19.105 | 19930 | 22.654 |
| 4 | 29 | 0.392830 | 2.402004 | 7328 | 33461.011 | 18.509 | 21844 | 22.637 |
| 5 | 41 | 0.450919 | 2.504597 | 6800 | 32652.622 | 19.275 | 21910 | 22.169 |
| 6 | 2425 | 0.478860 | 1.684975 | 6880 | 66153.005 | 18.861 | 19995 | 21.800 |

## 4. 各维度最优参数组（候选内）
| 维度 | 最优 candidate_id | 最优值 |
|---|---:|---:|
| sig_bytes | 9 | 6800 |
| sign_ms | 41 | 32652.622 |
| verify_ms | 29 | 18.509 |
| witness_rows | 9 | 19930 |
| prove_e2e_ms | 61 | 21.675 |

## 5. 主推荐组（candidate_id=61）与其它组全维度差值
- 说明：`delta_*_pct_vs_primary` 为相对主推荐组百分比，负值代表该维度优于主推荐组。

| candidate_id | sig_bytes | sign_ms | verify_ms | witness_rows | prove_e2e_ms | delta_sig_pct_vs_primary | delta_sign_pct_vs_primary | delta_verify_pct_vs_primary | delta_witness_pct_vs_primary | delta_prove_pct_vs_primary |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9 | 6800 | 34229.064 | 19.105 | 19930 | 22.654 | -15.34 | 4.25 | 2.52 | -2.48 | 4.52 |
| 13 | 7248 | 34348.821 | 18.663 | 20294 | 22.540 | -9.76 | 4.61 | 0.14 | -0.69 | 3.99 |
| 29 | 7328 | 33461.011 | 18.509 | 21844 | 22.637 | -8.76 | 1.91 | -0.68 | 6.89 | 4.44 |
| 41 | 6800 | 32652.622 | 19.275 | 21910 | 22.169 | -15.34 | -0.55 | 3.43 | 7.21 | 2.28 |
| 61 | 8032 | 32833.710 | 18.636 | 20436 | 21.675 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| 2425 | 6880 | 66153.005 | 18.861 | 19995 | 21.800 | -14.34 | 101.48 | 1.21 | -2.16 | 0.58 |

## 6. 最终结论与参数组
- 主推荐参数组：`candidate_id=61`（性能优先综合评分第 1）。
- 相比 `poseidon2-192s`：`sign_ms` 改善约 `7.26%`，`verify_ms` 改善约 `31.02%`。
- 若你更看重最小签名大小：保持 `candidate_id=41`。
- 若你更看重最小约束规模：保持 `candidate_id=9`。

## 7. 图表清单
- 签名时间对比：`fig-compare-sign-ms-v1.png`
- 验签时间对比：`fig-compare-verify-ms-v1.png`
- Sign vs ZK 散点：`fig-compare-sign-vs-zk-v1.png`
- 通用三指标归一化柱状图：`fig-compare-multimetric-common-v1.png`
- 候选五指标热力图：`fig-compare-candidate-heatmap-v1.png`
