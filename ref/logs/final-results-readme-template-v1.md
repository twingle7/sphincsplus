# Final Results 索引（论文/答辩映射）

## 1. 使用方式
- 目标：把 `final-results-v1` 内文件快速映射到“论文章节”和“答辩页”。
- 页码字段采用建议位（`Pxx`），你可按最终 PPT 顺序替换。
- 引用顺序建议：先 `core-experiments` 讲系统闭环，再 `param-search` 讲参数优化与 M6 边界。

## 2. 论文映射总表
| 文件 | 主要用途 | 论文章节建议 | 答辩页建议 |
|---|---|---|---|
| `core-experiments/project-final-summary-v1.md` | 项目总结与最终结论 | 第1章 研究目标与贡献；第7章 总结 | P2-P3（总览） |
| `core-experiments/thesis-notes-stark-v2.md` | 叙事主线、图表建议、边界声明 | 第1章；第2章 系统设计；第7章 局限与未来工作 | P3-P4（叙事） |
| `core-experiments/release-checklist-v2.md` | 发布口径与验收清单 | 附录A 工程可复现与发布清单 | P5（验收口径） |
| `core-experiments/blind-sign-e2e-v2.md` | 盲签端到端流程证据 | 第5章 实验与验证（功能正确性） | P6（E2E） |
| `core-experiments/cross-backend-consistency-v1.md` | C/Rust 一致性结果 | 第5章 实验与验证（一致性） | P7（跨后端一致性） |
| `core-experiments/m17-consistency-report-v2.md` | M17 一致性阶段报告 | 第5章；附录B 回归明细 | P8（回归矩阵） |
| `core-experiments/benchmark-stark-v2.md` | STARK 指标主结果 | 第5章 实验与性能 | P9（性能主表） |
| `core-experiments/benchmark-stark-v2-local.md` | 本地 STARK 复现实验 | 附录B 复现细节 | P9 备份页 |
| `core-experiments/benchmark-4way-local.md` | 多维 benchmark（本地） | 附录B 复现细节 | P9 备份页 |
| `param-search/poseidon2-instantiation-spec-v1.md` | 参数搜索规则与筛选口径 | 第4章 参数设计与搜索方法 | P10（方法） |
| `param-search/params-search-raw-v1.csv` | 搜索原始候选集 | 第4章（数据来源） | P10 备份页 |
| `param-search/params-search-struct-pass-v1.csv` | 结构约束通过候选 | 第4章（结构筛选） | P10 备份页 |
| `param-search/params-security-eval-v1.csv` | 安全评估全量结果 | 第4章（安全筛选） | P11（安全筛选） |
| `param-search/params-security-pass-v1.csv` | 安全通过候选集 | 第4章（候选收缩） | P11 备份页 |
| `param-search/params-benchmark-v1-full.csv` | 候选基准测试全量 | 第5章（性能数据基表） | P12 备份页 |
| `param-search/params-signverify-finalists.csv` | 入围组签名/验签实测 | 第5章（入围对比） | P12（入围） |
| `param-search/params-m5-merged-v1.csv` | M5 合并数据基表 | 第5章（多指标联合） | P13 备份页 |
| `param-search/params-pareto-frontier-v1.csv` | Pareto 前沿点集 | 第5章（多目标优化） | P13（Pareto） |
| `param-search/params-pareto-nonfrontier-v1.csv` | 非前沿点集 | 第5章（对照） | P13 备份页 |
| `param-search/params-pareto-v1.md` | Pareto 文字结论 | 第5章（优化结论） | P13（结论） |
| `param-search/params-final-candidates-v1.md` | 最终推荐参数组 | 第5章（推荐方案） | P14（推荐组） |
| `param-search/params-compare-with-192s-v1.csv` | 与 192s 基线对比表 | 第5章（与基线对比） | P15（基线对比） |
| `param-search/params-candidate-rank-v1.csv` | 候选综合评分 | 第5章（综合排序） | P15 备份页 |
| `param-search/params-primary-delta-v1.csv` | 主推荐 vs 其它组差值 | 第5章（全维差异） | P15 备份页 |
| `param-search/fig-compare-sign-ms-v1.png` | 签名耗时图 | 第5章（性能图） | P16（图1） |
| `param-search/fig-compare-verify-ms-v1.png` | 验签耗时图 | 第5章（性能图） | P16（图2） |
| `param-search/fig-compare-sign-vs-zk-v1.png` | sign 与 zk 关系图 | 第5章（折中分析） | P16（图3） |
| `param-search/fig-compare-multimetric-common-v1.png` | 多指标归一化对比 | 第5章（综合对比） | P17（综合图） |
| `param-search/fig-compare-candidate-heatmap-v1.png` | 候选热力图 | 第5章（候选全局视图） | P17（热力图） |
| `param-search/params-budget-degradation-v1.csv` | M6 预算退化数据 | 第6章 安全边界与预算退化 | P18（M6数据） |
| `param-search/params-budget-degradation-v1.md` | M6 预算退化结论 | 第6章（结论） | P18（M6结论） |
| `param-search/params-security-claim-template-v1.md` | 谨慎表述模板 | 第6章（口径边界）；附录A | P19（边界声明） |
| `MANIFEST.txt` | 归档清单与可追溯性 | 附录A 数据与材料索引 | P20（材料索引） |

## 3. 代码与复现映射
| 文件 | 用途 | 论文章节建议 | 答辩页建议 |
|---|---|---|---|
| `scripts/search_params_poseidon2.py` | 参数候选生成 | 第4章 方法 | P10 备份页 |
| `scripts/eval_security_poseidon2.py` | 安全筛选计算 | 第4章 方法 | P11 备份页 |
| `scripts/collect_benchmark_params.sh` | 参数组 benchmark 采集 | 第5章 实验流程 | P12 备份页 |
| `scripts/analyze_pareto_poseidon2.py` | Pareto 与推荐组分析 | 第5章 多目标优化 | P13 备份页 |
| `scripts/plot_param_comparison.py` | 基线与多图对比生成 | 第5章 图表生成 | P16-P17 备份页 |
| `scripts/analyze_budget_degradation_poseidon2.py` | M6 预算退化计算 | 第6章 安全边界 | P18 备份页 |
| `scripts/collect_benchmark_4way.sh` | 4way benchmark 采集 | 第5章 工程性能 | P9 备份页 |
| `scripts/collect_benchmark_v2.sh` | STARK v2 benchmark 采集 | 第5章 工程性能 | P9 备份页 |
| `scripts/run_m17_regression.sh` | M17 回归入口 | 第5章 工程验证 | P8 备份页 |

## 4. 建议的答辩讲述顺序（20 页版本）
1. P2-P5：项目目标、主线、验收边界（`project-final-summary` + `thesis-notes` + `release-checklist`）。
2. P6-P9：系统闭环证据（E2E、一致性、benchmark）。
3. P10-P17：参数搜索方法、Pareto、推荐组、与基线多维对比。
4. P18-P19：M6 预算退化与安全表述边界。
5. P20：归档清单与复现入口（`MANIFEST` + scripts）。

## 5. 口径提醒（写作与答辩）
- “目标筛选达标”与“严格证明”必须显式区分。
- 预算退化结论属于 `proxy-v1` 筛选模型下界分析，不替代形式化证明。
- 任何“已证明 128-bit”表述，仅在具备完整证明链时使用。
