# M5 最终推荐参数 v1

## 1. 推荐规则
- 最小签名：按 `sig_bytes` 升序。
- 最小约束：按 `witness_rows` 升序。
- 综合平衡：按四目标归一化总分最小。

## 2. 推荐结果
- 最小签名：candidate_id=41 (n=16, h=60, d=6, k=22, a=6, w=16, q=65536; sig_bytes=6800, sign_ms=32652.622, verify_ms=19.275, witness_rows=21910, prove_e2e_ms=22.169)
- 最小约束：candidate_id=9 (n=16, h=60, d=6, k=14, a=10, w=16, q=65536; sig_bytes=6800, sign_ms=34229.064, verify_ms=19.105, witness_rows=19930, prove_e2e_ms=22.654)
- 综合平衡：candidate_id=13 (n=16, h=60, d=6, k=14, a=12, w=16, q=65536; sig_bytes=7248, sign_ms=34348.821, verify_ms=18.663, witness_rows=20294, prove_e2e_ms=22.540)

## 3. 说明
- 推荐候选均来自 Pareto 前沿，并且满足 M3 安全通过 + M4 实测可用。
- 详细候选与淘汰原因见配套 CSV 与 Pareto 文档。
