# protocol-v0（M1 冻结版）

## 1. 目标与范围
- 本文档冻结 v0 阶段协议语句与对象边界，作为实现与测试唯一依据。
- v0 目标是验证“签发者仅签 `com`”的可运行闭环，并为后续 Fischlin/STARK 对接提供稳定接口。
- v0 不追求经典可去盲代数语义，也不以性能接近 SHA2 后端为验收目标。

## 2. 目标语句
- 唯一合法语句：存在 `(m, r, sigma_com)`，满足：
- `com = Commit(m || r)`
- `Verify(pk, com, sigma_com) = 1`

## 3. 签名对象
- v0 统一签名对象：`BSig = (com, sigma_com, pi_F)`。
- 约束：签发者只对 `com` 签名，不直接签 `m`。
- `pi_F` 在 v0 中作为 Fischlin 层占位证明承诺，先用于“对象绑定与接口对齐”，后续升级为正式知识证明对象。

## 4. 接口冻结
- `spx_p2_commit(com, m, mlen, r, rlen)`
- `spx_p2_verify_com(pk, com, sigma_com)`
- `spx_p2_trace_verify_com(trace, pk, com, sigma_com)`
- `spx_p2_encode_bytes_to_lanes(out_lanes, out_count, in_bytes, in_len)`
- `spx_p2_bsig_issue(ctx, sk, m, mlen, r, rlen)`
- `spx_p2_bsig_prove(ctx, pk)`
- `spx_p2_bsig_verify(public_bsig, pk)`

## 5. 验证路径约束
- `trace_verify_com` 必须复用 `verify_com`，禁止双实现分叉。
- 所有哈希记录必须由统一 `HashCall` 序列导出，禁止 bytes/felts 二义表示。
- 字节到 lane 映射必须唯一采用 little-endian 规则。

## 6. v0 验收标准
- 文档中不出现“签 `m`”与“签 `com`”并存冲突。
- 代码中 `verify_com` 与 `trace_verify_com` 结果一致。
- 端到端可执行 `Commit -> Issue(Sign com) -> ProveKnowledge -> Verify`。
- 在不公开 `m,r` 的前提下，仅凭 `(com, sigma_com, pi_F)` 可完成对象验证，且本地可复放 trace 供 witness 对接。
