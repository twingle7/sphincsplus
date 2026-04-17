# verify-full-spec-v1（M9b 阶段 1 冻结版）

## 1. 目标
- 在 M9a 的最小连接点约束之上，扩展为“完整验签闭环约束”：
  - `verify_com` 接受；
  - `trace_verify_com` 接受；
  - witness `trace` 与重放 `trace` 完全一致；
  - witness `rows` 与 `trace -> rows` 规范展开一致；
  - `hashcall_air` 子约束无违规。

## 2. 公开输入与私有 witness
- 公开输入：
  - `pk`
  - `com`
- 私有 witness：
  - `sigma_com`
  - `trace`
  - `rows`

## 3. 阶段 1 约束集合
- 约束 1：`spx_p2_verify_com(pk, com, sigma_com) == 0`
- 约束 2：`spx_p2_trace_verify_com(trace_replay, pk, com, sigma_com) == 0`
- 约束 3：`trace == trace_replay`
- 约束 4：`trace.dropped_calls == 0 && trace.dropped_lanes == 0`
- 约束 5：每个 `HashCall` 的 `domain_tag` 必须属于允许集合
- 约束 6：每个 `HashCall` 的 `input/output lane_count` 与 `real_len` 的 8-byte lane 映射一致
- 约束 7：`row_count` 与 `spx_p2_witness_count_rows_v1(trace)` 一致
- 约束 8：`rows` 与 `spx_p2_witness_build_rows_v1(trace)` 重建结果逐行一致
- 约束 9：`spx_p2_hashcall_air_eval_constraints_v1(trace, rows, row_count)` 无违规

## 4. 证明对象
- `verify_full_proof_v1 = (commitment, constraint_count, violation_count)`
- `commitment` 绑定：
  - `pk || com || sigma_com`
  - `trace` 全量元数据与 calls/lanes
  - `row_count || rows`

## 5. 验收口径（阶段 1）
- 合法 witness 下 `prove/verify` 通过；
- 篡改 `sigma_com`、`rows`、`trace` 关键字段或 dropped 元数据后，`verify` 失败；
- 与 M9a 相比，阶段 1 已覆盖 trace/rows/hashcall 的完整闭环一致性。

## 6. 阶段 2 预留
- 本文档仅冻结 M9b 阶段 1。
- M9b 阶段 2 将继续加入 `HASH_MESSAGE/FORS/WOTS+/Merkle` 的模块级状态约束与最终根值绑定约束。
