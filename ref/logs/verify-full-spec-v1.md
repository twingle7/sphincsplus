# verify-full-spec-v1（M9b 阶段 1+2 冻结版）

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

## 6. 阶段 2 约束集合（模块级语义 + 根值绑定检查）
- 约束 10：若 trace 中出现 `HASH_MESSAGE` 调用，其输出长度必须等于 `SPX_DGST_BYTES`（由 `FORS_MSG_BYTES + TREE_BYTES + LEAF_BYTES` 组成）
- 约束 11：`PRF_ADDR` 调用的地址类型必须属于 `{WOTSPRF, FORSPRF}`，且输出长度必须等于 `SPX_N`
- 约束 12：所有 `THASH_(SIMPLE/F/H/TL)` 调用满足：
  - `input_real_len >= SPX_N + SPX_ADDR_BYTES + SPX_N`
  - `output_real_len == SPX_N`
- 约束 13：模块覆盖性约束：
  - trace 中必须覆盖 `FORS` 相关地址类型（`FORSPRF/FORSTREE/FORSPK`）
  - trace 中必须覆盖 `WOTS+` 相关地址类型（`WOTSPRF/WOTS/WOTSPK`）
  - trace 中必须覆盖 `Merkle` 相关地址类型（`HASHTREE`）
- 约束 14：根值绑定结构性检查（阶段 2 硬约束）：
  - trace 中必须存在顶层 `HASHTREE`（`tree_height >= SPX_TREE_HEIGHT - 1`）的 `THASH_H/THASH_TL` 调用；
  - 破坏该高度结构后，模块约束必须检出违规。

## 6.1 阶段 3 细化（地址类型 / 域标签 / inblocks 一致性）
- 约束 15：`PRF_ADDR` 调用输入长度必须等于 `2*SPX_N + SPX_ADDR_BYTES`
- 约束 16：`THASH` 调用输入长度必须可被解析为 `SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N`
- 约束 17：`THASH` 语义域与 `inblocks` 一致：
  - `THASH_F <=> inblocks == 1`
  - `THASH_H <=> inblocks == 2`
  - `THASH_TL <=> inblocks >= 3`
- 约束 18：地址类型与 `THASH` 语义域兼容：
  - `WOTS` 仅允许 `THASH_F`
  - `WOTSPK/FORSPK` 仅允许 `THASH_TL`
- 约束 19：地址类型对应的 `tree_height` 边界必须正确：
  - `FORSTREE`：`tree_height <= SPX_FORS_HEIGHT`
  - `HASHTREE`：`tree_height <= SPX_TREE_HEIGHT`
- 约束 20：根值绑定约束：
  - 顶层 `HASHTREE` 的 `THASH_H/THASH_TL` 输出中，至少存在一个输出值与 `pk_root`（`pk` 后 `SPX_N` 字节）一致；
  - 若不存在候选输出或无匹配输出，判定为违规。

## 7. 验收口径（阶段 2）
- 在阶段 1 基础上，模块级语义约束全部满足时 `prove/verify` 通过；
- 在 trace 出现对应调用时，篡改 `PRF_ADDR` 地址类型、`HASH_MESSAGE` 输出长度后，模块约束可检出违规；
- 对“顶层 `HASHTREE` 高度”篡改，模块约束应检出违规；
- 在 trace 出现对应调用时，篡改 `WOTS` 域标签、`THASH_H` 输入块数后，模块约束应检出违规；
- 篡改 `pk_root` 后，`verify_full` 约束应检出违规（根值绑定被破坏）；
- 对真实验签路径，阶段 2 约束与 C 验签接受条件保持一致，不引入额外假阳性。
