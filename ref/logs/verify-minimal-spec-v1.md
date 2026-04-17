# verify-minimal-spec-v1（M9a 冻结版）

## 1. 目标
- 在不一次性覆盖完整 SPHINCS+ 语义的前提下，先约束 `verify_com` 的关键连接点正确性。
- 保证隐藏 witness `(sigma_com, trace)` 与公开 `(pk, com)` 之间的一致执行关系。

## 2. 最小语义边界
- 约束 1：`spx_p2_verify_com(pk, com, sigma_com) == 0`
- 约束 2：`spx_p2_trace_verify_com(trace_replay, pk, com, sigma_com) == 0`
- 约束 3：`trace_replay` 与 witness 中提供的 `trace` 完全一致（calls/lanes/meta）

## 3. Witness 与公开量
- 公开输入：
- `pk`
- `com`
- 私有 witness：
- `sigma_com`
- `trace`

## 4. 最小证明对象
- `verify_min_proof_v1 = (commitment, constraint_count, violation_count)`
- `commitment` 绑定 `pk || com || sigma_com || trace`（最小抗篡改绑定）

## 5. 验收标准
- 合法 witness 下 `prove/verify` 通过；
- 篡改 `sigma_com` 或 `trace` 任一关键字段后 `verify` 失败；
- 该模块不要求覆盖 `HASH_MESSAGE/FORS/WOTS/Merkle` 的完整高层语义。
