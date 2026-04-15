# stark-proof-spec-v1（M5 冻结版）

## 1. 目的
- 冻结 v1 的证明边界与对象可见性。
- 明确 v1 与 v0 的职责分层，避免继续混用公开签名对象语义。
- 为 M6（witness 格式）与后续 AIR 实现提供唯一上游约束。

## 2. v1 目标语句
- 存在私有见证 `(m, r, sigma_com, trace, aux)`，满足：
- `com = Commit(m || r)`
- `Verify(pk, com, sigma_com) = 1`
- `trace` 来自 `spx_p2_trace_verify_com(trace, pk, com, sigma_com)` 的一致执行
- `trace` 与既有 `HashCall` 规范、编码规则、padding 规则一致
- 对外验证流程不直接公开 `sigma_com`

## 3. 可见性边界
- 公开输入（v1）：
- `pk`
- `com`
- `public_ctx`（v1 最小实现冻结为空）
- 私有见证（v1）：
- `m`
- `r`
- `sigma_com`
- `trace`
- `aux`（v1 最小实现冻结为空）

## 4. 对象模型冻结
- 对外展示对象（v1）：
- `Show_v1 = (com, pi_F, public_ctx)`
- 内部凭证材料（v1）：
- `Cred_v1_internal = (m, r, com, sigma_com, trace, aux)`

强约束：
- v1 外部对象中不得出现 `sigma_com`。
- 禁止复用 `spx_p2_bsig_public` 作为 v1 对外对象。
- `verify_com / trace_verify_com` 在 v1 中仅作为 prover 内部 helper。

## 5. 接口冻结（M5 范围）
- `spx_p2_show_v1`：v1 对外对象类型
- `spx_p2_cred_v1_internal`：v1 内部凭证类型
- `spx_p2_show_from_internal_v1(...)`：从内部凭证构造展示对象（边界层）
- `spx_p2_show_verify_shape_v1(...)`：仅做 v1 对象形状约束检查（非 STARK 验证）

说明：
- M5 不实现真实 STARK 证明验证；
- 真实证明构造/验证在 M10 执行；
- 本阶段目标是“边界冻结”，不是“密码学终验”。

## 6. 版本关系声明
- v0：公开 `sigma_com` 的过渡原型（继续保留用于兼容测试）。
- v1：隐藏 `sigma_com` 的正式展示版（后续主线）。
- 两者共享底层 helper（commit/verify_com/trace_verify_com/编码）但外部对象与验证语义严格分离。

## 7. M5 验收标准
- 文档中不再出现“v1 公开 sigma_com”的口径。
- 代码层存在独立 `show_poseidon2_v1.*` 接口与对象，不复用 v0 外部对象。
- 通过边界测试：v1 对外对象可序列化/校验形状，且不含 `sigma_com` 字段。
