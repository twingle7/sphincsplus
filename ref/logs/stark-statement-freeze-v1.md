# STARK Statement Freeze v1

## 1. 冻结目标
- 固定 Rust prove/verify 双侧使用的 statement 派生口径，避免后续语义漂移。

## 2. 冻结字段
- `statement_version`: `1`（当前对应 `verify_full_v1` 语义包）。
- `public_input_digest` 派生输入：
  - `pk`
  - `com`
  - `public_ctx`
  - `statement_version (LE bytes)`
- `ctx_binding` 派生输入：
  - `public_ctx`
- `bind_seed` 派生输入：
  - `public_input_digest`
  - `ctx_binding`

## 3. 证明对象绑定
- `commitment` 必须由 `proof_bytes` 派生并在 verify 端重算一致。
- `flags/proof_system_id/statement_version` 作为格式 + 语义前置校验。

## 4. 必测篡改项
- 篡改 `public_ctx` -> verify 拒绝。
- 篡改 `public_input_digest` -> verify 拒绝。
- 篡改 `proof_bytes` 或 `commitment` -> verify 拒绝。
- 篡改 `statement_version` -> verify 拒绝。

## 5. 兼容策略
- `final` 无版本号接口仅接受 `pi_F_v2`；
- 历史 `v1` 对象仅允许走 `*_compat` 路径。
