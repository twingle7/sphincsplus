# STARK FFI v2 迁移说明（M15）

## 1. 目标
- 在保持 `ffi_v1` ABI 不变的前提下，完成默认 `pi_F` 输出路径向 `v2` 迁移。
- 验证路径兼容 `v1/v2` 双版本，保障历史样本可回放。

## 2. 本轮策略
- `show` 层默认 prove/verify 改为统一走 `ffi_v1`。
- `ffi_v1` verify 增加 proof 版本分派：
  - `magic == PFP1`：走 C 侧 `verifier_v1`（兼容旧对象）；
  - `magic == PFP2`：走 Rust 后端验证（开启 `SPX_P2_USE_RUST_STARK` 时）；
  - 其它 magic：拒绝。
- `ffi_v1` generate 保持原 ABI：
  - Rust 后端启用时默认产出 `pi_F_v2`；
  - 未启用 Rust 后端时维持 v1 生成能力。

## 3. 兼容性语义
- 生成默认：跟随后端能力，优先 `v2`。
- 验证兼容：始终兼容 `v1`，并在 Rust 后端开启时支持 `v2`。
- 该策略避免了 ABI 破坏，同时支持渐进切换与回滚。

## 4. 已知边界
- 未启用 Rust 后端时，`v2` proof 的验证能力受限（当前 C 侧不提供 `v2` 完整 verifier）。
- M15 完成的是“默认路径切换 + 兼容分派”；M16/M17 继续推进端到端与发布收口。
