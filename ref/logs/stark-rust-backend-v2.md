# Rust STARK 后端 v2（M14）

## 1. 目标
- 将 Rust 后端从“单模块 proof blob”升级为可对接 `pi_F_v2` 的证明/验证路径。
- 保持 `ffi_v1` 外部 ABI 不变，内部输出切换为 `pi_F_v2` 编码。

## 2. 本轮实现范围
- `stark-rs/src/lib.rs`：
  - 生成路径改为输出 `pi_F_v2` 结构（`magic/version/header_len/total_len/proof_system_id/statement_version`）。
  - 增加 `public_input_digest`、`ctx_binding`、`commitment` 三类绑定字段。
  - proof payload 使用 Winterfell 真实 proof bytes。
- 验证路径：
  - 严格解码并校验 `pi_F_v2` 格式；
  - 重算 `public_input_digest` 与 `ctx_binding`，不一致即拒绝；
  - 对 proof bytes 执行 Winterfell 验证并给出接受/拒绝结果。

## 3. 与 M13 的对齐
- 对齐 `pi_F-格式规范-v2.md` 的字段布局与保留区规则。
- `reserved[2]` 强制全零，防止隐式扩展破坏兼容语义。
- `pi_F_v2` 不包含 `sigma_com` 明文字段。

## 4. 与 `verify_full` 的语义关系
- 当前 Rust 后端已完成：
  - `pk/com/public_ctx/statement_version` 绑定；
  - proof 真实性校验与格式层完整校验；
  - 与 C 侧 FFI 的统一接口行为。
- 后续继续细化方向：
  - 将 C 侧 `verify_full` 的模块约束逐项映射到 Rust AIR 约束列；
  - 实现与 C `verify_full` 完整同语义的约束等价。

## 5. M14 验收口径（本仓库阶段）
- 可通过 `SPX_P2_USE_RUST_STARK` 启用 Rust 后端 prove/verify。
- 生成对象为 `pi_F_v2` 编码，篡改格式/上下文/proof 后验证拒绝。
- C/Rust 统一使用同一 FFI ABI，便于后续 M15 默认切换。
