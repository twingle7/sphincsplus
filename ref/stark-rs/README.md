# stark-rs（M11 并行）

本目录是 Rust STARK 后端 crate，用于并行推进真实 STARK 证明路径。

当前状态：
- 已导出 ABI 版本查询函数：
  - `spx_p2_rust_get_abi_version_v1`
- 已导出 prove/verify 函数，并实现**单模块真实 STARK proof**（Winterfell）：
  - `spx_p2_rust_generate_pi_f_v1`
  - `spx_p2_rust_verify_pi_f_v1`
- 当前证明语句是“与 `pk/com/public_ctx` 绑定的确定性工作轨迹正确性”，用于打通真实 STARK 生成/验证链路。
- 当前尚未覆盖完整 `verify_com` 语义约束，属于模块级真实 proof 落地阶段。

下一步：
- 将证明语句从“单模块工作轨迹”扩展到 `verify_full` 语义对应的真实约束系统；
- 将 `ffi_v1.c` 的内部实现切换到 Rust 后端（`SPX_P2_USE_RUST_STARK`）；
- 保持 `stark/ffi_v1.h` 外部 ABI 不变。
