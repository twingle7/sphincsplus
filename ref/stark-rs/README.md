# stark-rs Stub (M11-P2 并行)

本目录是 Rust STARK 后端的最小占位 crate，用于先冻结 C/Rust ABI 形状。

当前状态：
- 已导出 ABI 版本查询函数：
  - `spx_p2_rust_get_abi_version_v1`
- 已导出 prove/verify 占位函数（返回 `NOT_IMPLEMENTED`）：
  - `spx_p2_rust_generate_pi_f_v1`
  - `spx_p2_rust_verify_pi_f_v1`

下一步：
- 接入 Winterfell prover/verifier 真实实现；
- 将 `ffi_v1.c` 的内部实现从 C 骨架切换到 Rust 后端；
- 保持 `stark/ffi_v1.h` 外部 ABI 不变。
