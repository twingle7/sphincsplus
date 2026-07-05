# stark-rs（M11 并行）

本目录是 Rust STARK 后端 crate，用于并行推进真实 STARK 证明路径。

当前状态：
- 已导出 ABI 版本查询函数：
  - `spx_p2_rust_get_abi_version_v1`
- 已导出 prove/verify 函数，并实现基于 Winterfell 的真实 STARK proof：
  - `spx_p2_rust_generate_pi_f_v1`
  - `spx_p2_rust_verify_pi_f_v1`
- 当前实现输出 `pi_F_v2` 编码，并绑定
  - `pk/pk_E/com/m_pub/public_ctx/sigma_C/statement_version`
  - `framework_id = Fischlin-Strict`
  - `signature_system_id = Poseidon2-SPHINCS+-like`
- 当前仍处于“与 C `verify_full` 逐项约束等价”收敛阶段，后续继续扩展 AIR 约束覆盖。

下一步：
- 将 C `verify_full` 的模块约束逐项映射到 Rust AIR 并做同语义回归；
- 完成 `show` 层默认 `pi_F_v2` 输出切换；
- 与 C 侧 final `stark/ffi.h` 接口保持兼容。
