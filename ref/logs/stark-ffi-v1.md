# stark-ffi-v1（M11-P1）

## 1. 目标
- 定义 C/Rust 之间稳定的 `pi_F` 生成与验证 ABI 边界。
- 在不引入 Rust 依赖的前提下，先在 C 侧完成接口与错误码收敛，便于后续后端替换。

## 2. ABI 版本
- `SPX_P2_STARK_FFI_ABI_VERSION_V1 = 1`
- 通过 `spx_p2_ffi_get_abi_version_v1()` 读取，调用方可据此做版本协商。

## 3. 错误码
- `SPX_P2_FFI_OK = 0`
- `SPX_P2_FFI_ERR_NULL = -1`
- `SPX_P2_FFI_ERR_INPUT = -2`
- `SPX_P2_FFI_ERR_BUFFER_SMALL = -3`
- `SPX_P2_FFI_ERR_PROVE = -4`
- `SPX_P2_FFI_ERR_VERIFY = -5`

## 4. 数据结构
- `spx_p2_ffi_blob_v1`：
  - `data/len/cap` 三元组，承载 proof blob。
- `spx_p2_ffi_public_inputs_v1`：
  - `pk/com/public_ctx/public_ctx_len`
- `spx_p2_ffi_private_witness_v1`：
  - `sigma_com`（作为 prover 私有 witness 保留）

## 5. 接口
- `spx_p2_ffi_generate_pi_f_v1(...)`：
  - 输入 `public + witness`，输出 `proof blob`。
- `spx_p2_ffi_verify_pi_f_v1(...)`：
  - 输入 `public + proof blob`，输出验证结果。

## 6. 当前实现说明
- 当前实现后端仍调用 C 侧 `prover_v1/verifier_v1`，属于 FFI 形状冻结阶段。
- 后续接 Rust/Winterfell 时，只需替换接口内部实现，不破坏外部 ABI。

## 7. 后续升级点
- 将 `sigma_com` 从 **proof blob 序列化输出** 中移除（但继续作为 prover 私有 witness 输入）。
- 增加错误码细分（格式错误、约束错误、后端内部错误）。
- 增加字节序与结构对齐的跨语言一致性测试（C/Rust 双向）。
