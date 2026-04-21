# C -> Rust 约束映射表 v1（执行中）

## 1. 说明
- 目的：把 C 侧 `air_verify_full` 语义逐项映射到 Rust AIR/验证逻辑。
- 状态标记：
  - `done`：已在 Rust 侧有对应实现；
  - `wip`：进行中；
  - `todo`：尚未落地。

## 2. 映射项
| C 侧语义项 | C 参考实现 | Rust 对应位置 | 状态 |
|---|---|---|---|
| `verify_com(pk, com, sigma)` 有效性 | `air_verify_full.c` | `ffi_v2_strict` 前置验签 | done |
| `trace_verify_com` 重放一致性 | `air_verify_full.c` | Rust statement 派生统一 + trace_digest/witness_rows/trace_calls 绑定到 commitment | done |
| witness row 重建一致性 | `witness_builder.c` + `air_verify_full.c` | Rust commitment 绑定 `witness_rows` + 篡改拒绝测试 | done |
| 模块约束：PRF/THASH/HASH_MESSAGE | `air_verify_full.c` | `ffi_v2_strict` 生成前执行 `verify_full_air_eval_constraints_v1` 守卫 | done（守卫级） |
| 根绑定（top merkle root == pk root） | `air_verify_full.c` | 同上（`verify_full_air_eval_constraints_v1` 内含 root binding 检查） | done（守卫级） |
| proof bytes + statement -> commitment 一致性 | `pi_F_v2` 规范 + verify | Rust verify 重算 `H(proof_bytes, public_input_digest, ctx_binding)` | done |
| `public_ctx` 绑定 | `ctx_binding` 校验 | Rust verify 重算 `ctx_binding` | done |

## 3. 下一步执行顺序
1. 将“守卫级 done”升级为“Rust AIR 内生 done”（避免仅依赖生成端预检查）；
2. 对模块约束与根绑定新增跨后端一致性回归样本集（已新增 v1：valid/tamper_sig/tamper_com）；
3. 完成 benchmark 与发布复核实测填表（M17 第三阶段）。
