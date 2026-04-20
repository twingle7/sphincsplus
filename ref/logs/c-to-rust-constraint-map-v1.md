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
| `trace_verify_com` 重放一致性 | `air_verify_full.c` | Rust prove/verify statement 绑定 | wip |
| witness row 重建一致性 | `witness_builder.c` + `air_verify_full.c` | Rust 侧等价 witness 约束 | todo |
| 模块约束：PRF/THASH/HASH_MESSAGE | `air_verify_full.c` | Rust AIR transition/辅助约束 | todo |
| 根绑定（top merkle root == pk root） | `air_verify_full.c` | Rust public input/约束绑定 | todo |
| proof bytes -> commitment 一致性 | `pi_F_v2` 规范 + verify | Rust verify 重算 commitment | done |
| `public_ctx` 绑定 | `ctx_binding` 校验 | Rust verify 重算 `ctx_binding` | done |

## 3. 下一步执行顺序
1. 完成 trace replay 语义在 Rust 侧的可验证约束化；
2. 引入 witness rows 等价重建检查；
3. 分模块补齐 PRF/THASH/HASH_MESSAGE/MERKLE；
4. 对齐根绑定并做跨后端一致性回归。
