# m17-consistency-report-v2（执行记录模板）

## 1. 目的
- 作为 M17 第二阶段执行记录页，统一记录测试矩阵、预期结果与本地实测结论。
- 支持发布前复核与论文附录引用。

## 2. 三角色交互演示
- 用例：`test/poseidon2_roles_interaction_v2`
- 核心期望：
  - 输出明确角色流：`[User] -> [Signer] -> [User] -> [Verifier]`；
  - `ShowProve/ShowVerify` 走 `v2-strict` 路径（proof 必须是 `pi_F_v2`）；
  - 首次验证 `ACCEPT`；
  - 篡改 `public_ctx` 后验证 `REJECT (expected)`；
  - 最终打印 `poseidon2_roles_interaction_v2: OK`。

## 3. 测试矩阵（M17 第二阶段）
| suite | command | expected | local_result |
|---|---|---|---|
| role-demo | `./test/poseidon2_roles_interaction_v2` | 退出码 0，含 ACCEPT/REJECT | TBD |
| blind-e2e | `./test/poseidon2_fischlin_blind_e2e_v2` | 退出码 0，输出 OK | TBD |
| show | `./test/poseidon2_show_v1` | 退出码 0，输出 OK | TBD |
| ffi | `./test/poseidon2_stark_ffi_v1` | 退出码 0，输出 OK | TBD |
| format | `./test/poseidon2_pi_f_format_v2` | 退出码 0，输出 OK | TBD |
| stats | `./test/poseidon2_stark_stats_v1` | 退出码 0，`magic/ver` 合法 | TBD |

## 4. 指标采集（与 benchmark-stark-v2 对齐）
- 记录字段：
  - `trace_calls/trace_lanes/witness_rows/proof_bytes/proof_magic/proof_version/prove_ms/verify_ms`
- 采集来源：
  - `poseidon2_stark_stats_v1` 标准输出。

## 5. 发布前一致性结论
- C 默认后端：`PASS/FAIL`（TBD）
- Rust 后端：`PASS/FAIL`（TBD）
- C/Rust 共同覆盖样本是否一致：`YES/NO`（TBD）
