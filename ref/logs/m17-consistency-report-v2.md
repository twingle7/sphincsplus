# m17-consistency-report-v2（执行记录模板）

## 1. 目的
- 作为 M17 第二阶段执行记录页，统一记录测试矩阵、预期结果与本地实测结论。
- 支持发布前复核与论文附录引用。

## 2. 三角色交互演示
- 用例：`test/poseidon2_roles_interaction`
- 核心期望：
  - 输出明确角色流：`[User] -> [Signer] -> [User] -> [Verifier]`；
  - `ShowProve/ShowVerify` 走 `v2-strict` 路径（proof 必须是 `pi_F_v2`）；
  - 首次验证 `ACCEPT`；
  - 篡改 `public_ctx` 后验证 `REJECT (expected)`；
  - 最终打印 `poseidon2_roles_interaction test: OK`。

## 3. 测试矩阵（M17 第三阶段）
| suite | command | expected | local_result |
|---|---|---|---|
| role-demo | `./test/poseidon2_roles_interaction` | 退出码 0，含 ACCEPT/REJECT | PASS（本地脚本回归） |
| blind-e2e | `./test/poseidon2_fischlin_blind_e2e` | 退出码 0，输出 OK | PASS（本地脚本回归） |
| show | `./test/poseidon2_show_v1` | 退出码 0，输出 OK | PASS（历史回归） |
| ffi | `./test/poseidon2_stark_ffi_v1` | 退出码 0，输出 OK | PASS（历史回归） |
| format | `./test/poseidon2_pi_f_format` | 退出码 0，输出 OK | PASS（历史回归） |
| stats | `./test/poseidon2_stark_stats` | 退出码 0，`magic/ver` 为 final v2 | PASS（本地脚本回归） |
| binding | `./test/poseidon2_statement_binding` | 退出码 0，篡改 statement 拒绝 | PASS（本地脚本回归） |
| replay | `./test/poseidon2_trace_replay_binding` | 退出码 0，篡改 commitment/proof 拒绝 | PASS（本地脚本回归） |
| c-guard | `./test/poseidon2_verify_full_guard` | 退出码 0，篡改 trace 触发 violations | PASS（本地脚本回归） |
| cross-backend | `./test/poseidon2_cross_backend_consistency` | 退出码 0，C/Rust 结论一致 | PASS（本地脚本回归） |

## 3.1 自动化入口
- 回归脚本：`scripts/run_m17_regression.sh`
- 指标采集：`scripts/collect_benchmark_v2.sh`
- 本地采集产物：`logs/benchmark-stark-v2-local.md`

## 4. 指标采集（与 benchmark-stark-v2 对齐）
- 记录字段：
  - `trace_calls/trace_lanes/witness_rows/proof_bytes/proof_magic/proof_version/prove_ms/verify_ms`
- 采集来源：
  - `poseidon2_stark_stats` 标准输出。

## 5. 发布前一致性结论
- C 默认后端：`PASS`
- Rust 后端：`PASS`
- C/Rust 共同覆盖样本是否一致：`YES`
