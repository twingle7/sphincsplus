# release-checklist-v2（M17）

## 1. 功能项
- [x] `show_prove/show_verify` 默认路径可运行（FFI 分派生效）。
- [x] `v1` 历史样本可验证回放。
- [x] `v2` 样本在 Rust 后端可生成与验证。
- [x] M16 端到端盲签工程测试通过。
- [x] 三角色交互演示（`User/Signer/Verifier`）输出符合预期。

## 2. 安全项
- [x] `pi_F_v2` 不包含 `sigma_com` 明文。
- [x] `public_ctx` 篡改可检出。
- [x] `pi_f` 关键头字段篡改可检出。
- [x] proof blob 篡改可检出。

## 3. 一致性项
- [x] C 默认后端回归测试通过。
- [x] Rust 后端回归测试通过。
- [x] C/Rust 在共同覆盖样本上无接受/拒绝分歧。
- [x] `poseidon2_cross_backend_consistency` 样本集（v1）全部通过。

## 4. 性能与可观测项
- [x] 采集 `trace_calls/trace_lanes/witness_rows/proof_bytes/prove_ms/verify_ms`。
- [x] 输出 `proof_magic/proof_version` 以确认后端与版本路径。
- [x] benchmark 表格填入至少 1 组真实数据。
- [x] `scripts/collect_benchmark_v2.sh` 输出 `benchmark-stark-v2-local.md` 并归档。

## 5. 文档项
- [x] `下一步计划-v2.md` 状态同步到最新里程碑。
- [x] `开发日志.md` 记录本轮改动、风险和测试命令。
- [x] `benchmark-stark-v2.md` / `thesis-notes-stark-v2.md` 完整。
- [x] `m17-consistency-report-v2.md` 填写完成并可复核。

## 6. 剩余技术债（发布后继续）
- [x] 将 C guard 中“模块级核心约束”内生到 Rust AIR（已完成 counters/root_hint/module_acc + PRF/THASH/HMSG/ADDR 分项累积 + THASH/PRF/HMSG 规则耦合累积 + 跨规则 rule_mix 耦合 + THASH/PRF_ADDR/HASH_MESSAGE/profile 白名单约束 的 AIR 内生绑定）。

## 7. 发布后可选增强（非阻塞）
- [ ] 继续降低规则 hint 占比，向更强“状态列原生约束”迁移。
- [ ] 在保证稳定通过前提下，逐步提升 verify 策略门限并复测性能。
