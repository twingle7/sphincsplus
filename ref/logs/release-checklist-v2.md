# release-checklist-v2（M17）

## 1. 功能项
- [ ] `show_prove/show_verify` 默认路径可运行（FFI 分派生效）。
- [ ] `v1` 历史样本可验证回放。
- [ ] `v2` 样本在 Rust 后端可生成与验证。
- [ ] M16 端到端盲签工程测试通过。
- [ ] 三角色交互演示（`User/Signer/Verifier`）输出符合预期。

## 2. 安全项
- [ ] `pi_F_v2` 不包含 `sigma_com` 明文。
- [ ] `public_ctx` 篡改可检出。
- [ ] `pi_f` 关键头字段篡改可检出。
- [ ] proof blob 篡改可检出。

## 3. 一致性项
- [ ] C 默认后端回归测试通过。
- [ ] Rust 后端回归测试通过。
- [ ] C/Rust 在共同覆盖样本上无接受/拒绝分歧。

## 4. 性能与可观测项
- [ ] 采集 `trace_calls/trace_lanes/witness_rows/proof_bytes/prove_ms/verify_ms`。
- [ ] 输出 `proof_magic/proof_version` 以确认后端与版本路径。
- [ ] benchmark 表格填入至少 1 组真实数据。

## 5. 文档项
- [ ] `下一步计划-v2.md` 状态同步到最新里程碑。
- [ ] `开发日志.md` 记录本轮改动、风险和测试命令。
- [ ] `benchmark-stark-v2.md` / `thesis-notes-stark-v2.md` 完整。
- [ ] `m17-consistency-report-v2.md` 填写完成并可复核。
