# Fischlin + Poseidon2 + STARK 完整闭环评估与里程碑（v2）

> 状态标记：`✅ 已完成` / `🟡 进行中` / `⬜ 未开始`  
> 本文用于反映 strict 主链真实进展，并以“Fischlin 全内生语义”作为唯一终态标准。

## 1. 目标语句（冻结口径）
- 公开输入：`x = (pk_sig, pk_E, m_pub, ctx_pub)`
- 见证：`w = (r, omega2, c, sigma')`
- 关系：
  - `c = Com(m_pub; r)`
  - `Verify(pk_sig, c, sigma') = 1`
  - `C = Enc(pk_E, c || sigma'; omega2)`
- 最终验证语义：验证器仅基于 `Sigma=(C, pi)` 与 `x` 判定“存在见证使三关系同时成立”。

## 2. 当前状态总览（截至本次更新）
- `✅` strict prove/verify 主链可运行，`sigma_C + pi_f_v2` 已稳定工作。
- `✅` statement digest 已绑定 `pk_E / sigma_c / public_ctx`，prove/verify 同步。
- `✅` M20-7 已完成第一阶段增强：`Verify(pk,c,sigma')` 已从仅 prefix 绑定，提升为“prefix + `sigma_c` tail 与 `public_ctx` 规则化 AIR 关系”。
- `🟡` `Verify(pk,c,sigma')` 仍是工程化可约束近似，不是完整 Fischlin transcript/challenge 内生约束。
- `⬜` `Com(m_pub; r)` 关系尚未进入 STARK 主约束（`m_pub/r` 仍未完整纳入 strict witness/trace）。
- `🟡` `Enc(pk_E, c||sigma';omega2)` 已从 `EncTag` 占位切换到 m20 PKE-tail 公式，但尚未完全下沉为 AIR 内生约束主导。

## 3. 已完成项（保留）

### 3.1 工程主链
- `✅` strict 路径打通：`show -> ffi(strict) -> relation_migration -> rust prove/verify`。
- `✅` 错误码分层与 strict 关系迁移层已建立（`INPUT/BACKEND/PROVE/VERIFY`）。
- `✅` M19/M20 相关门禁已覆盖部分篡改场景（`pk_E/omega2/C/public_ctx`）。

### 3.2 M20-7 第一阶段（本轮新增）
- `✅` AIR 中新增对 `public_ctx` 与 `sigma_c` tail limbs 的规则化约束，不再仅做 prefix 绑定。
- `✅` `PublicInputs` / `WorkAir` / trace 列与 assertions 已同步扩展，prove 与 verify 两侧一致接线。
- `✅` 该增强已满足“向全内生推进”的阶段性目标，但不代表 Fischlin 完整关系已闭环。

## 4. 仍存在的关键缺口（按终态影响排序）

### G1. `Com(m_pub; r)` 未内生到 STARK 主约束（高优先级）
- 影响：无法证明 `c` 真实由 `m_pub,r` 打开。
- 现状：strict witness/trace 尚未完整承载并约束 `m_pub/r`。

### G2. `Verify(pk,c,sigma')` 尚非完整密码学内生约束（高优先级）
- 影响：当前约束仍偏工程化，未达到 Fischlin 级别 transcript/challenge 全内生一致性。
- 现状：已完成“增强 AIR 绑定”但未完成“完整验签语义约束”。

### G3. `Enc(pk_E, c||sigma';omega2)` 仍为占位实现（高优先级）
- 影响：第三关系不满足标准 Fischlin 的加密关系定义。
- 现状：`EncTag` 路径可运行，但非真实 PKE 密文关系。

### G4. verify 公开输入语义未完全收敛到 `x=(pk_sig,pk_E,m_pub,ctx_pub)`（高优先级）
- 影响：最终验证语句与规范仍有差距。
- 现状：需冻结 `m_pub` 明文或其公开摘要方案，并写入 strict API。

### G5. `omega2` 随机性语义偏离标准（中优先级）
- 影响：可能影响 blindness 口径与后续安全性叙述一致性。
- 现状：协议层仍有确定性绑定策略，需要回归“随机性 + 可约束正确性”。

## 5. 更新后里程碑（删繁就简）

### M20-6：接口与语句重冻结（`✅`）
- 范围：冻结 strict witness/public inputs 最小闭环数据面。
- 验收：
  - strict witness 可承载 `m_pub/r/sigma'/omega2`（或等价拆分并可约束）。
  - strict verify 输入显式覆盖 `m_pub`（或公开摘要并文档冻结）。

### M20-7：Com/Verify AIR 化（`🟡`，已完成第一阶段）
- `✅` 已完成：
  - `Verify` 相关 AIR 从 prefix-only 提升为“prefix + tail/public_ctx 规则化约束”。
  - strict 核心测试已按 `G1 -> G2` 顺序补齐 prove/verify 负例：`m_pub/r/pk_sig/sigma'` 篡改均会触发输入/见证/证明拒绝。
- `⬜` 待完成：
  - `Com(m_pub;r)` 进入主约束；
  - `Verify(pk,c,sigma')` 升级为完整密码学内生约束（非仅工程规则化绑定）。
- 验收：
  - 篡改 `m_pub/r/sigma'/c/public_ctx` 在 strict 下由 proof 主导拒绝。

### M20-8：Enc 关系标准化（`🟡`）
- 范围：替换 `EncTag`，落地可约束 PKE 关系。
- `✅` 已完成：
  - m20 strict `sigma_c` 已切换到 `spx_p2_build_sigma_c_m20_pke()`，不再走旧 `EncTag` 占位公式；
  - show/relation/Rust strict witness relation 三处计算口径已统一到同一 m20 PKE-tail 语义；
  - 门禁已覆盖 `omega2/C` 篡改拒绝，且新增 `pk_E` 篡改拒绝用例（strict core enforcement）。
  - M20-8 Step 2 已落地第一版：`pk_E` 关键公开量已映射到 AIR 可见列（`pk_e_public_l0..l2`），并新增 m20 门控等值断言：`sigma_c_tail = com + pk_e_public + omega2_witness`（按 limb 约束）。
  - M20-8 Step 3 已推进（阶段A）：prove 路径移除 `strict_witness_relation` 的硬前置拒绝，`pk_E/omega2/C` 不一致优先由 AIR 约束不可满足主导拒绝。
  - M20-8 Step 3 策略收敛：回归“真实语义优先”，`omega2` 在 strict prove 路径恢复为必需见证，避免用缺省恢复替代真实 PKE 随机性语义。
  - M20-8 Step 3 已推进（阶段C）：AIR 新增 `enc_mode_hint` 布尔位约束（bitness），封堵门控位非 `0/1` 的绕过空间。
- `⬜` 待完成：
  - 将当前“工程化 limb 等式”升级为更贴近真实 PKE 语义的 AIR 约束（降低规则化近似）；
  - 完成 M20-10 全矩阵后，对 M20-8 给出“拒绝主因来源于 proof 约束”的闭环证据。
- 验收：
  - `C` 为真实密文语义；
  - `pk_E/omega2/C` 篡改由 AIR 约束主导拒绝。

### M20-9：Spec-First 语义闭环（`🟡`）
- 范围：以 Fischlin 规范为唯一基线，建立“数学关系 -> AIR 约束 -> 测试”映射。
- 验收：
  - strict 口径不再依赖 C `air_verify_full` 同语义对齐作为终判标准；
  - 差异项全部可解释、可追踪。

### M20-10：tamper 全矩阵门禁冻结（`⬜`）
- 范围：单点/交叉/格式攻击统一门禁。
- 验收：
  - 负例拒绝主因来自 STARK 语句约束，而非外层 guard。

### M21：参数与数据重跑（`⬜`）
- 前置：M20-6/7/8/9/10 完成。
- 交付：约束规模、proof size、prove/verify 时间与参数搜索报告归档。

## 6. 当前执行优先级（更新）
- `P0`：完成 M20-7 第二阶段（把 `Com` 与完整 `Verify` 语义真正内生到 AIR）。
- `P0`：完成 M20-8 收口第二阶段（`pk_E/omega2/C` 从 relation 检查主导推进到 AIR 主约束主导）。
- `P1`：完成 M20-9 三向映射表与差异分类回归。
- `P1`：修正 `omega2` 语义到“随机性 + 约束正确性”。

## 7. 下一步计划（M20-8 收口）
- `Step 1`：补齐 tamper 门禁最小闭环（`pk_E/omega2/C` 三元篡改）并固定到 strict 核心测试集合。`（已完成）`
- `Step 2`：把 m20 PKE 关系的关键公开量映射到 AIR 可见列（先做常值保持 + 等值断言）。`（已完成第一版）`
- `Step 3`：逐步移除对外层 relation 的主导依赖，验证拒绝主因转移到 proof 约束不可满足。`（已完成阶段C：enc_mode 位约束 + 语义优先收敛）`
- `Step 4`：与 M20-10 合并验收，形成“篡改项 -> 约束来源 -> 失败相位”的可追溯矩阵。`（进行中，已补 strict 核心测试覆盖 omega2 缺失应拒绝）`

## 9. 本轮代码改动日志（M20-8 Step3-C）
- `ref/test/poseidon2_stark_strict_core_enforcement.c`
  - 重构为按关键缺口顺序验收的 strict 核心门禁测试：
  - `G1 / Com(m_pub; r)`：新增 `g1_bad_m_should_reject_prove_inputs`、`g1_bad_r_should_reject_witness`、`g1_bad_r_should_reject_prove`；
  - `G2 / Verify(pk, c, sigma')`：新增 `verify_tamper_pk_sig_should_reject`、`g2_bad_pk_sig_should_fail_prove_or_verify`；
  - `G3 / Enc(pk_E, c || sigma'; omega2)`：保留 `pk_E/omega2/sigma_c` 篡改负例；
  - `G4 / x=(pk_sig, pk_E, m_pub, ctx_pub)`：新增 `verify_tamper_public_ctx_should_reject`、`verify_missing_m_pub_should_reject`；
- `ref/stark-rs/src/lib.rs`
  - `spx_p2_rust_validate_strict_relation_inputs_v1()` 中恢复 `omega2` 严格要求：strict prove 路径必须提供 `omega2` 且长度为 `SPX_N`；
  - `spx_p2_rust_generate_pi_f_v1()` 中恢复 `spx_p2_rust_validate_strict_witness_relation_v1()` 语义锚点校验；
  - 去除 `omega2` 缺省恢复分支，trace 侧仅接受真实 witness `omega2`；
  - `WorkAir::evaluate_transition()` 新增 `enc_mode_hint` bitness 约束：`enc_mode_hint * (enc_mode_hint - 1) = 0`；
  - 目标：以真实语义一致性优先，避免“可运行但偏语义近似”的策略漂移。
- `ref/show/protocol_poseidon2_v1.c`
  - 收紧 `spx_p2_protocol_verify_v1()`：当 show 携带 `m_pub`（M20）时不再隐式使用内嵌明文验证，必须改走 `spx_p2_protocol_verify_m20_v1()`，使最终公开语句收敛到显式 `x=(pk_sig, pk_E, m_pub, ctx_pub)`。
- `ref/test/poseidon2_fischlin_spec_flow_v1.c`
  - 新增 `verify_v1_should_require_explicit_m_pub_for_m20`，冻结 M20 verify API 口径。

## 10. M20-8 配套验收测试（本地 WSL）
- 构建前置（先编译 Rust 后端静态库）：
  - `cd ref/stark-rs && cargo build --release`
- 构建（使用当前仓库实际存在的 poseidon2 参数组并启用 Rust STARK 后端）：
  - `make -C ref clean`
  - `make -C ref PARAMS=sphincs-poseidon2-192s THASH=simple EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK"`
- 执行关键验收：
  - `./ref/test/poseidon2_stark_strict_core_enforcement`
  - `./ref/test/poseidon2_fischlin_spec_flow_v1`
  - `./ref/test/poseidon2_verify_full_air_v1`
- 重点观察：
  - `strict_prove_inputs_baseline`、`strict_prove_witness_baseline` 基线通过；
  - `g1_bad_m_should_reject_prove_inputs`、`g1_bad_r_should_reject_witness`、`g2_bad_pk_sig_should_fail_prove_or_verify` 必须拒绝；
  - `omega2` 缺失路径 `generate_v1_without_omega2_should_reject` 必须拒绝；
  - tamper 用例 `tamper_pk_e_should_fail_prove_or_verify`、`tamper_omega2_should_fail_prove_or_verify`、`tamper_sigma_c_should_fail_prove_or_verify`、`verify_tamper_public_ctx_should_reject` 必须拒绝；
  - `poseidon2_fischlin_spec_flow_v1` 中 `verify_v1_should_require_explicit_m_pub_for_m20` 必须拒绝。

## 8. 完成态定义（不变）
- 可证明：验证语义等价“存在见证使三关系同时成立”。
- 可执行：Issue/Unblind/Show strict e2e 稳定通过。
- 可反驳：任一关系篡改在 strict 下稳定拒绝，且拒绝主因来自 proof 约束。
- 可复现：约束、性能、参数数据可重复，文档与代码一致。
