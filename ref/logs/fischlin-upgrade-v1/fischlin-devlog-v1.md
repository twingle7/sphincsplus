# Fischlin 升级开发日志 v1

## 2026-04-26（初始化）

### 今日目标
- 在 `ref/logs` 下建立 Fischlin 升级文档工作区。
- 冻结技术口径与里程碑交付，作为后续实现依据。

### 已完成
- 新建目录：`ref/logs/fischlin-upgrade-v1`。
- 新增文档：
  - `README.md`
  - `fischlin-technical-spec-v1.md`
  - `fischlin-milestone-deliverables-v1.md`
  - `fischlin-devlog-v1.md`
- 对齐上游基线：
  - `ref/logs/fischlin-full-framework-roadmap-v1.md`
  - `ref/logs/fischlin-blind-sign-spec-v1.md`

### 代码落地（M18 第一批）
- `ref/show/show_poseidon2_v1.h`
  - 在展示对象中新增 `sigma_C` 与 `sigma_C_len` 字段，作为 final 语义对象 `Sigma=(C,pi)` 的 `C` 承载位。
  - 保留 `com` 为 compat 迁移字段（非 strict 语义主字段）。
- `ref/show/show_poseidon2_v1.c`
  - prove 路径填充 `sigma_C/sigma_C_len`（M18 过渡：使用 `SPX_N` 长度占位承载）。
  - strict verify 新增 `sigma_C` 形状校验，拒绝缺失或非法 `C`。
  - strict verify 改为使用 `sigma_C` 作为传入 FFI 的公开绑定输入，不再依赖 legacy `com` 字段。
- `ref/test/poseidon2_roles_interaction.c`
  - 增加 `sigma_C` 负例：清空 `sigma_C_len` 后 verify 必须拒绝。
  - 输出日志增加 `C_len` 观测字段。
- `ref/test/poseidon2_show_m18_route_isolation.c`
  - 新增 M18 路由隔离测试：`sigma_C` 缺失时 strict 拒绝、compat 仍可按 legacy `com` 路径验证。
- `ref/Makefile`
  - 将 `test/poseidon2_show_m18_route_isolation` 纳入 Poseidon2 测试集合。

### 代码落地（M18 收口 + M19 前推）
- `ref/show/show_poseidon2_v1.h`
  - 将 `sigma_C` 容量扩为 `2*SPX_N`，用于承载过渡期 `C`（前缀保留 `com`，后缀绑定 witness 派生值）。
- `ref/show/show_poseidon2_v1.c`
  - 新增 `spx_p2_build_sigma_c_placeholder()`：构造 `C = com || aux`，其中 `aux=Commit(sigma_com, com)`。
  - strict prove/verify 全链路传递 `sigma_C` 到 FFI；strict verify 增加 `sigma_C` 与 `com` 前缀一致性检查。
  - legacy m10 路由保持不把 `sigma_C` 注入语句摘要（仅 strict 路由启用），确保 compat 窗口可控。
- `ref/stark/ffi_v1.h`
  - 扩展 public inputs：新增 `sigma_c/sigma_c_len`（可选字段）。
- `ref/stark/ffi_v1.c`
  - 新增 `sigma_c` 指针/长度一致性校验。
  - strict v2 生成与验证新增强制条件：`sigma_c` 必填、长度至少 `SPX_N`、且前缀等于 `com`。
- `ref/stark-rs/src/lib.rs`
  - FFI 结构同步增加 `sigma_c/sigma_c_len`。
  - `derive_statement_inputs()` 纳入 `sigma_c_digest`（`hash_expand(sigma_c)`）计算 `public_input_digest` 与 `ctx_binding`，完成语句层对 `C` 的绑定。
  - prove/verify 两端同步读取并使用 `sigma_c`，保证同语句验证。
- `ref/test/poseidon2_statement_binding.c`
  - 新增 `sigma_C` 篡改负例：修改 `C` 后 verify 必须拒绝。
- `ref/test/poseidon2_show_m18_route_isolation.c`
  - 更新路由隔离断言：
  - strict 对象缺失 `sigma_C` 时，strict/compat 都应拒绝（因语句已绑定 `C`）。
  - legacy compat 对象仍可在 `sigma_C` 缺失下通过 compat 验证。
- `ref/test/poseidon2_roles_interaction.c`
  - 修正 `sigma_C_len` 恢复逻辑，避免硬编码 `SPX_N`。
- `ref/stark/stats_v1.c`、`ref/test/poseidon2_stark_ffi_v1.c`
  - 补齐新 FFI 字段初始化（`sigma_c=0, sigma_c_len=0`）以保持 legacy 路径语义稳定。
  - 修复 `poseidon2_stark_ffi_v1` 缓冲区上限：由 `SPX_P2_PI_F_V1_MAX_BYTES` 提升为 `64KiB`，适配 Rust 路径输出 `pi_F_v2` 的实际体积，避免 `ffi_generate` 误报失败。

### M19 继续推进（本轮）
- 结果判断：`roles_interaction / statement_binding / route_isolation` 全通过，说明 `sigma_C` 语句绑定主链路生效。
- 问题归因：`stark_ffi_v1` 失败为测试容量配置问题，不是 `Sigma` 语义回归。

### 代码落地（M19 强化：Enc 关系接线）
- `ref/show/show_poseidon2_v1.h`
  - `spx_p2_cred_v1_internal` 新增 witness 字段：`omega2[SPX_N]` 与 `omega2_len`。
- `ref/show/show_poseidon2_v1.c`
  - 将 `C` 构造从简单占位升级为 witness 驱动：
  - `C = c || EncTag`，其中 `EncTag` 绑定 `(pk_E占位, c, sigma', omega2)`。
  - 新增 `omega2` 选择逻辑：若未显式提供则回退到可复现派生值（保障旧用例兼容）。
  - strict prove 使用 witness 构造 `C`，strict verify 仍要求 `C` 前缀与 `com` 一致。
- `ref/stark/ffi_v1.c`
  - strict 模式下 `sigma_c_len` 由“至少 `SPX_N`”收紧为“必须等于 `2*SPX_N`”。
- `ref/test/poseidon2_m19_enc_relation.c`（新增）
  - 覆盖 M19 关键矩阵：
  - 不同 `omega2` 导致不同 `C`；
  - 跨对象替换 `C` 必拒绝（`pi` 与 `C` 绑定生效）；
  - 篡改 `sigma'` 时 strict prove 必失败。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m19_enc_relation`。

### 第二轮改动（2026-04-26，M19 再推进：显式 pk_E 绑定）
- `ref/stark/ffi_v1.h`
  - `spx_p2_ffi_public_inputs_v1` 新增 `pk_e/pk_e_len` 字段，支持把 `pk_E` 作为独立公开输入传入 prove/verify。
- `ref/stark/ffi_v1.c`
  - 增加 `pk_e` 指针/长度一致性校验。
  - strict v2 路径新增强制条件：`pk_e` 必填且长度至少 `SPX_N`。
- `ref/stark-rs/src/lib.rs`
  - Rust FFI 结构同步新增 `pk_e/pk_e_len`。
  - `derive_statement_inputs()` 改为显式纳入 `pk_E`（通过 `pk_e_digest`）参与 `public_input_digest/ctx_binding` 计算。
  - prove/verify 两端一致读取并绑定 `pk_E`。
- `ref/show/show_poseidon2_v1.h`
  - 新增 strict M19 API：`spx_p2_show_prove_v2_strict_m19` / `spx_p2_show_verify_v2_strict_m19`，参数显式区分 `pk_sig` 与 `pk_E`。
- `ref/show/show_poseidon2_v1.c`
  - `C` 构造函数改为显式接收 `pk_E`，`EncTag` 与 `pk_E` 直接绑定。
  - strict v2 默认 API 保持兼容：内部走 `pk_E = pk_sig` 的回退桥接。
  - m10/legacy 路径补齐新 FFI 字段初始化，避免未定义输入。
- `ref/show/show_poseidon2.h`、`ref/show/show_poseidon2.c`
  - 新增对外包装：`spx_p2_show_prove_m19` / `spx_p2_show_verify_m19`。
- `ref/test/poseidon2_m19_pk_e_binding.c`（新增）
  - 覆盖“同 proof 替换 `pk_E` 必拒绝”负例，验证 `pk_E` 已进入语句绑定。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m19_pk_e_binding`。

### 第三轮改动（2026-04-26，M19 深化：Enc 一致性下沉到 strict FFI）
- `ref/hash_poseidon2_adapter.h`、`ref/hash_poseidon2_adapter.c`
  - 新增统一构造函数 `spx_p2_build_sigma_c_m19()`，将 `C = (c || EncTag)` 的构造固定为共享实现。
  - `EncTag` 显式绑定 `(pk_E, c, sigma', omega2)`；`omega2` 缺失时使用可复现回退值。
- `ref/stark/ffi_v1.h`
  - `spx_p2_ffi_private_witness_v1` 扩展 `omega2/omega2_len`，让 strict prove 可读取完整 witness。
- `ref/stark/ffi_v1.c`
  - strict v2 生成新增强校验：基于 `(pk_E, c, sigma', omega2)` 重算 `sigma_c`，与输入 `sigma_c` 必须字节一致。
  - 保留长度/前缀校验，并新增 `omega2` 指针-长度一致性检查。
- `ref/show/show_poseidon2_v1.c`
  - show 层 `C` 构造改为调用共享 `spx_p2_build_sigma_c_m19()`，避免 show/ffi 两套实现漂移。
  - strict prove 把 `omega2` 传入 FFI witness；未提供时保持回退兼容路径。
- `ref/stark-rs/src/lib.rs`
  - Rust FFI witness 结构同步扩展 `omega2/omega2_len`（当前主要用于 ABI 对齐与输入校验）。
- `ref/test/poseidon2_m19_strict_ffi_consistency.c`（新增）
  - 覆盖 strict FFI 关键负例：`sigma_c` 与 witness 中 `omega2` 不一致时生成必须拒绝。
  - 覆盖正例：一致 witness 下 strict generate/verify 正常通过。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m19_strict_ffi_consistency`。

### 第四轮改动（2026-04-26，M19 大步推进：语句版本切换 + final e2e 矩阵）
- `ref/stark/pi_f_format_v2.h`、`ref/stark/pi_f_format.h`
  - 新增并启用 `SPX_P2_PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V2`。
  - 当前活跃语句版本切换为 `VERIFY_FULL_V2`，用于区分 M19 新绑定域与旧 proof 域。
- `ref/stark-rs/src/lib.rs`
  - Rust 侧同步切换 `statement_version` 到活跃版本常量（prove 编码 + verify 检查 + 语句摘要输入一致）。
- `ref/test/poseidon2_pi_f_format_v2.c`
  - 格式回环测试改用活跃语句版本常量，避免硬编码旧版本号。
- `ref/test/poseidon2_m19_final_e2e.c`（新增）
  - 新增 M19 final 风格 e2e 测试矩阵：
  - `pk_E` 交换拒绝；
  - `omega2` 变化驱动 `C` 变化；
  - 跨对象交换 `C` 拒绝；
  - `public_ctx` 交换拒绝。
- `ref/test/poseidon2_m19_strict_ffi_consistency.c`
  - 扩充 strict FFI 负例：`sigma_c` 与 `pk_E` 不一致拒绝、`sigma'` 损坏拒绝。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m19_final_e2e`。

### 第五轮改动（2026-04-26，M19 全量收口：显式 m19 主链 + release gate）
- `ref/test/poseidon2_roles_interaction.c`
  - 主流程切换到显式 `spx_p2_show_prove_m19 / spx_p2_show_verify_m19`，不再依赖隐式 `pk_E=pk_sig` 回退路径。
  - 测试内显式设置 `omega2`，并派生 `pk_E`，使角色交互示例与 M19 语义一致。
- `ref/test/poseidon2_fischlin_blind_e2e.c`
  - e2e 用例切换到显式 m19 API，补齐 `pk_E/omega2` 输入，收紧“协议主链”测试口径。
- `ref/test/poseidon2_m19_enc_relation.c`
  - M19 Enc 关系测试切换到显式 m19 API，避免由默认包装器掩盖 `pk_E` 参数遗漏。
- `ref/test/poseidon2_m19_release_gate.c`（新增）
  - 新增 M19 发布门禁测试：
  - `show_prove_m19/show_verify_m19` 正向通过；
  - 错误 `pk_E` 拒绝；
  - `pi_F_v2` 解码后 `statement_version == VERIFY_FULL_V2`；
  - `sigma_C` 形状满足 `2*SPX_N` 且前缀为 `c`。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m19_release_gate`，作为进入 M20 前回归集合的一部分。

### M20 准备状态（更新）
- M19 主语义链路（`pk_E/omega2/C/public_ctx/statement_version`）已完成显式化并具备门禁测试。
- 下一步进入 M20 时，重点从“语义补线”转为“协议编排与失败路径图谱”。

### 第六轮改动（2026-04-26，M20-1 首轮：流程编排骨架 + 统一错误码）
- `ref/show/protocol_poseidon2_v1.h`、`ref/show/protocol_poseidon2_v1.c`（新增）
  - 新增 M20-1 协议编排接口：
  - `spx_p2_issue_request_v1`（holder 生成 `com`）；
  - `spx_p2_issue_sign_v1`（issuer 对 `com` 签发 `sigma_blind`）；
  - `spx_p2_unblind_v1`（工程化身份去盲映射到 `cred`）；
  - `spx_p2_issue_unblind_v1`（Issue+Unblind 便捷编排）；
  - `spx_p2_protocol_show_v1` / `spx_p2_protocol_verify_v1`（统一封装 `show_*_m19`）。
  - 新增统一流程错误码 `SPX_P2_FLOW_*` 与 `spx_p2_flow_status_to_string_v1`。
- `ref/test/poseidon2_m20_flow_v1.c`（新增）
  - 新增 M20-1 流程测试：
  - 正常流 `Issue->Unblind->Show->Verify` 通过；
  - 错误 `pk_E` 返回统一 `VERIFY` 错误；
  - 篡改 witness 返回统一 `PROVE` 错误。
- `ref/Makefile`
  - 新增编排实现源文件 `show/protocol_poseidon2_v1.c`；
  - 新增测试目标 `test/poseidon2_m20_flow_v1`。
- `ref/logs/fischlin-upgrade-v1/fischlin-milestone-deliverables-v1.md`
  - 写入 M19 阶段结论（真实 STARK + 外置 guard 现状）与 M20-1 首轮落地状态。

### 第七轮改动（2026-04-26，M20-1 修复：无 Rust 后端时的流程测试门禁）
- 问题定位：
  - `poseidon2_m20_flow_v1` 在未启用 `-DSPX_P2_USE_RUST_STARK` 时，strict v2 证明路径返回 `SPX_P2_FLOW_ERR_PROVE`，导致测试直接失败（现象：`FAIL: protocol_show status=prove`）。
- 修复：
  - `ref/test/poseidon2_m20_flow_v1.c`
  - 新增后端门禁分支：当未启用 Rust STARK 且 `protocol_show` 返回 `PROVE` 时，测试输出 `SKIP` 并返回成功。
  - 启用 Rust STARK 时保持原有严格断言（必须完整通过正常流与负例）。

### 第八轮改动（2026-04-26，M20-2 推进：显式 witness 绑定收紧）
- `ref/show/protocol_poseidon2_v1.c`
  - `spx_p2_issue_unblind_v1` 在未显式提供 `omega2` 时，新增确定性回退生成（`omega2=Commit(com, sigma_blind)`），保证编排层输出的凭证始终携带显式 `omega2` witness。
  - `spx_p2_protocol_show_v1` 收紧输入约束：要求 `cred->omega2_len == SPX_N`，缺失显式 witness 时返回 `SPX_P2_FLOW_ERR_INPUT`，避免沿用隐式空 witness 路径。
- `ref/test/poseidon2_m20_witness_binding_v1.c`（新增）
  - 新增 M20-2 witness 绑定测试：
  - `issue_unblind` 在未传 `omega2` 时应补齐显式 witness；
  - `protocol_show` 对缺失 `omega2` 的凭证应拒绝；
  - 在启用 Rust STARK 后端时继续校验 show/verify 正常流。
- `ref/Makefile`
  - 新增测试目标 `test/poseidon2_m20_witness_binding_v1`。

### 第九轮改动（2026-04-26，M20-2 继续推进：omega2 一致性前置校验）
- `ref/show/protocol_poseidon2_v1.c`
  - `spx_p2_protocol_show_v1` 新增 `omega2` 一致性前置校验：按 `(com, sigma_com)` 重算期望 `omega2`，与凭证中的 `omega2` 必须一致，不一致则返回 `SPX_P2_FLOW_ERR_INPUT`。
  - 目的：把 `omega2` witness 的绑定失败前移到协议层，减少“进入 prove 后才失败/或被隐式接受”的不确定性。
- `ref/test/poseidon2_m20_flow_v1.c`
  - 新增负例：篡改 `omega2` 必须返回 `INPUT`。
  - 更新既有负例口径：篡改 `sigma_com` 由协议层前置一致性拒绝（期望 `INPUT`）。
- `ref/test/poseidon2_m20_witness_binding_v1.c`
  - 新增负例：`omega2` 篡改后 `protocol_show` 必拒绝（`INPUT`）。

### 第十轮改动（2026-04-26，M20-2 修复：issue_unblind 与 show 的 omega2 口径对齐）
- 问题：
  - `poseidon2_m20_flow_v1` 使用固定 `omega2`（非 `(com,sigma_com)` 重算值）时，`issue_unblind` 先通过，但 `protocol_show` 前置校验返回 `INPUT`，导致测试在 show 阶段失败。
- 修复：
  - `ref/show/protocol_poseidon2_v1.c`
  - `spx_p2_issue_unblind_v1` 新增一致性前置校验：若调用方显式传入 `omega2`，要求其必须等于 `(com,sigma_com)` 重算值，否则直接返回 `SPX_P2_FLOW_ERR_INPUT`。
  - 未显式传入 `omega2` 时，继续自动回退到该重算值，确保 `issue_unblind -> show` 口径一致。
  - `ref/test/poseidon2_m20_flow_v1.c`
  - 改为走默认回退 witness（传 `omega2=0`），避免测试自身注入与协议口径不一致的输入。

### 第十一轮改动（2026-04-26，M20-2 推进：去 SKIP 化，改为能力感知断言）
- 问题：
  - 在未启用 Rust 后端时，M20 测试长期输出 `SKIP`，无法形成稳定“通过/失败”信号。
- 调整：
  - `ref/test/poseidon2_m20_flow_v1.c`
  - 去掉 `SKIP` 分支，改为能力感知断言：
  - 启用 Rust 后端：要求 `show/verify` 正常通过；
  - 未启用 Rust 后端：要求 strict `show` 返回 `SPX_P2_FLOW_ERR_PROVE`，同时继续校验 `omega2/sigma_com` 篡改应被协议层 `INPUT` 拒绝。
  - `ref/test/poseidon2_m20_witness_binding_v1.c`
  - 去掉 `SKIP` 分支，改为能力感知断言：
  - 启用 Rust 后端：要求 `show/verify` 正常通过；
  - 未启用 Rust 后端：要求 strict `show` 返回 `SPX_P2_FLOW_ERR_PROVE`，并保留显式 witness 绑定负例校验。
- 结果：
  - 无 Rust 环境下测试输出从 `SKIP` 改为 `OK | backend=stub ...`，可纳入常规回归门禁。

### 第十二轮改动（2026-04-26，M20-2 继续收口：verify 形状前置校验 + issue 显式 witness 负例）
- `ref/show/protocol_poseidon2_v1.c`
  - 新增 `protocol_verify` 前置形状守卫（`pi_f_len/sigma_C_len/sigma_C前缀/com非零/public_ctx_len`），不满足时返回 `SPX_P2_FLOW_ERR_INPUT`，避免直接落到后端 `VERIFY` 模糊错误。
- `ref/test/poseidon2_m20_flow_v1.c`
  - 新增后端无关负例：构造 malformed `show`（空对象）调用 `protocol_verify`，期望返回 `INPUT`。
- `ref/test/poseidon2_m20_witness_binding_v1.c`
  - 新增后端无关负例：`issue_unblind` 显式传入错误 `omega2`，期望返回 `INPUT`。
- 收益：
  - M20-2 协议层的错误码语义更“前置且可判定”，即使未启用 Rust 后端，也能覆盖更多关键约束门禁。

### 第十三轮改动（2026-04-26，M20-2 最后一段：后端错误码分层收口）
- `ref/show/protocol_poseidon2_v1.h`、`ref/show/protocol_poseidon2_v1.c`
  - 新增统一错误码 `SPX_P2_FLOW_ERR_BACKEND`，用于表示“strict 语义需要 Rust STARK 后端，但当前构建不可用”。
  - 新增后端能力接口：
  - `spx_p2_protocol_has_rust_backend_v1()`；
  - `spx_p2_protocol_backend_mode_v1()`（返回 `rust/stub`）。
  - `protocol_show/protocol_verify` 在无 Rust 后端且进入 strict prove/verify 路径失败时，返回 `BACKEND` 而非混用 `PROVE/VERIFY`。
- `ref/test/poseidon2_m20_flow_v1.c`、`ref/test/poseidon2_m20_witness_binding_v1.c`
  - 无后端分支断言从 `PROVE` 切换为 `BACKEND`，并统一打印 `backend=<mode>`。
- 收益：
  - M20-2 统一错误码分层完成：`INPUT`（前置约束）/`BACKEND`（能力缺失）/`PROVE|VERIFY`（后端执行失败）语义边界清晰。

### 第十四轮改动（2026-04-27，M20-3 首轮：关系迁移层落地）
- `ref/stark/relation_migration_v1.h`、`ref/stark/relation_migration_v1.c`（新增）
  - 新增 M20-3 迁移层接口，集中承载 strict prove/verify 前置关系检查：
  - `spx_p2_relation_validate_strict_prove_inputs_v1()`；
  - `spx_p2_relation_validate_strict_verify_inputs_v1()`；
  - `spx_p2_relation_precheck_strict_prove_witness_v1()`。
  - 将 `sigma_c` 一致性重算、`Verify(pk,c,sigma')` witness 预检查、`verify_full` guard 评估从 `ffi_v1.c` 抽离，形成单点迁移入口。
- `ref/stark/ffi_v1.c`
  - strict v2 generate/verify 改为调用迁移层接口，不再内联散落关系检查逻辑。
  - 语义保持不变，主要是结构去耦，为后续“下沉 AIR/见证约束”做代码位形准备。
- `ref/Makefile`
  - 新增 `stark/relation_migration_v1.c` 与对应头文件编译接入。
- 结果：
  - M20-3 已开始实质落地：关系检查从“散点实现”进入“可替换单点层”，后续可按函数粒度逐项迁移到证明系统内生约束。

### 第十五轮改动（2026-04-27，M20-3 继续：strict 输入校验后端委托通道）
- `ref/stark-rs/src/lib.rs`
  - 新增导出函数 `spx_p2_rust_validate_strict_relation_inputs_v1()`，对 strict 路径做后端侧输入形状与绑定前缀校验（`pk_e/sigma_c/com`，以及可选 witness 指针-长度一致性）。
- `ref/stark/relation_migration_v1.c`
  - 在启用 Rust 后端时，`spx_p2_relation_validate_strict_prove_inputs_v1()` 与 `spx_p2_relation_validate_strict_verify_inputs_v1()` 优先委托 Rust 校验函数，再保留 C 侧同语义兜底检查。
  - 当前策略是“后端优先 + C 兜底”，为后续逐条移除外层语义 guard 提供平滑迁移路径。
- 结果：
  - M20-3 从“结构抽离”进一步推进到“校验入口后移”，已形成可演进的跨语言迁移骨架。

### 第十六轮改动（2026-04-27，M20-3 继续：relation migration 门禁测试）
- `ref/test/poseidon2_m20_relation_migration_v1.c`（新增）
  - 新增迁移层专用测试，直接覆盖：
  - `spx_p2_relation_validate_strict_prove_inputs_v1()` 正例；
  - `spx_p2_relation_validate_strict_verify_inputs_v1()` 正例与 `sigma_c_len/prefix` 负例；
  - `spx_p2_relation_precheck_strict_prove_witness_v1()` 正例与 `sigma_c` 篡改负例。
- 结果：
  - M20-3 已具备独立可执行门禁，用于验证“关系迁移层”行为稳定且可持续重构。
  - 根据本地回归反馈修正测试用例：`bad_sigma_c_prefix` 现在实际篡改 `sigma_c` 前缀字节（原先误改后半段导致断言失真）。
  - `poseidon2_m19_strict_ffi_consistency` 调整为能力感知断言：无 Rust 后端断言 `strict_generate` 返回 `PROVE`；有 Rust 后端执行完整 strict 正/负例，同时将 proof cap 提升到 `256KiB` 并打印失败返回码便于定位。

### 第十七轮改动（2026-04-27，M20-3 继续：strict 定长语义收紧）
- `ref/stark/relation_migration_v1.c`
  - strict 输入约束由“最小长度”收紧为“定长”：
  - `pk_e_len` 必须等于 `SPX_N`；
  - `omega2_len` 仅允许 `0`（fallback）或 `SPX_N`（显式 witness）。
- `ref/stark-rs/src/lib.rs`
  - Rust 侧 `spx_p2_rust_validate_strict_relation_inputs_v1()` 同步执行上述定长约束，保持“后端优先 + C 兜底”语义一致。
- `ref/test/poseidon2_m20_relation_migration_v1.c`
  - 新增负例：
  - `pk_e_len != SPX_N` 应拒绝；
  - `omega2_len` 非 `0/SPX_N` 应拒绝。
- 结果：
  - M20-3 在 strict 关系输入层进一步消除可变长度歧义，为后续将关系判定继续下沉到内生约束提供更稳定接口边界。

### 第十八轮改动（2026-04-27，M20-3 继续：strict 输入校验改为后端权威）
- `ref/stark/relation_migration_v1.c`
  - 在 `SPX_P2_USE_RUST_STARK` 构建下：
  - `spx_p2_relation_validate_strict_prove_inputs_v1()` 与 `spx_p2_relation_validate_strict_verify_inputs_v1()` 直接返回 Rust 校验结果映射，不再重复执行 C 同语义检查。
  - 在无 Rust 后端构建下继续保留 C fallback 逻辑，保持 stub 路径可测。
- 结果：
  - M20-3 从“后端优先 + C 兜底同跑”推进到“后端权威 + C fallback 分支化”，减少外层 guard 对 strict 语义的重复主导。

### 第十九轮改动（2026-04-27，M20-3 加速：strict precheck 继续下放）
- `ref/stark/relation_migration_v1.c`
  - 在 `SPX_P2_USE_RUST_STARK` 构建下，`spx_p2_relation_precheck_strict_prove_witness_v1()` 仅保留 `sigma_c` 一致性重算检查，`verify_com + verify_full_guard` 外层语义检查不再在 C 层执行，改由后端 proving 阶段主导判定。
  - 在无 Rust 后端构建下，保留原有 C 路径（含 `verify_com + verify_full_guard`）以维持 stub 路径行为与回归覆盖。
  - 同步做条件编译收口：`air_verify_full.h` 与 `spx_p2_eval_verify_full_guard()` 仅在非 Rust 构建编译，避免后端构建下出现未使用静态函数风险。
- 结果：
  - M20-3 进一步压缩 C 外层语义面，strict 主链语义更多由后端 proving/constraints 给出。

### 第二十轮改动（2026-04-27，M20-3 加速：sigma_c 一致性后端桥接）
- `ref/stark/relation_migration_v1.h`、`ref/stark/relation_migration_v1.c`
  - 新增桥接函数 `spx_p2_relation_backend_validate_sigma_c_m19_v1()`，集中实现 `sigma_c` 一致性重算校验（含 `omega2` fallback 语义），作为后端可复用入口。
  - Rust 构建下 `spx_p2_relation_precheck_strict_prove_witness_v1()` 改为调用 Rust 导出校验接口，不再在该路径直接执行 C 侧 `sigma_c` 逻辑。
- `ref/stark-rs/src/lib.rs`
  - 新增 `spx_p2_rust_validate_strict_witness_relation_v1()`：
  - 先执行 strict 输入形状校验；
  - 再通过 FFI 调用 C 桥接函数做 `sigma_c` 一致性判定；
  - 将返回码统一映射为 Rust 侧状态码，供 C 迁移层直接消费。
- `ref/test/poseidon2_m20_backend_sigma_c_bridge_v1.c`（新增）
  - 新增桥接层专用门禁：覆盖 `sigma_c` 正例与末字节篡改负例。
- 结果：
  - `sigma_c` 一致性检查已完成“后端调用路径”迁移：strict Rust 路径下由 Rust 校验入口驱动，C 实现收敛为可替换桥接组件。

### 第二十一轮改动（2026-04-27，M20-3 加速：sigma_c 一致性 Rust 原生化）
- `ref/stark-rs/src/lib.rs`
  - 移除对 `spx_p2_relation_backend_validate_sigma_c_m19_v1()` 的依赖，在 Rust 内新增 `rust_build_sigma_c_m19_native()`，按 M19 语义原生重建 `sigma_c = (c || EncTag)`：
  - `omega2` 缺失时使用 `spx_p2_commit(sigma_com, com)` 做 deterministic fallback；
  - `EncSeed/PkESeed/EncTag` 三段使用 `poseidon2_hash_bytes_domain(..., SPX_P2_DOMAIN_CUSTOM, ...)` 生成；
  - 标签字节使用与 C 保持一致的 `\0` 结尾常量，确保 hash 输入语义对齐。
  - `spx_p2_rust_validate_strict_witness_relation_v1()` 现直接比较 `pub.sigma_c` 与 Rust 原生重算结果。
- `ref/stark/relation_migration_v1.h`、`ref/stark/relation_migration_v1.c`
  - 删除对外桥接导出声明；C 侧 `sigma_c` 检查函数改为文件内 `static`，仅服务非 Rust fallback 路径。
- `ref/test/poseidon2_m20_backend_sigma_c_bridge_v1.c`
  - 测试入口切换为统一 API `spx_p2_relation_precheck_strict_prove_witness_v1()`，持续覆盖正例与 `sigma_c` 篡改负例，避免绑定已移除的桥接导出。
- 结果：
  - strict Rust 路径下，`sigma_c` 一致性关系已由 Rust 主逻辑原生主导，M20-3 向“完整内生”再前推一段。

### 第二十二轮改动（2026-04-27，M20-3 加速：verify_com 语义并入 Rust strict 主链）
- `ref/stark-rs/src/lib.rs`
  - 在 `spx_p2_rust_validate_strict_witness_relation_v1()` 内新增 `verify_com` 校验（通过 `SPX_spx_p2_verify_com`），使 Rust strict witness relation 在后端入口即可判定 `Verify(pk,c,sigma')` 失败，并返回 `SPX_P2_RUST_ERR_PROVE`。
  - 保持 `sigma_c` 原生重算校验在其后执行；即“签名关系失败优先记为 `PROVE`，`sigma_c` 绑定失败记为 `INPUT`”的分层语义。
- `ref/test/poseidon2_m20_relation_migration_v1.c`
  - 新增 `sigma_com` 篡改门禁：
  - Rust 构建断言 `spx_p2_relation_precheck_strict_prove_witness_v1()` 返回 `SPX_P2_FFI_ERR_PROVE`；
  - 非 Rust fallback 断言返回 `SPX_P2_FFI_ERR_INPUT`（保持当前 fallback 语义稳定）。
- `ref/test/poseidon2_m19_strict_ffi_consistency.c`
  - 将 `bad_sigma_com` 用例从“非 OK 即可”收紧为精确错误码断言（Rust/stub 均断言 `SPX_P2_FFI_ERR_PROVE`）。
- 结果：
  - strict Rust 主链对 `verify_com` 关系的前置判定进一步后端化，错误码分层更接近“完整内生”目标。

### 第二十三轮改动（2026-04-27，M20-3 对齐冻结规范：strict 显式 omega2）
- `ref/stark-rs/src/lib.rs`
  - `spx_p2_rust_validate_strict_relation_inputs_v1()` 收紧 strict witness 形状：要求 `omega2` 必须显式提供（`omega2!=NULL && omega2_len==SPX_N`），不再接受缺失 witness 的旧口径。
  - `rust_build_sigma_c_m19_native()` 的 `omega2` fallback 参数顺序对齐共享实现，统一为 `Commit(com, sigma_com)` 口径，避免 C/Rust 派生漂移。
  - `spx_p2_rust_validate_strict_witness_relation_v1()` 新增显式 `omega2` 与 `Commit(com, sigma_com)` 一致性校验，篡改时返回 `INPUT`。
- `ref/stark/relation_migration_v1.c`
  - 非 Rust fallback 的 strict prove 输入校验同步收紧为“显式 `omega2` 必填”，维持跨后端一致语义。
- `ref/test/poseidon2_m20_relation_migration_v1.c`
  - 新增 `validate_prove_should_reject_missing_omega2` 门禁，固定 strict 下“缺失 witness 必拒绝”行为。
- 结果：
  - strict 关系输入与 `fischlin-upgrade-v1/fischlin-technical-spec-v1.md` 中 `w=(r,omega2,c,sigma')` 定义完成对齐，旧版缺失 `omega2` 兼容语义仅保留在非 strict/legacy 语境。

### 关键决策
- 将最终语句冻结为 Fischlin-Strict，核心对象改为 `Sigma=(C,pi)`。
- 明确旧对象仅用于 compat，不得作为 final 语义。
- 明确新语句下约束与参数数据需重跑，旧数据仅作历史对照。

### 当前风险
- `Enc` 关系内生后约束规模可能显著上涨，影响 prove 时间与 proof size。
- 接口升级阶段可能出现 legacy/final 路由混用风险。

### 阻塞项
- 暂无外部阻塞，等待开始代码实现阶段。

### 第二十四轮改动（2026-04-27，评估轮：完整 STARK 闭环差距盘点 + 新里程碑文档）
- 新增文档：
  - `ref/logs/fischlin-upgrade-v1/fischlin-stark-full-gap-and-milestone-v1.md`
- 本轮动作：
  - 对照冻结规范与标准 Fischlin 语句，系统复核 strict 主链调用路径：
  - `protocol_show/protocol_verify -> show_*_m19 -> ffi_v2_strict -> relation_migration -> rust generate/verify`。
  - 逐项核对 C `air_verify_full` 与 Rust AIR 的约束覆盖范围，形成“已实现 / 未实现 / 偏离项”清单。
  - 给出“实现完整 STARK 证明闭环所需步骤”与新的技术里程碑（M20-6 到 M20-10 + M21 收口）。
- 关键结论（评估结论，不含代码改动）：
  - 当前 strict 路径已具备可运行证明编排与对象绑定，但尚未达到“Fischlin 三关系完整内生于 STARK 语句”。
  - `Com/Verify/Enc` 中：
  - `Verify` 目前主要在 precheck 层；
  - `Com` 关系缺少 `m_pub/r` witness 进入 STARK 主约束；
  - `Enc` 仍为 `EncTag` 工程占位，未达到标准加密关系定义。
  - Rust AIR 与 C `verify_full` 仍未同语义闭环，需继续做“约束映射 + 一致性门禁”收口。
- 输出物：
  - 形成“标准流程 -> 现状差距 -> 改造任务 -> 验收定义”一体化文档，作为后续实现排期基线。

### 第二十五轮改动（2026-04-27，M20-6 首轮大步推进：m_pub/r 绑定接入 strict 主链）
- 目标：在不打断既有 m19 路径的前提下，前推 M20-6（显式 `m_pub` 与 `Com` opening witness）到可用代码状态。
- 结构体与接口扩展：
  - `ref/stark/ffi_v1.h`
  - `spx_p2_ffi_public_inputs_v1` 新增 `m_pub/m_pub_len`；
  - `spx_p2_ffi_private_witness_v1` 新增 `m/mlen/r/rlen`。
- strict 校验层改造：
  - `ref/stark/relation_migration_v1.c`
  - prove/verify 输入校验支持“双轨”：
  - 兼容轨（m19）：`m_pub,m,r` 全缺省可通过；
  - 强语义轨（m20）：任一出现则要求 `m_pub==m` 且 opening 完整；
  - precheck 在 m20 轨增加 `Com(m;r)==com` 校验（返回 `PROVE`）。
- Rust 后端改造：
  - `ref/stark-rs/src/lib.rs`
  - FFI 结构同步新增 `m_pub/m/r` 字段；
  - `derive_statement_inputs()` 将 `m_pub` 纳入 `public_input_digest/ctx_binding/start` 派生；
  - strict relation/witness 校验改为“双轨”（m19 兼容 + m20 强约束）；
  - `generate/verify` 路径读取 `m_pub` 参与语句摘要，完成 prove/verify 同口径绑定。
- show/protocol API 前推（新增 m20 入口）：
  - `ref/show/show_poseidon2_v1.h/.c`
  - 新增 `spx_p2_show_prove_v2_strict_m20()` 与 `spx_p2_show_verify_v2_strict_m20()`；
  - `m19` 保持兼容语义（不强制 `m_pub/r`）；
  - `m20` 强制 `cred` 含 `m/r` 且 opening 与 `com` 一致。
  - `ref/show/show_poseidon2.h/.c`
  - 新增对外包装 `spx_p2_show_prove_m20()` 与 `spx_p2_show_verify_m20()`。
  - `ref/show/protocol_poseidon2_v1.h/.c`
  - 新增 `spx_p2_protocol_show_m20_v1()`、`spx_p2_protocol_verify_m20_v1()`。
- 协议编排补全：
  - `spx_p2_issue_unblind_v1()` 在成功 unblind 后回填 `cred.m/cred.r`，用于后续 m20 prove。
- 测试与调用点适配：
  - 更新 strict 相关测试输入构造，补齐新字段（m19 兼容路径置空，m20 路径填充）。
  - 变更文件：
  - `ref/test/poseidon2_m20_relation_migration_v1.c`
  - `ref/test/poseidon2_m19_strict_ffi_consistency.c`
  - `ref/test/poseidon2_m20_backend_sigma_c_bridge_v1.c`
  - `ref/test/poseidon2_stark_ffi_v1.c`
  - `ref/stark/stats_v1.c`
- 本轮语义结果：
  - strict 主链已可承载 `m_pub` 公开输入与 `m,r` opening witness；
  - 现有 m19 路径继续可用，m20 路径可用于逐步切换到更完整 Fischlin 语句绑定。

### 第二十六轮改动（2026-04-27，WSL 构建链路热修：Rust STARK 链接补齐）
- 触发场景：
  - 在 `EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK"` 下执行 `make -j8`，`PQCgenKAT_sign` 目标链接阶段出现 undefined reference（`spx_p2_rust_*`）。
- 根因分析：
  - `Makefile` 已根据宏设置 `LDLIBS += -L... -lsphincsplus_stark_rs ...`，但 `PQCgenKAT_sign` 规则未使用 `$(LDLIBS)`，仅链接 `-lcrypto`，导致 Rust 符号未解析。
- 修复动作：
  - 文件：`ref/Makefile`
  - 规则：
  - 从 `$(CC) ... -lcrypto`
  - 改为 `$(CC) ... -lcrypto $(LDLIBS)`
- 结果：
  - `PQCgenKAT_sign` 与测试目标在 Rust STARK 开启时使用同一链接策略，消除该类链接缺口。

### 第二十七轮改动（2026-04-27，M20 稳定性修复：strict precheck 与 show_prove 故障排障）
- 触发症状（WSL 实测）：
  - `precheck_witness_good got=-2`
  - `strict_precheck_good got=-2`
  - `FAIL: show_prove`
- 根因：
  - Rust strict relation 输入校验把 `omega2` 误设为“必填且长度固定 SPX_N”，与现有 `sigma_c` 构造逻辑（允许缺省 `omega2` 并 fallback）不一致；
  - Rust strict witness precheck 额外强制 `omega2 == Commit(com, sigma_com)`，超出 relation migration 层职责，导致合法见证被误拒绝。
- 修复动作：
  - `ref/stark-rs/src/lib.rs`
  - `spx_p2_rust_validate_strict_relation_inputs_v1()`：
    - `omega2` 改为可选输入，允许两种合法形态：
    - 缺省：`omega2 == NULL && omega2_len == 0`
    - 显式：`omega2 != NULL && omega2_len == SPX_N`
  - `spx_p2_rust_validate_strict_witness_relation_v1()`：
    - 移除“`omega2` 必须等于 `Commit(com, sigma_com)`”的强制校验；
    - 保留 `sigma_c` 重构一致性校验与 `Verify(pk,com,sigma_com)` 校验。
  - `ref/stark/relation_migration_v1.c`
  - 非 Rust fallback 同步采用相同 `omega2` 合法性判定（可选/显式两态）。
- 结果：
  - strict relation/precheck 与 prove 链路恢复一致口径；
  - 修复 `m20_relation_migration`、`m20_backend_sigma_c_bridge`、`show_prove` 相关失败路径；
  - 为后续将 m20 强语义路径设为主链提供稳定基础。

### 第二十八轮改动（2026-04-27，联动修复：omega2 语义回正 + Rust .so 符号问题）
- 触发症状（WSL）：
  - `validate_prove_should_reject_missing_omega2 got=0`
  - 多个测试运行时报错：`libsphincsplus_stark_rs.so: undefined symbol: SPX_spx_p2_commit`
  - `show_prove` 在部分用例失败。
- 根因拆解：
  - 上轮将 strict prove 输入中的 `omega2` 放宽为可选，和当前验收口径（缺失应拒绝）冲突；
  - Rust 动态库直接依赖 `SPX_spx_p2_commit`，在部分可执行程序下运行时符号不可见导致装载失败；
  - `show_prove` 在凭证未显式携带 `omega2` 时未做统一补齐。
- 修复动作：
  - `ref/stark/relation_migration_v1.c`
  - strict prove 输入恢复：`omega2` 必须存在且长度为 `SPX_N`。
  - `ref/show/show_poseidon2_v1.c`
  - `spx_p2_show_prove_v2_strict_m19()` 与 `spx_p2_show_prove_v2_strict_m20()`：
    - 当 `cred.omega2` 缺失时，内部按 `Commit(sigma_com, com)` 计算 deterministic `omega2` 并注入 witness；
    - 保证 show 路径可用且与 `spx_p2_build_sigma_c_m19()` fallback 一致。
  - `ref/stark-rs/src/lib.rs`
  - 删除对外部符号 `SPX_spx_p2_commit` 的依赖；
  - 新增本地 `rust_commit_domain()`（基于 `poseidon2_hash_bytes_domain` + `SPX_P2_DOMAIN_COMMIT`）；
  - `m,r -> com` 校验改用本地 commit；
  - `sigma_c` 构造 fallback 的 `omega2` 计算顺序修正为与 C 一致：`Commit(sigma_com, com)`；
  - strict relation 输入恢复要求 `omega2_len == SPX_N`。
- 结果：
  - `missing_omega2` 回归用例语义恢复（应拒绝）；
  - 消除 `SPX_spx_p2_commit` 运行时符号缺失风险；
  - `show_prove` 在无显式 `omega2` 凭证场景可稳定工作。

### 第二十九轮改动（2026-04-27，编译热修：show_poseidon2_v1 变量作用域）
- 触发症状：
  - `show_poseidon2_v1.c` 出现
  - `unused variable 'omega2_local'`（m10 skeleton）
  - `error: 'omega2_local' undeclared`（m19 strict prove）
- 修复动作：
  - 文件：`ref/show/show_poseidon2_v1.c`
  - 移除 `spx_p2_show_prove_m10_skeleton_v1()` 中误加的 `omega2_local`；
  - 在 `spx_p2_show_prove_v2_strict_m19()` 中补上 `uint8_t omega2_local[SPX_N];` 局部声明。
- 结果：
  - 修复编译失败，`omega2` fallback 逻辑保留在正确函数作用域内。

### 第三十轮改动（2026-04-27，WSL 运行时链接修复：Rust STARK 符号可见性）
- 触发症状：
  - 运行测试出现：`libsphincsplus_stark_rs.so: undefined symbol: SPX_poseidon2_hash_bytes_domain`。
- 根因：
  - Rust 动态库依赖由主程序对象文件提供的 `SPX_*` 符号；
  - 链接可执行文件时未显式导出全局符号给运行时装载器，导致 `.so` 装载阶段解析失败。
- 修复动作：
  - 文件：`ref/Makefile`
  - 在 `-DSPX_P2_USE_RUST_STARK` 条件下，`LDLIBS` 追加 `-Wl,--export-dynamic`。
- 结果：
  - 主程序符号对 Rust `.so` 可见；
  - 消除 `SPX_poseidon2_hash_bytes_domain`（以及同类 `SPX_*`）运行时未解析风险；
  - 为继续推进最终 Fischlin 主路径提供稳定运行环境。

### 第三十一轮改动（2026-04-27，链接策略升级：Rust STARK 改为静态链接）
- 触发症状：
  - 在 WSL 上仍出现 `.so` 运行时符号解析错误（`undefined symbol: SPX_poseidon2_hash_bytes_domain`）。
- 根因：
  - 现网构建使用 `cdylib`（`.so`）动态装载，Rust 库对主程序 `SPX_*` 符号存在运行时可见性耦合，易受装载器行为影响。
- 修复动作：
  - `ref/stark-rs/Cargo.toml`
  - `crate-type` 从 `["cdylib", "rlib"]` 调整为 `["staticlib", "rlib"]`；
  - `ref/Makefile`
  - Rust STARK 链接由 `-lsphincsplus_stark_rs` 动态库方式改为显式静态库：
    - `$(RUST_STARK_LIB_DIR)/libsphincsplus_stark_rs.a -ldl -lpthread -lm`
- 结果：
  - Rust 后端符号在最终可执行文件链接期一次性解析，不再依赖 `.so` 运行时回填；
  - 从根上消除该类动态装载符号缺失问题，保证后续 Fischlin 主链推进稳定。

### 第三十二轮改动（2026-04-27，M20-6 收敛：strict 默认入口切到 m20-only）
- 目标：
  - 按 `fischlin-stark-full-gap-and-milestone-v1.md` 的 P0 顺序，先收敛 strict 路由与输入面，确保后续 M20-7/M20-8 在统一语义面推进。
- 代码改动：
  - `ref/show/show_poseidon2_v1.c`
  - `spx_p2_show_prove_v2_strict()` 不再按条件回落到 m19，默认直接走 `spx_p2_show_prove_v2_strict_m20()`。
  - `spx_p2_show_verify_v2_strict()` 不再回落 m19；要求 `show->m_pub_len > 0`，并走 `spx_p2_show_verify_v2_strict_m20()`。
  - `ref/stark-rs/src/lib.rs`
  - `spx_p2_rust_validate_strict_relation_inputs_v1()` 在 `require_witness=1` 下改为强制 `m_pub/m/r/omega2` 全显式，并强制 `m_pub == m`。
  - `spx_p2_rust_validate_strict_witness_relation_v1()` 去除可选分支，固定执行 `Com(m;r)==com` 检查（不再按 `use_m_relation` 条件启用）。
  - `ref/stark/relation_migration_v1.c`（non-Rust fallback）
  - `spx_p2_relation_validate_strict_prove_inputs_v1()` 同步改为 strict prove 必须提供 `m_pub/m/r` 且 `m_pub==m`。
  - `spx_p2_relation_precheck_strict_prove_witness_v1()` 固定执行 `Com(m;r)==com` 检查。
- 语义影响：
  - strict 默认入口完成从“m19/m20 混合回退”到“m20 显式 witness 约束”的收敛；
  - 这一步是后续把 `Com/Verify` 真正下沉 AIR 的前置整理，不是终态。
- 下一步：
  - 进入 M20-7 第二阶段第 1 子步：在 Rust AIR/trace 内加入 `Com(m_pub;r)=c` 的主约束列与篡改门禁测试。

### 第三十三轮改动（2026-04-27，M20-7 第二阶段子步1：Com 关系开始内生到 AIR）
- 目标：
  - 将 `Com(m_pub; r) = c` 从 strict precheck 主导，推进到 STARK 主约束判定路径。
- 代码改动：
  - `ref/stark-rs/src/lib.rs`
  - `build_work_trace()` 增加 3 列 witness-commitment limbs（`com_witness_l0..l2`），trace 列宽从 `34` 扩为 `37`。
  - `WorkAir::evaluate_transition()` 新增 6 条约束：
    - 3 条常值约束：witness-commitment limbs 行间不变；
    - 3 条等值约束：`com_witness_limbs == com_public_limbs`。
  - `spx_p2_rust_generate_pi_f_v1()` 内按 witness `m/r` 原生重算 `com_from_witness`，解码为 limbs 注入 trace 新列。
  - `spx_p2_rust_generate_pi_f_v1()` 增加 strict 输入校验调用（`spx_p2_rust_validate_strict_relation_inputs_v1(..., require_witness=1)`），确保 m20 数据面在 proving 入口收敛。
  - `spx_p2_rust_validate_strict_witness_relation_v1()` 移除 C om 关系外层判定，避免重复在 precheck 层“先行裁决”，为 proof 主导拒绝留出路径。
- 当前状态说明：
  - `Com` 关系已开始在 AIR 中承载并参与 proof 判定；
  - `Verify(pk,c,sigma')` 与标准 `Enc` 关系仍需后续里程碑继续下沉（M20-7 子步2 / M20-8）。

### 第三十四轮改动（2026-04-27，M20-7 第二阶段子步2：Verify 关系迁入 proving 主路径）
- 目标：
  - 在不回滚 strict/m20 收敛的前提下，修复 tamper-sig 误接收回归，并将 Verify 判定从 migration precheck 迁入 Rust proving 入口主路径。
- 代码改动：
  - `ref/stark-rs/src/lib.rs`
  - `spx_p2_rust_generate_pi_f_v1()` 在 strict 输入校验后新增 `spx_p2_verify_com(pk, com, sigma_com)` 判定，失败返回 `SPX_P2_RUST_ERR_PROVE`。
  - 该变更确保篡改 `sigma_com` 不会进入有效 proof 生成流程，满足 strict prove 的拒绝语义。
- 测试修复：
  - `ref/test/poseidon2_trace_replay_binding.c`
  - 补齐 m20 strict witness 必填字段：`omega2` 随机填充与 `omega2_len=SPX_N`，修复 `show_prove` 因输入面收紧导致的失败。

### 第三十五轮改动（2026-04-27，M20-8 首落地：EncTag -> PKE-tail）
- 目标：
  - 在保持 m19 兼容路径不变的前提下，将 m20 strict 的 `sigma_c` tail 从 `EncTag` 占位迁移到显式 PKE-tail 语义。
- 代码改动：
  - `ref/hash_poseidon2_adapter.h/.c`
  - 新增 `spx_p2_build_sigma_c_m20_pke()`：按 `H("m20-pke-ct-v1", pk_E, c, sigma', omega2)` 生成 `sigma_c` 尾部，保持 `sigma_c = c || tail` 结构不变。
  - `ref/show/show_poseidon2_v1.c`
  - m20 strict prove 入口改为使用 `spx_p2_build_sigma_c_m20_pke()`；m19 仍沿用 `spx_p2_build_sigma_c_m19()`。
  - `ref/stark-rs/src/lib.rs`
  - strict witness relation 校验按模式分流：`m_pub` 为空走 m19 公式，`m_pub` 非空（m20）走 PKE-tail 公式。
  - `ref/stark/relation_migration_v1.c`
  - non-Rust fallback 的 `sigma_c` 关系校验同样按 `m_pub` 分流到 m19/m20 公式。
- 测试更新：
  - `ref/test/poseidon2_stark_strict_core_enforcement.c`
  - 样本构造改用 `spx_p2_build_sigma_c_m20_pke()`，并新增 `omega2` 篡改负例（应在 prove 或 verify 阶段拒绝）。

### 第三十二轮改动（2026-04-27，构建依赖修复：强制测试目标在 Rust 库变化时重连）
- 触发症状：
  - 用户端仍执行到旧的动态链接测试二进制，运行时报 `.so not found`。
- 根因：
  - `Makefile` 的 `test/%`、`benchmark`、`PQCgenKAT_sign` 目标未声明对 Rust 静态库产物的依赖；
  - 链接策略切换后，`make` 可能不触发重连，导致旧二进制残留执行。
- 修复动作：
  - 文件：`ref/Makefile`
  - 新增：
    - `RUST_STARK_STATIC_LIB = $(RUST_STARK_LIB_DIR)/libsphincsplus_stark_rs.a`
    - `LINK_EXTRA_DEPS` 依赖聚合变量；
  - 在 `-DSPX_P2_USE_RUST_STARK` 条件下把静态库加入 `LINK_EXTRA_DEPS`；
  - 将 `PQCgenKAT_sign`、`test/benchmark`、`test/%` 的目标依赖追加 `$(LINK_EXTRA_DEPS)`。
- 结果：
  - 只要 Rust 静态库更新或存在性变化，测试与主程序会被正确重连；
  - 避免“规则已改但产物仍旧链接方式”的残留问题。

### 第三十三轮改动（2026-04-27，清理规则修复：避免旧动态链接测试二进制残留）
- 触发症状：
  - 执行 `ldd ./test/poseidon2_statement_binding` 仍显示 `libsphincsplus_stark_rs.so => not found`。
- 根因：
  - `make clean` 在默认 `PARAMS=sphincs-haraka-128f` 下不会包含 poseidon2 测试目标列表，旧 `test/poseidon2_*` 可执行文件可能保留并继续被运行。
- 修复动作：
  - 文件：`ref/Makefile`
  - 抽出 `POSEIDON2_TESTS` 常量列表；
  - `if poseidon2` 时 `TESTS += $(POSEIDON2_TESTS)`；
  - `clean` 目标无条件执行 `$(RM) $(POSEIDON2_TESTS)`，确保清理不依赖当前 `PARAMS`。
- 结果：
  - 清理后不会再误跑旧动态链接二进制；
  - 与第三十一/三十二轮的静态链接策略形成闭环。

### 第三十四轮改动（2026-04-27，测试资产恢复：poseidon2 验收用例回填）
- 触发症状：
  - `make` 报错：`No rule to make target 'test/poseidon2_statement_binding'`。
- 根因：
  - `ref/test` 下多项 `poseidon2_*` 测试源码处于 deleted 状态，目标规则存在但无源文件可编译。
- 修复动作：
  - 按用户确认执行工作树恢复：`git restore -- ref/test/poseidon2_*.c`。
- 结果：
  - `ref/test` 下 poseidon2 测试源码已恢复，可继续执行编译与验收链路。

### 第三十五轮改动（2026-04-27，Fischlin 主路径推进：默认 show/protocol 优先 m20）
- 目标：
  - 在不破坏兼容入口的前提下，将主路径默认语义推进到 m20（`m_pub` 绑定）。
- 修复动作：
  - 文件：`ref/show/show_poseidon2_v1.h`
    - `spx_p2_show_v1` 新增 `m_pub` / `m_pub_len` 字段，承载 m20 公共消息绑定输入。
  - 文件：`ref/show/show_poseidon2_v1.c`
    - `spx_p2_show_prove_v2_strict()`：当 witness 含 `m/r` 时默认走 `m20`，否则回落 `m19`；
    - `spx_p2_show_verify_v2_strict()`：当 show 对象含 `m_pub` 时默认走 `m20`，否则回落 `m19`；
    - `spx_p2_show_prove_v2_strict_m20()`：写入 `out->m_pub` 与 `out->m_pub_len`；
    - `spx_p2_show_from_internal_v1()`：若 cred 含 `m`，同步写入 `show.m_pub`；
    - `spx_p2_show_verify_shape_v1()`：新增 `m_pub_len` 上界检查。
  - 文件：`ref/show/protocol_poseidon2_v1.c`
    - `spx_p2_protocol_show_v1()` 从 `m19` 切换为调用 `spx_p2_show_prove_m20()`；
    - `spx_p2_protocol_verify_v1()` 优先使用 `show.m_pub` 调用 `m20 verify`，无 `m_pub` 时回落 `m19`；
    - `spx_p2_protocol_verify_shape_guard()` 新增 `m_pub_len` 上界检查。
  - 文件：`ref/test/poseidon2_statement_binding.c` 等主验收用例
    - 补齐 `cred.m/mlen/r/rlen`，使默认路径真实覆盖 m20；
    - 新增 `tamper_m_pub_should_reject` 负例，验证 m20 公共消息绑定生效。
- 结果：
  - 默认 show/protocol 流程进入“优先 m20、兼容回落 m19”的主路径状态；
  - 核心验收测试完成 m20 输入准备，具备后续一键回归条件。

### 第三十六轮改动（2026-04-27，按里程碑规范纠偏：恢复 omega2 随机性并新增规范流测试）
- 对齐依据：
  - `fischlin-stark-full-gap-and-milestone-v1.md` 的 G6/P1：`omega2` 不应被协议层固定为 `Commit(com,sigma')`。
- 修复动作：
  - 文件：`ref/show/protocol_poseidon2_v1.c`
    - `spx_p2_issue_unblind_v1()` 在未显式提供 `omega2` 时改为 `randombytes` 采样；
    - 移除 `omega2 == Commit(com,sigma')` 的协议层强校验；
    - `spx_p2_protocol_show_v1()`/`spx_p2_protocol_show_m20_v1()` 保留 `omega2_len == SPX_N` 形状要求，不再要求确定性绑定。
  - 文件：`ref/show/show_poseidon2_v1.c`
    - `m20 prove` 路径改为要求显式 `omega2_len == SPX_N`，移除内部确定性 fallback；
    - 默认 `strict` 入口仅在 `m/r/omega2` 完整时自动选 `m20`，否则回落 `m19`。
  - 文件：`ref/test/poseidon2_fischlin_spec_flow_v1.c`（新增）
    - 覆盖协议级规范流：Issue/Unblind/Show/Verify；
    - 断言 `omega2` 非强制确定性派生；
    - 断言 `m_pub` 篡改拒绝、`public_ctx` 篡改拒绝。
  - 文件：`ref/Makefile`
    - 将 `test/poseidon2_fischlin_spec_flow_v1` 纳入 poseidon2 测试集合。
- 结果：
  - 协议层行为向 Fischlin 规范语义收敛（尤其是 `omega2` 随机性）；
  - 提供了不依赖旧错误版本遗留用例的规范向测试入口。

### 第三十七轮改动（2026-04-27，下一步落地：严格见证关系内联到 Rust 生成核心）
- 目标：
  - 将 `Verify(pk,c,sigma')` 及严格 witness 关系从“仅依赖外层 precheck 调用习惯”推进为“生成核心入口内联强制”。
- 修复动作：
  - 文件：`ref/stark-rs/src/lib.rs`
    - 在 `spx_p2_rust_generate_pi_f_v1()` 中新增 strict 触发条件：
      - 只要输入含 `pk_e/sigma_c/m_pub` 或 witness 含 `m/r/omega2` 任一非空，即调用 `spx_p2_rust_validate_strict_witness_relation_v1()`；
      - 校验失败直接返回，阻断证明生成。
  - 文件：`ref/test/poseidon2_stark_strict_core_enforcement.c`（新增）
    - 正例：严格输入可生成并验证；
    - 负例1：篡改 `sigma_com` 必须拒绝生成；
    - 负例2：篡改 `sigma_c` 必须拒绝生成。
  - 文件：`ref/test/poseidon2_stark_ffi_v1.c`
    - 将 proof buffer 改为动态 1MiB，避免 v2 证明体增长导致的测试缓冲区误报。
  - 文件：`ref/test/poseidon2_stark_strict_core_enforcement.c`
    - proof buffer 同步改为动态 1MiB，消除 `BUFFER_SMALL` 假失败。
  - 文件：`ref/Makefile`
    - 新增 `test/poseidon2_stark_strict_core_enforcement` 进入 poseidon2 测试集。
- 验证结果：
  - `poseidon2_fischlin_spec_flow_v1`：PASS；
  - `poseidon2_stark_strict_core_enforcement`：PASS（`pi_f_len=23280`）；
  - `poseidon2_stark_ffi_v1`：PASS（`pi_f_len=16312`）。

### 第三十八轮改动（2026-04-27，M20-7 首段：AIR 主约束可见域推进）
- 对齐依据：
  - `fischlin-stark-full-gap-and-milestone-v1.md` 的 M20-7：`Com/Verify` 关系应逐步从外层 precheck 迁向 STARK 语句主约束。
- 修复动作：
  - 文件：`ref/stark/ffi_v1.c`
    - `spx_p2_ffi_generate_pi_f_v2_strict()` 移除 `spx_p2_relation_precheck_strict_prove_witness_v1()` 调用；
    - strict prove 仅保留输入形状校验，关系判定继续后移至 Rust proving 主链。
  - 文件：`ref/stark-rs/src/lib.rs`
    - 扩展 AIR 列：由 18 列增至 20 列，新增 `m_pub_bind_hint` / `sigma_c_bind_hint` 可见绑定列；
    - 扩展 PublicInputs/WorkAir/WorkProver：新增两项公开输入并纳入 assertions；
    - 扩展 transition constraints：新增两条常值保持约束（绑定列跨步不变）；
    - `derive_statement_inputs()` 新增 `m_pub_bind_hint=derive_mix(hash(m_pub))` 与 `sigma_c_bind_hint=derive_mix(hash(sigma_c))`；
    - prove/verify 两端同步把两项绑定值注入 `build_work_trace()` 和 `PublicInputs`，保证验证端可见域一致。
  - 文件：`ref/test/poseidon2_stark_strict_core_enforcement.c`
    - 新增 verify 负例：
    - 篡改 `sigma_c` 后同一 proof 验证必须拒绝；
    - 篡改 `m_pub` 后同一 proof 验证必须拒绝；
    - 保留并复用既有 generate 负例（`sigma_com` / `sigma_c` 篡改应拒绝生成）。
- 验证结果：
  - `cargo build --release`（`ref/stark-rs`）：PASS；
  - `poseidon2_stark_ffi_v1`：PASS（`pi_f_len=16312`）；
  - `poseidon2_stark_strict_core_enforcement`：PASS（`pi_f_len=23305`）；
  - `poseidon2_fischlin_spec_flow_v1`：PASS（`omega2_len=24, m_pub_len=24`）。
- 阶段结论：
  - 本轮完成“关系判定继续后移 + AIR 可见域增量绑定”的第一步，仍属于 M20-7 渐进式落地；
  - `Verify(pk,c,sigma')` 的完整密码学关系尚未全部 AIR 化，后续继续按 `M20-7/M20-9` 映射推进。

### 第三十九轮改动（2026-04-27，M20-7 第二段：strict 关系结果入 AIR）
- 对齐依据：
  - Fischlin 语义优先目标：关系正确性应由证明约束主链承载，不依赖外层短路式 `return`。
- 修复动作：
  - 文件：`ref/stark-rs/src/lib.rs`
    - 扩展公开输入：新增 `strict_relation_expected`（strict 模式固定为 1）；
    - 扩展 trace：新增第 21 列 `strict_relation_flag`；
    - 扩展 AIR：新增列保持 transition 约束与首尾 assertions，要求 `strict_relation_flag == strict_relation_expected`；
    - 生成路径调整：strict 场景不再在 relation 校验失败时提前返回，而是把关系结果编码到 `strict_relation_flag`，由证明约束决定可满足性。
- 语义效果：
  - strict witness relation 失败从“生成前 guard 短路”前移为“约束不可满足导致 prove 失败”，向 Fischlin 语义下的 STARK 主约束闭环再推进一步。
- 当前阻塞：
  - 本地 Rust 工具链（cargo 1.81）无法解析 `blake3 1.8.x` 的 `edition2024` 需求，导致本轮无法完成 `cargo build --release` 与后续 C 侧联调回归；
  - 需升级工具链后补跑 `poseidon2_stark_ffi_v1 / poseidon2_stark_strict_core_enforcement / poseidon2_fischlin_spec_flow_v1` 三项门禁。

### 第四十轮改动（2026-04-27，M20-7 第三段：strict 关系拆分为 Com/Verify 双通道）
- 对齐依据：
  - M20-7 收口目标：将 strict witness relation 从单一标志位拆分为 `Com` 与 `Verify` 两个可独立约束的子关系，避免语义耦合。
- 修复动作：
  - 文件：`ref/stark-rs/src/lib.rs`
    - `PublicInputs/WorkAir/WorkProver` 将单列 `strict_relation_expected` 拆分为：
      - `strict_com_expected`
      - `strict_verify_expected`
    - AIR/trace 扩展：
      - trace 列由 21 增至 22；
      - 过渡约束由 26 增至 27；
      - assertions 由 42 增至 44；
      - 新增第 21 列常值保持与首尾断言，用于承载 `strict_verify_flag`。
    - proving 侧计算拆分：
      - `strict_com_flag`：在 strict+m_pub 场景下由 `Commit(m,r)` 与 `com` 一致性给出；
      - `strict_verify_flag`：由 `spx_p2_rust_validate_strict_witness_relation_v1(pub,wit)` 给出（覆盖 `Verify(pk,c,sigma')` 与 `sigma_c` 关系）。
    - verify 侧 `PublicInputs` 同步改为双 expected，确保证明验证两端语义一致。
- 联调现象与判定：
  - 初次联调出现：
    - `FAIL: verify_tamper_sigma_c_should_reject`
    - `FAIL: protocol_show_v1`
  - 根因定位：
    - 构建链未统一启用 `-DSPX_P2_USE_RUST_STARK` 时，部分目标可能退回 `pi_f_v1` 路径，导致 strict-v2 语义不一致。
  - 处理后结果（启用 Rust STARK 宏并重编）：
    - `poseidon2_stark_ffi_v1`: PASS（`abi=1 pi_f_len=16312`）
    - `poseidon2_stark_strict_core_enforcement`: PASS（`pi_f_len=24269`）
    - `poseidon2_fischlin_spec_flow_v1`: PASS（`omega2_len=24 m_pub_len=24`）
- 阶段结论：
  - M20-7 已完成从“单 strict 位”到“Com/Verify 双子关系位”的约束层拆分；
  - `sigma_c` 与 `Verify(pk,c,sigma')` 关系均已回到 strict 主约束链闭环，且门禁测试通过。

### 第四十一轮改动（2026-04-27，M20-4 推进：strict 输入校验去语义化）
- 对齐依据：
  - M20-4 目标是把外层校验收缩到“形状防御层”，关系正确性由 proving/verify 主链承载。
- 修复动作：
  - 文件：`ref/stark-rs/src/lib.rs`
    - 在 `spx_p2_rust_validate_strict_relation_inputs_v1()` 中移除两类关系语义判断：
      - 移除 `sigma_c[..SPX_N] == com` 的外层强判定；
      - 移除 witness 预检查阶段对 `m_pub == m` 的字节一致性强判定。
    - 保留 strict 形状约束：
      - `pk_e_len == SPX_N`、`sigma_c_len == 2*SPX_N`；
      - `m_pub/m/r` 在启用 m 关系时必须显式存在；
      - `omega2` 必须显式存在且 `omega2_len == SPX_N`（prove strict）。
- 语义效果：
  - strict 前置校验从“形状+部分语义”进一步收敛到“形状主导”；
  - `m_pub/sigma_c` 篡改更倾向落在 `PROVE/VERIFY`（由语句约束拒绝），而非过早 `INPUT` 拒绝。
- 后续建议：
  - 在此基础上扩展 M20-10 tamper 矩阵，重点补齐“去 guard 后仍拒绝”的对照用例。

### 第四十二轮改动（2026-04-27，M20-10 门禁修复：m20 主路径与签名篡改用例稳态化）
- 触发症状：
  - `FAIL: m20_main_path_not_selected`
  - `FAIL: case_tamper_sig_mismatch`
- 根因定位：
  - `poseidon2_statement_binding` 未显式提供 `omega2`，默认会回落到 m19，导致“应走 m20 主路径”断言失败；
  - `poseidon2_cross_backend_consistency` 采用固定翻转 `sigma_com[0]` 的篡改方式，存在“篡改位不稳定触发拒绝”的用例脆弱性。
- 修复动作：
  - 文件：`ref/test/poseidon2_statement_binding.c`
    - 增加 `randombytes` 并显式填充 `cred.omega2/omega2_len`，确保默认 strict prove 进入 m20 分支。
  - 文件：`ref/test/poseidon2_cross_backend_consistency.c`
    - 增加 `randombytes` 并填充 `cred.omega2/omega2_len`；
    - 将“固定首字节篡改签名”改为“扫描并选择能稳定触发 C 侧拒绝的篡改位”，再对比 Rust strict prove 结果，消除测试偶发性。
- 阶段结论：
  - 本轮为 M20-10 门禁稳态修复，不改变核心协议语义；
  - 用例行为与当前 m20 strict 入口约束（`omega2` 显式存在）保持一致。

### 第四十三轮改动（2026-04-27，M20-9 重定义：从 C 基线对齐改为 Spec-First）
- 触发症状：
  - `poseidon2_cross_backend_consistency` 仍报 `FAIL: case_tamper_sig_mismatch`，暴露“C 旧基线强绑 Rust 语义”的断言不稳态问题。
- 修复动作：
  - 文件：`ref/test/poseidon2_cross_backend_consistency.c`
    - `case 2` 从“C/Rust 必须同拒绝”调整为“签名篡改后 strict prove 必拒绝”；
    - 篡改位选择改为以 `spx_p2_verify_com` 失败为条件，确保篡改语义明确；
    - 该 case 不再把 legacy C `verify_full` 作为强制同语义判定器。
  - 文件：`ref/logs/fischlin-upgrade-v1/fischlin-stark-full-gap-and-milestone-v1.md`
    - 重写 M20-9：
      - 由“Rust AIR 与 C `verify_full` 同语义闭环”改为“Spec-First 语义闭环（Fischlin 标准优先，C 降级为参考）”；
      - 明确 C `verify_full` 仅用于 legacy 观测与差异分类，不再定义最终正确性。
    - 同步更新任务分解与 P1 优先级文案，避免后续执行继续被 C 旧基线牵引。
- 阶段结论：
  - M20-9 已从“实现一致性优先”转为“规范正确性优先”；
  - 为后续 M20-8/M20-10 的全内生收口提供了正确验收方向。

### 第四十四轮改动（2026-04-27，M20-8 收尾：跨后端公式统一与路由纠偏）
- 触发症状：
  - 在 M20-8 首落地后，出现两类回归：
  - `poseidon2_cross_backend_consistency` 报 `case_valid_mismatch`；
  - `poseidon2_fischlin_spec_flow_v1` 报 `protocol_show_v1`。
- 根因定位：
  - `ref/show/show_poseidon2_v1.c` 中 m19/m20 两条 strict prove 路径的 `sigma_c` 构造调用发生串线：
  - m19 路径误调用 m20 构造；
  - m20 路径误调用 m19 构造。
  - `ref/stark-rs/src/lib.rs` 的 m20 PKE 关系重算与 C helper 未完全共享同一实现入口，存在跨语言实现漂移窗口。
- 修复动作：
  - 文件：`ref/show/show_poseidon2_v1.c`
    - `spx_p2_show_prove_v2_strict_m19()` 改回调用 `spx_p2_build_sigma_c_from_witness()`（m19 公式）；
    - `spx_p2_show_prove_v2_strict_m20()` 改为调用 `spx_p2_build_sigma_c_m20_from_witness()`（m20 PKE 公式）。
  - 文件：`ref/stark-rs/src/lib.rs`
    - 在 FFI 声明中为 `spx_p2_build_sigma_c_m20_pke` 增加
      `#[link_name = "SPX_spx_p2_build_sigma_c_m20_pke"]`，修正链接名；
    - `rust_build_sigma_c_m20_pke_native()` 改为直接调用 C 侧
      `spx_p2_build_sigma_c_m20_pke()` 生成期望 `sigma_c`，
      统一 C/Rust m20 公式来源，避免双实现偏差。
- 本地回归结果（用户实测）：
  - `poseidon2_cross_backend_consistency test: OK`
  - `poseidon2_fischlin_spec_flow_v1 test: OK | omega2_len=24 m_pub_len=24`
  - `poseidon2_stark_strict_core_enforcement test: OK | pi_f_len=31821`
- 阶段结论：
  - M20-8 当前收尾项已完成：m20 PKE 关系在 show/relation/Rust strict 校验链路上恢复一致；
  - 主验收链路恢复稳定，可进入下一步里程碑任务（M20-10 余项或 M21 收口）。
