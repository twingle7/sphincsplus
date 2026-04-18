# pi_F 生成落地方案 v1（M10）

## 1. 目标与范围
- 目标：把当前 `verify_full` 约束系统从“可调试 AIR harness”推进到“可生成并验证 `pi_F` 的展示层对象”。
- 范围：
  - 先落地 **最小可跑通 M10 骨架**（非最终零知识）；
  - 再升级到 **完整 STARK/Fri 证明对象**（最终版本）。

## 2. 最佳实现路径（推荐）
- 推荐框架：`Winterfell`（Rust，AIR-first）。
- 推荐原因：
  - 与当前 `stark/air_*` 分层高度一致；
  - 证明对象、trace table、约束合成路径清晰；
  - 工程化接入成本低于重型框架改造。

## 3. 当前骨架实现（本仓库）
- 已新增骨架模块：
  - `stark/prover_v1.h/.c`
  - `stark/verifier_v1.h/.c`
  - `show/show_poseidon2_v1.h/.c` 新增 M10 骨架接口
- 当前 `pi_F` 格式（骨架版）：
  - 头：`magic/version/flags/sigma_len`
  - 绑定域：`ctx_binding = H(public_ctx)`（M10.1 已接入）
  - 体：`sigma_com`（仅骨架临时保留）+ `verify_full_proof_v1(commitment,constraint_count,violation_count)`
- 骨架特性：
  - 可跑通 `show_prove -> show_verify`；
  - 可对 `com/pi_F` 篡改进行失败检测；
  - **非零知识**（因为骨架 `pi_F` 携带 `sigma_com`）。

## 4. TODO 列表（按优先级）

### P0（M10 必做）
- [x] 定义 `pi_F_v1` 骨架序列化格式（字段版本化、长度前缀、proof meta）。
- [x] 将 `show_prove/show_verify` 接到 `pi_F_v1` 骨架对象。
- [x] 增加 `test/poseidon2_show_v1.c` 的篡改测试矩阵（`com/pi_F/public_ctx`）。
- [x] 冻结 `pi_F_v1` 最终字节级规范（含 Rust FFI 兼容字段保留区）。

### P1（M10->M11 过渡）
- [ ] 在 Rust 侧实现 `trace -> LDE -> composition -> FRI` 的真正 prover。
- [ ] C 侧仅负责 witness/输入构建，proof 生成迁移到 Rust 后端。
- [ ] 增加 C/Rust FFI 边界层（稳定 ABI + 错误码）。

### P2（最终零知识版本）
- [ ] 从 `pi_F` 中移除 `sigma_com` 序列化字段（`sigma_com` 继续作为 prover 私有 witness）。
- [ ] 增加零知识隐藏检查与公开输入最小化检查。
- [ ] 完成 `Show_v1 = (com, pi_F, public_ctx)` 的最终安全审阅。

## 5. 风险与规避
- 风险 1：骨架版 `pi_F` 含私有签名，不能用于最终隐私目标。  
  - 规避：仅作 M10 接口打通，M11 前必须替换为纯 STARK proof。
- 风险 2：trace 采集口径不稳定导致 proof 不可复现。  
  - 规避：冻结 `trace/witness` 版本号并做向后兼容。
- 风险 3：跨语言后端接入时序列化不一致。  
  - 规避：先冻结字节序与字段定义，再做 FFI。

## 6. 里程碑验收（M10 最小）
- `test/poseidon2_show_v1` 可编译并通过。
- `show_prove_m10_skeleton_v1` 成功生成 `pi_F`。
- `show_verify_m10_skeleton_v1` 可验证通过，且篡改 `com/pi_F` 失败。

## 7. M10.2 结果
- 新增 `stark/pi_f_format_v1.h/.c`，形成独立 `pi_F` 编码/解码层。
- `pi_F` 固定头字段冻结为：
  - `magic`、`version`、`flags`
  - `header_len`、`total_len`、`proof_system_id`
  - `ctx_binding`、`sigma_com`、`commitment`
  - `constraint_count`、`violation_count`
  - `reserved[2]`（为 Rust FFI 扩展预留，v1 解析时必须为全 0）
- `prover_v1/verifier_v1` 已统一走格式层，避免手写偏移散落在业务代码中。
