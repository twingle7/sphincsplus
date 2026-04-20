# STARK-RS 完整证明落地路线图 v1

## 1. 目标定义
- 最终目标：在现有 `C + Rust` 架构下，交付“完整且真实”的 STARK 证明与验证路径。
- 范围限定：
  - 保持 C 侧接口层（Show/FFI）可用；
  - 不要求 C 侧独立实现完整 STARK prover/verifier；
  - 由 Rust 后端承担真实 STARK 证明系统主体。

## 2. 当前状态
- 已完成：
  - `pi_F_v2` 格式冻结与 strict 路径接入；
  - `final` 无版本号接口主线；
  - 三角色演示与 e2e 基础回归；
  - 关键工程故障修复（链接、prover/verify 公共输入不一致、strict 前置验签）。
- 未完成核心：
  - Rust AIR 与 C `verify_full` 逐项同语义对齐仍未闭环。

## 3. 关键差距
- 语句完整性差距：
  - Rust 端目前证明语句仍偏工程化，尚未覆盖 C `air_verify_full` 的全部约束语义。
- 一致性差距：
  - 缺少“C 约束项 -> Rust 约束项”的逐项映射与自动化一致性验证矩阵。
- 交付差距：
  - benchmark 与发布复核目前以模板为主，缺少最终实测数据闭环。

## 4. 分阶段执行计划
### 阶段 A：Statement Freeze（立即执行）
- 冻结 `public_input_digest/ctx_binding/statement_version` 口径。
- 统一 Rust prover/verifier 的 statement 派生函数，禁止分叉。
- 验收：
  - 同一输入派生值稳定一致；
  - 关键绑定字段篡改稳定拒绝。

### 阶段 B：约束映射与最小闭环
- 产出 C `verify_full` -> Rust AIR 约束映射表。
- 先覆盖硬约束优先项：
  - `verify_com`、trace replay、一致性重建、根绑定。
- 验收：
  - 覆盖项具备对应单测与负例。

### 阶段 C：完整语义对齐
- 逐项补齐模块约束（PRF/THASH/HASH_MESSAGE/MERKLE 等）。
- 扩展到与 C `verify_full` 等价的公开输入语义与拒绝行为。
- 验收：
  - C/Rust 在共同样本集上同接受/拒绝结论；
  - 无“C 过 / Rust 拒”或“C 拒 / Rust 过”的未解释差异。

### 阶段 D：发布收口（M17 第三阶段）
- 填充 benchmark 实测数据；
- 完成一致性报告与发布 checklist 勾选闭环。
- 验收：
  - 形成可复核交付包（代码、测试、报告、结论）。

## 5. 风险与缓释
- 风险 1：statement 定义漂移导致证明不兼容。
  - 缓释：集中派生函数 + 版本化声明 + 篡改测试。
- 风险 2：约束映射不完整导致“伪完整”。
  - 缓释：逐项映射表 + 覆盖率清单 + 负例矩阵。
- 风险 3：后端工具链差异影响联调。
  - 缓释：明确构建前置条件，固定 Rust 版本区间并记录环境。

## 6. 完成判据
- `final` 路径仅接受真实 `pi_F_v2` 且由 Rust STARK 后端生成/验证；
- Rust AIR 与 C `verify_full` 完整同语义；
- benchmark/一致性/发布检查三项全部实测完成并存档。
