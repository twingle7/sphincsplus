# Fischlin 升级文档目录（v1）

## 1. 目录目的
- 记录“从 Fischlin-like 到 Fischlin-Strict”的技术设计、实现决策与开发过程。
- 统一协议语句、接口语义、约束映射和实验口径，避免文档分散造成漂移。

## 2. 文档清单
- `fischlin-technical-spec-v1.md`：Fischlin-Strict 技术规范与冻结口径。
- `fischlin-devlog-v1.md`：开发日志（阶段进展、风险、决策、待办）。
- `fischlin-milestone-deliverables-v1.md`：里程碑、交付物与验收清单。
- `fischlin-stark-full-gap-and-milestone-v1.md`：完整 STARK 闭环差距评估与新版技术里程碑。

## 3. 使用约定
- 所有“语句定义”改动必须先更新技术规范，再改代码。
- 所有“接口/格式”变更必须同步更新里程碑交付清单。
- 每次阶段性提交后必须更新开发日志（至少包含：变更、验证、风险）。
- 开发日志按“轮次”独立分段记录（如“第一轮/第二轮”），避免跨轮混写。

## 4. 与上游文档关系
- 总路线图基线：`../fischlin-full-framework-roadmap-v1.md`。
- 盲签协议语义基线：`../fischlin-blind-sign-spec-v1.md`。

## 5. 当前版本状态
- 当前版本：`v1`（M19 已收口，M20-1 流程编排首轮已落地）。
