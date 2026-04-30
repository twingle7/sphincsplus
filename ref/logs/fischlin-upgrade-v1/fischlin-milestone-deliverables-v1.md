# Fischlin-Strict 里程碑与交付清单（v1）

## 目标
- 给 `fischlin-upgrade-v1` 专题工作区提供一个“可交付物索引”。
- 将技术规范、开发日志、缺口分析和最终方案之间的关系固定下来。

## 当前文档角色
- `fischlin-technical-spec-v1.md`
  - 作为 Fischlin-Strict 语义、接口与约束映射的规范真源。
- `fischlin-devlog-v1.md`
  - 作为专题开发日志，记录每轮改动、验证、风险与决策。
- `fischlin-stark-full-gap-and-milestone-v1.md`
  - 作为严格 STARK 闭环差距、收口优先级与阶段计划。
- `最终版方案.md`
  - 作为较完整的最终方案草案。
- `Fischlin盲签框架的完整定义.md`
  - 作为更偏理论和定义层的参考材料。

## 已交付
- `Poseidon2` 替换 `SPHINCS+` 底层哈希的工程主链。
- `show/prove/verify` 的 strict Rust STARK 主链。
- `final` 演示链：
  - `poseidon2_roles_interaction`
  - `poseidon2_fischlin_blind_e2e`
- `SHA2 vs Poseidon2` 的约束 / proof 对比支线与独立日志。

## 待继续收口
- `Com / Verify / Enc` 关系进一步下沉到 AIR 主约束。
- `pk_E` 作为独立公开量的口径与测试矩阵继续收口。
- 专题文档中的阶段号表述继续替换为描述性命名。

## 使用约定
- 修改 Fischlin-Strict 语义前，先改 `fischlin-technical-spec-v1.md`。
- 修改实现收口状态前，更新 `fischlin-stark-full-gap-and-milestone-v1.md`。
- 修改专题开发过程记录时，更新 `fischlin-devlog-v1.md`。
