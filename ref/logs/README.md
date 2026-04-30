# `logs/` 使用说明

本目录保存的是开发过程中的“工作记录”，而不是稳定 API 的单一真源。

## 建议阅读顺序

- 想看当前实现结论：
  - `project-final-summary-v1.md`
  - `release-checklist-v2.md`
  - `blind-sign-e2e-v2.md`
  - `thesis-notes-stark-v2.md`
- 想看严格路径剩余缺口：
  - `fischlin-upgrade-v1/fischlin-stark-full-gap-and-milestone-v1.md`
- 想看 `SHA2 vs Poseidon2` 真实约束/证明对比支线：
  - `开发日志-方案B-THASH-exact.md`
- 想看 Fischlin-Strict 专题设计与专题开发日志：
  - `fischlin-upgrade-v1/README.md`
- 想回溯细节：
  - `开发日志.md`

## 使用约定

- `开发日志.md`
  - 作为主项目主线开发流水记录。
  - 轮次应保持主线单调连续，不与专题/支线 round 编号合并。
- `开发日志-方案B-THASH-exact.md`
  - 作为 `THASH exact / sha2_exact` 对比研究支线日志。
- `fischlin-upgrade-v1/fischlin-devlog-v1.md`
  - 作为 Fischlin-Strict 专题开发日志，独立于主线轮次维护。
- 以 `spec`、`summary`、`checklist` 命名的文档
  - 可作为阶段性结论参考。
- `benchmark-*`、`params-*`
  - 属于实验与参数搜索产物。
- `protocol-v0.md`、`trace-spec-v0.md`
  - 保留为早期阶段资料，仅供历史追溯。

## 当前接口真源

若你要修改代码接口，请优先以这些头文件为准，而不是先看日志：

- `show/show_poseidon2.h`
- `show/protocol_poseidon2.h`
- `stark/ffi.h`
- `stark/pi_f_format.h`
- `stark/stats.h`
