# `ref/` 目录说明

本目录在原始 `SPHINCS+` reference implementation 的基础上，承载当前正在维护的
`Poseidon2 + show/verify + STARK` 主链实现。

## 当前应关注的目录

- `show/`
  - 展示对象与协议流入口。
  - 新代码优先包含：
    - `show/show_poseidon2.h`
    - `show/protocol_poseidon2.h`
- `stark/`
  - C 侧 witness、格式、FFI、统计与兼容校验层。
  - 新代码优先包含：
    - `stark/ffi.h`
    - `stark/pi_f_format.h`
    - `stark/stats.h`
- `stark-rs/`
  - Rust STARK 后端，实现当前 strict 主链使用的真实 prove/verify。
- `test/`
  - 当前保留的回归、接口、格式、一致性和 benchmark 测试。
- `scripts/`
  - 参数搜索、benchmark、结果打包脚本。

## 历史兼容层

- 文件名带 `_v1` 的头文件或源码仍然保留，但定位为：
  - 历史 ABI 兼容；
  - 低层迁移测试；
  - 版本化格式或阶段性实验的维护入口。
- 新增代码默认不要直接依赖这些 `_v1` 头文件，除非你明确在做：
  - 旧 proof 格式兼容；
  - 版本化接口回归；
  - 低层迁移调试。

## 文档与结果

- `logs/`
  - 开发日志、设计说明、规范草案与阶段性实验记录。
  - 这是“工作记录区”，不是对外 API 的真源文档。
- `final-results-v1/`
  - 已归档的发布材料与结果快照。
  - 这是“交付产物区”，不是当前开发应优先修改的目录。

## 当前正式入口

- Show:
  - `spx_p2_show_prove()`
  - `spx_p2_show_verify()`
- Protocol flow:
  - `spx_p2_issue_request()`
  - `spx_p2_issue_sign()`
  - `spx_p2_unblind()`
  - `spx_p2_protocol_show()`
  - `spx_p2_protocol_verify()`
  - `spx_p2_protocol_show_strict_public()`
  - `spx_p2_protocol_verify_strict_public()`
- STARK FFI:
  - `spx_p2_ffi_generate_pi_f()`
  - `spx_p2_ffi_verify_pi_f()`
- Stats:
  - `spx_p2_stark_collect_stats()`
  - `spx_p2_stark_collect_ffi_stats()`

## 不再保留的内容

- 早期 `deprecated/` 目录中的旧版本演示测试已经移除。
- 若需要回溯历史演化，请查看 `logs/开发日志.md`。
