# `ref/` 目录说明

本目录在原始 `SPHINCS+` reference implementation 的基础上，承载当前正在维护的
`Poseidon2 + show/verify + STARK` 主链实现。

为保持主线目录干净，论文材料、历史日志、阶段性结果和非主线资产已迁移到仓库根目录
`_archive/` 下分类归档。

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
    - `stark/show_proof_format.h`
    - `stark/stats.h`
- `stark-rs/`
  - Rust STARK 后端，实现当前 strict 主链使用的真实 prove/verify。
- `test/`
  - 当前保留的回归、接口、格式、一致性和 benchmark 测试。
- `scripts/`
  - 参数搜索、benchmark、结果打包脚本。

## 当前约定

- `show/` 与 `stark/` 下的无版本头文件是当前唯一正式入口。
- 若某些源码文件名仍带 `_v1`，它们只表示仓库内部实现文件尚未重命名，不再代表对外版本化接口。
- 新增代码不要再依赖已删除的 `v0` 原型或 `show_v1` 骨架测试。

## 归档位置

- `_archive/experiment-results/logs/`
  - 原 `ref/logs/` 的开发日志、实验日志、规范草案与阶段性结果。
- `_archive/experiment-results/final-results-v1/`
  - 原 `ref/final-results-v1/` 的交付快照与归档材料。
- `_archive/paper-materials/`
  - 原根目录论文草稿与 `ref/毕设材料/`。

这些内容保留供回溯和写作使用，但都不是当前开发应优先修改的主线目录。

## 当前正式入口

- Show:
  - `spx_p2_show_prove()`
  - `spx_p2_show_verify()`
  - `spx_p2_show_prove_statement_bound()`
  - `spx_p2_show_verify_statement_bound()`
- Protocol flow:
  - `spx_p2_prepare_issue_request()`
  - `spx_p2_issue_respond()`
  - `spx_p2_finalize_credential()`
  - `spx_p2_issue_finalize()`
  - `spx_p2_protocol_show()`
  - `spx_p2_protocol_verify()`
- STARK FFI:
  - `spx_p2_ffi_generate_pi_f()`
  - `spx_p2_ffi_verify_pi_f()`
- Stats:
  - `spx_p2_stark_collect_stats()`
  - `spx_p2_stark_collect_ffi_stats()`

## 不再保留的内容

- `bsig_poseidon2_v0.*`
- `test/poseidon2_bsig_v0.c`
- `test/poseidon2_show_v1.c`
- `test/poseidon2_show_v1_boundary.c`
- 若需要回溯历史演化，请查看 `_archive/experiment-results/logs/开发日志.md`。
