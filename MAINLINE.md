# Mainline Workspace

当前仓库已按”主线开发区 / 归档区”整理。

主线开发优先查看：

- `ref/stark-rs/src/air_engine.rs` — 全内生 STARK AIR（核心）
- `ref/stark-rs/src/trace_builder.rs` — SPHINCS+ 验证跟踪构建器
- `ref/stark-rs/src/lib.rs` — 旧版混合证明模型（兼容保留）
- `ref/stark/ffi.h` / `ffi.c` — C FFI 接口（含 full-air 新路径）
- `ref/show/` — Fischlin show/protocol 层
- `ref/params/params-sphincs-poseidon2-128f-small.h` — 开发参数
- `ref/scripts/` — 测试/基准脚本
- `ref/test/` — C 侧测试

已归档到仓库根目录 `_archive/` 的内容包括：

- 论文材料与写作草稿
- 历史开发日志（M12-M17 等旧里程碑已删除，仅保留主线日志）
- 非主线后端目录
- 构建缓存、临时参数与中间产物

如果要回溯历史资料，请从 `_archive/README.md` 开始。
