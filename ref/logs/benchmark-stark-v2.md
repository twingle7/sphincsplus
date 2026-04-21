# benchmark-stark-v2（M17）

## 指标口径
- `trace_calls`：`HashCall` 调用数
- `trace_lanes`：trace lane 数
- `witness_rows`：witness 行数
- `proof_bytes`：`pi_F` 字节长度
- `proof_magic`：证明对象 magic（`PFP1` 或 `PFP2`）
- `proof_version`：证明对象版本号
- `prove_ms`：proof 生成耗时（毫秒）
- `verify_ms`：proof 验证耗时（毫秒）

## 采集命令（默认后端）
```bash
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc test/poseidon2_stark_stats
./test/poseidon2_stark_stats
```

## 采集命令（Rust 后端）
```bash
cd ref/stark-rs
cargo build --release
```
```bash
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_stats
./test/poseidon2_stark_stats
```

## 结果模板
| date | params | backend | trace_calls | trace_lanes | witness_rows | proof_bytes | proof_magic | proof_version | prove_ms | verify_ms |
|---|---|---|---:|---:|---:|---:|---|---:|---:|---:|
| 2026-04-19 | sphincs-poseidon2-192s | C-default | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| 2026-04-19 | sphincs-poseidon2-192s | Rust-stark | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## 预期结果基线（M17 第二阶段）
- 默认后端：
  - 允许 `proof_magic=PFP1`，要求 `proof_version=1`；
  - `trace_calls/trace_lanes/witness_rows/proof_bytes` 均为正数。
- Rust 后端：
  - 优先期望 `proof_magic=PFP2`，要求 `proof_version=2`；
  - 若环境受限导致回退，需在报告中说明原因并附日志。

## 自动采集脚本
```bash
./scripts/collect_benchmark_v2.sh
```
- 运行后会在 `logs/benchmark-stark-v2-local.md` 生成一条本地实测结果。
