# 测试总览

本文档汇总当前仓库仍然有效的测试目标、回归脚本、benchmark 入口和参数实验脚本。

需要先明确区分三类内容：

- **correctness / security-relevant tests**：用于验证协议主链、statement binding、strict witness 约束和篡改拒绝行为；
- **format / ffi / regression tests**：用于验证 proof 格式、FFI 接口和低层 AIR/witness 构造未明显回归；
- **benchmark / search scripts**：用于性能测量、参数重搜、批量实验和结果打包，不应与正确性测试等同理解。

## 环境

WSL:

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
export PARAMS=sphincs-poseidon2-192s
export THASH=simple
export CC_BIN=gcc
export CC=gcc
```

Rust STARK 后端:

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref/stark-rs
cargo build --release

cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
export EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK"
```

说明：

- final Fischlin 主链建议始终带 `EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK"` 执行。
- 已删除的 `bsig v0` 与 `show_v1` 骨架测试不再属于当前仓库测试面。
- 文件名或内部实现里仍存在部分 `_v1`，主要表示低层格式、AIR 或历史承载层，并不代表当前公开接口仍是旧版本。
- 文档中保留的部分 `strict_public` / `statement_bound` 目标是 **兼容别名** 或 **同源构建目标**，不应简单理解为多份独立测试覆盖。

## 1. 基础签名与 Poseidon2 测试

### 1.1 SPHINCS+ 基础调用面

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  test/spx \
  test/fors \
  test/benchmark

./test/spx
./test/fors
./test/benchmark
```

### 1.2 Poseidon2 基础哈希与适配层

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  test/poseidon2_api \
  test/poseidon2_kat \
  test/poseidon2_adapter \
  test/poseidon2_instantiation_m1

./test/poseidon2_api
./test/poseidon2_kat
./test/poseidon2_adapter
./test/poseidon2_instantiation_m1
```

这些测试支持的结论：

- `Poseidon2` 基础接口、固定向量和适配层编码未回归。
- `SPHINCS+` 基础签名与 FORS 子模块仍可工作。

## 2. AIR / witness / 证明格式测试

### 2.1 证明格式与 FFI 底层测试

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  test/poseidon2_verify_full_guard \
  test/poseidon2_pi_f_format

./test/poseidon2_verify_full_guard
./test/poseidon2_pi_f_format
```

### 2.2 实例化与 API 测试

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  test/poseidon2_api \
  test/poseidon2_adapter \
  test/poseidon2_instantiation_m1

./test/poseidon2_api
./test/poseidon2_adapter
./test/poseidon2_instantiation_m1
```

这些测试支持的结论：

- SPHINCS+ API 适配层、Poseidon2 实例化和 KAT 验证路径可工作。
- `ffi` 层与 proof 格式编码没有明显接口回归。
- 这些测试更偏**低层回归**，不能单独作为 final Fischlin strict 主链已经完整验证的证据。

## 3. Final Fischlin / show / protocol 主链

### 3.1 final 协议与规格测试

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_protocol_flow \
  test/poseidon2_protocol_flow_statement_bound \
  test/poseidon2_fischlin_statement_spec \
  test/poseidon2_fischlin_statement_bound_spec \
  test/poseidon2_roles_interaction \
  test/poseidon2_fischlin_blind_e2e

./test/poseidon2_protocol_flow
./test/poseidon2_protocol_flow_statement_bound
./test/poseidon2_fischlin_statement_spec
./test/poseidon2_fischlin_statement_bound_spec
./test/poseidon2_roles_interaction
./test/poseidon2_fischlin_blind_e2e
```

### 3.2 statement / replay / cross-backend 绑定测试

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_statement_binding \
  test/poseidon2_trace_replay_binding \
  test/poseidon2_cross_backend_consistency \
  test/poseidon2_stark_strict_core_enforcement \
  test/poseidon2_stark_stats

./test/poseidon2_statement_binding
./test/poseidon2_trace_replay_binding
./test/poseidon2_cross_backend_consistency
./test/poseidon2_stark_strict_core_enforcement
./test/poseidon2_stark_stats
```

### 3.3 兼容别名目标

这些目标仍在 `Makefile` 中保留，便于旧脚本或旧命名继续调用：

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_protocol_flow_strict_public \
  test/poseidon2_fischlin_strict_public_spec \
  test/poseidon2_protocol_benchmark_strict_public
```

说明：

- `test/poseidon2_protocol_flow_strict_public` 与 `test/poseidon2_protocol_flow` 使用同一份测试源。
- `test/poseidon2_fischlin_strict_public_spec` 与 `test/poseidon2_fischlin_statement_spec` 使用同一份测试源。
- `test/poseidon2_protocol_benchmark_strict_public` 与 `test/poseidon2_protocol_benchmark` 使用同一份 benchmark 源。
- `test/poseidon2_protocol_flow_statement_bound` 与 `test/poseidon2_protocol_flow` 也使用同一份测试源。
- `test/poseidon2_fischlin_statement_bound_spec` 与 `test/poseidon2_fischlin_statement_spec` 也使用同一份测试源。

因此，这些目标主要用于兼容命名和不同入口调用，**不应统计为额外的独立测试覆盖面**。

这些测试支持的结论：

- final `Commit -> Issue -> FinalizeCredential -> Show -> Verify` 主链可运行。
- `m_pub`、`pk_E`、`public_ctx`、`sigma_c`、proof digest、trace replay 绑定对关键篡改敏感。
- Rust STARK 后端已经接入 final `show/protocol/ffi` 主链。
- 其中 `poseidon2_stark_strict_core_enforcement`、`poseidon2_statement_binding`、`poseidon2_trace_replay_binding` 和 `poseidon2_cross_backend_consistency` 是当前最值得优先保留的 strict 核心测试。

## 4. 自动化回归脚本

### 4.1 strict 主回归

```bash
bash scripts/run_strict_regression.sh
```

该脚本会构建 Rust 后端并依次执行：

- `poseidon2_protocol_flow`
- `poseidon2_fischlin_statement_spec`
- `poseidon2_verify_full_guard`
- `poseidon2_cross_backend_consistency`
- `poseidon2_statement_binding`
- `poseidon2_trace_replay_binding`
- `poseidon2_roles_interaction`
- `poseidon2_fischlin_blind_e2e`
- `poseidon2_stark_stats`

说明：

- 该脚本适合作为**主回归入口**；
- 但它目前**没有覆盖** `poseidon2_stark_strict_core_enforcement`，因此如果你要做论文验收或严格本地验证，建议额外手动执行该目标。

推荐补跑：

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_stark_strict_core_enforcement

./test/poseidon2_stark_strict_core_enforcement
```

## 5. Poseidon2 vs SHA2 对比测试

### 5.1 verify 路径哈希画像

```bash
make clean
make PARAMS=sphincs-sha2-192s THASH=simple CC=$CC test/hash_profile_verify
./test/hash_profile_verify

make clean
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=$CC test/hash_profile_verify
./test/hash_profile_verify
```

Windows 对比脚本：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare_hash_profile_verify.ps1
```

### 5.2 THASH 级真实 STARK 对比

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref/stark-rs
cargo build --release

cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=benchmark SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=64 \
  ./test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=poseidon2_exact SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=128 \
  ./test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=sha2_exact SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=1024 \
  ./test/thash_backend_stark_compare
```

这些测试支持的结论：

- `hash_profile_verify` 给出 verify 路径哈希调用画像和 cost model 估算。
- `thash_backend_stark_compare` 给出 `THASH` 粒度下 `poseidon2` 与 `sha2` 的真实 STARK 对比数据。
- 它们用于论文实验数据与性能分析，不应替代 correctness / security-relevant tests。

## 6. 协议 benchmark

### 6.1 final 协议 benchmark 目标

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_protocol_benchmark \
  test/poseidon2_protocol_benchmark_statement_bound

./test/poseidon2_protocol_benchmark
./test/poseidon2_protocol_benchmark_statement_bound
```

### 6.2 strict 主链 benchmark 脚本

```bash
RUNS=30 bash scripts/collect_benchmark_v2.sh
RUNS=20 bash scripts/collect_benchmark_4way.sh
```

这些脚本会综合 `test/benchmark` 与 `test/poseidon2_stark_stats` 的输出生成日志。

说明：

- benchmark 结果受机器、编译器、运行轮数和 WSL 环境影响；
- 它们适用于做论文统计，不适合作为“协议实现正确”的直接证据。

## 7. 参数重搜与批量实验

### 7.1 参数搜索与安全筛选

```bash
python3 scripts/search_params_poseidon2.py
python3 scripts/eval_security_poseidon2.py
```

### 7.2 批量 benchmark 与全局 Pareto

```bash
bash scripts/collect_benchmark_params.sh
bash scripts/run_param_signverify_global_pareto.sh
python3 scripts/select_m4_ok_for_signverify.py
python3 scripts/report_resume_progress.py
```

### 7.3 中断续跑

```bash
bash scripts/resume_param_search.sh stark
bash scripts/resume_param_search.sh signverify
```

### 7.4 Pareto / 图表 / 预算分析

```bash
python3 scripts/analyze_pareto_poseidon2.py
python3 scripts/plot_param_comparison.py
python3 scripts/analyze_budget_degradation_poseidon2.py
```

### 7.5 结果打包与清理

```bash
bash scripts/package_final_results.sh
bash scripts/run_m6_and_bundle.sh
bash scripts/cleanup_workspace.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package_final_results.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_m6_and_bundle.ps1 -CleanOutputFirst
powershell -ExecutionPolicy Bypass -File scripts/cleanup_workspace.ps1
```

这些脚本支持的结论：

- 参数搜索、候选筛选、批量 benchmark、Pareto 分析和结果打包流程可复现执行。
- 它们不单独证明某组参数一定最优，也不替代正式安全分析。
- 它们属于实验与工程流程脚本，而不是协议 correctness 测试。

## 8. 推荐验收顺序

如果你准备在本地 WSL 做一轮完整验收，建议顺序如下：

1. 基础哈希与适配层：

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC \
  test/poseidon2_api test/poseidon2_kat test/poseidon2_adapter

./test/poseidon2_api
./test/poseidon2_kat
./test/poseidon2_adapter
```

2. Rust STARK 后端构建：

```bash
cd stark-rs && cargo build --release && cd ..
```

3. strict 主回归：

```bash
bash scripts/run_strict_regression.sh
```

4. strict 核心补充负例：

```bash
make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_stark_strict_core_enforcement

./test/poseidon2_stark_strict_core_enforcement
```

这一步很重要，因为它专门覆盖 strict witness / public statement / tamper rejection 的核心负例。

5. 论文统计数据：

```bash
./test/poseidon2_stark_stats
./test/thash_backend_stark_compare
./test/hash_profile_verify
```

6. 参数重搜与批量实验：

```bash
python3 scripts/search_params_poseidon2.py
python3 scripts/eval_security_poseidon2.py
bash scripts/collect_benchmark_params.sh
python3 scripts/analyze_pareto_poseidon2.py
```

## 9. 当前最推荐保留的测试集合

如果你只想保留一组“最能说明当前 final Fischlin 实现状态”的测试，建议优先执行：

```bash
bash scripts/run_strict_regression.sh

make -B PARAMS=$PARAMS THASH=$THASH CC=$CC EXTRA_CFLAGS="$EXTRA_CFLAGS" \
  test/poseidon2_stark_strict_core_enforcement \
  test/poseidon2_pi_f_format

./test/poseidon2_stark_strict_core_enforcement
./test/poseidon2_pi_f_format
```

这组测试最能支持以下结论：

- final Fischlin 主链可运行；
- strict statement binding 和 witness binding 对关键篡改敏感；
- Rust STARK 后端与 C 主链之间的证明格式和 FFI 接口没有明显回归。
