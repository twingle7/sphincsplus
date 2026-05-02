# 测试总览

本文档给出当前仓库建议保留和优先使用的测试命令，并明确说明：

- 每个测试在验证什么；
- 每个测试跑通后，最多能支持什么结论；
- 每个测试跑通后，仍然不能直接推出什么结论。

建议把这些测试分成五组理解：

- Poseidon2 替换正确性
- Fischlin / show / strict STARK 主链正确性
- `SHA2 vs Poseidon2` 约束与 proof 对比
- 参数重搜流程正确性
- benchmark 性能测量

## 如何解读测试结论

- `跑通` 的含义是：当前代码在该测试覆盖的输入和断言下满足预期。
- `跑通` 不等于：已经完成形式化安全证明，也不等于覆盖了所有边界情况。
- `基础 API / KAT` 只能支持“实现稳定、接口行为一致”，不能单独支持“协议主链正确”。
- `协议流 / e2e / strict` 才能支持“当前 show/prove/verify 主链可运行并能拒绝部分篡改”。
- `hash_profile / thash_compare` 只能支持“约束或成本估算/对比结论”，不能直接支持“完整 SPHINCS+ 证明成本结论”。
- `参数重搜脚本` 只能支持“候选筛选流程正确执行”，不能单独支持“推荐参数一定最优”。

## 环境约定

### WSL / Linux 推荐

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
export PARAMS=sphincs-poseidon2-192s
export THASH=simple
export CC_BIN=gcc
```

### Windows / MinGW 推荐

```powershell
cd d:\Desktop\My_Sphincs+\sphincsplus\ref
```

## 1. Poseidon2 替换相关测试

### 1.1 基础 API / KAT / adapter

WSL:

```bash
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc \
  test/poseidon2_api \
  test/poseidon2_kat \
  test/poseidon2_adapter \
  test/poseidon2_bsig_v0

./test/poseidon2_api
./test/poseidon2_kat
./test/poseidon2_adapter
./test/poseidon2_bsig_v0
```

Windows:

```powershell
mingw32-make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc `
  test/poseidon2_api `
  test/poseidon2_kat `
  test/poseidon2_adapter `
  test/poseidon2_bsig_v0

.\test\poseidon2_api
.\test\poseidon2_kat
.\test\poseidon2_adapter
.\test\poseidon2_bsig_v0
```

测试说明：

- `test/poseidon2_api`
  - 作用：检查 `oneshot` 与 `incremental` 接口一致、长度边界变化能导致输出变化、`THASH F/H/TL` 域分离有效。
  - 跑通支持的结论：`Poseidon2` 基础哈希 API 没有明显接口回归；域分离标签至少在当前实现中生效。
  - 跑通不支持的结论：不能单独说明 `SPHINCS+` 全链路已经正确，也不能说明安全性已经证明。
- `test/poseidon2_kat`
  - 作用：用固定向量锁定当前 `poseidon2.c` 实现输出，防止后续修改 silently 改变算法行为。
  - 跑通支持的结论：当前实现与仓库冻结的参考向量一致；后续改动没有破坏既定字节级输出。
  - 跑通不支持的结论：不能说明这些向量就是外部标准向量；这里只能说明“与本仓库当前冻结实现一致”。
- `test/poseidon2_adapter`
  - 作用：检查 `bytes -> lanes` 编码、`commit` 的确定性与消息绑定、`verify_com` 与 `trace_verify_com` 路径一致性。
  - 跑通支持的结论：适配层编码和 trace 记录机制是自洽的；承诺与 message/rand 绑定在当前实现里有效。
  - 跑通不支持的结论：不能单独说明 AIR 约束一定正确，也不能说明 strict STARK 主链正确。
- `test/poseidon2_bsig_v0`
  - 作用：验证较早期的 `bsig v0` 原型流程能完成 `issue/prove/verify`，并能拒绝 `sigma_com/show proof` 篡改。
  - 跑通支持的结论：仓库里早期 blind-sign 原型仍然可运行，且基本篡改守卫未坏。
  - 跑通不支持的结论：不能把它当作当前 final Fischlin-Strict 主链的直接证据；它更像原型回归测试。

### 1.2 SPHINCS+ 基本调用面

WSL:

```bash
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc \
  test/spx test/fors test/benchmark

./test/spx
./test/fors
./test/benchmark
```

测试说明：

- `test/spx`
  - 作用：验证当前参数集下完整签名/验签调用面还能工作。
  - 跑通支持的结论：`Poseidon2` 替换后，基础 `SPHINCS+` 风格签名 API 仍可用。
- `test/fors`
  - 作用：验证 FORS 子组件在当前参数和哈希后端下可工作。
  - 跑通支持的结论：替换哈希后，`SPHINCS+` 的关键子模块没有立即坏掉。
- `test/benchmark`
  - 作用：给基础签名/验签路径做性能 smoke test。
  - 跑通支持的结论：基础调用面不仅能跑，而且能输出可采集的性能数据。

结论边界：

- 这组三项一起跑通，可以支持“Poseidon2 已经替换到 `SPHINCS+` 的基础调用面，基础签名/验签仍可运行”。
- 这组三项不能单独支持“Fischlin 盲签 strict 主链已经正确”。

## 2. Fischlin / show / strict STARK 主链测试

### 2.1 协议流与展示对象

说明：

- 这组测试里只要走到 `show_prove/show_verify`，通常就需要真实 Rust STARK 后端。
- 如果未开启 `-DSPX_P2_USE_RUST_STARK`，它们更适合作为“编译与前半流程”检查，而不是最终成功用例。

WSL:

```bash
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc \
  test/poseidon2_show_v1 \
  test/poseidon2_show_v1_boundary \
  test/poseidon2_protocol_flow_statement_bound \
  test/poseidon2_fischlin_statement_bound_spec

./test/poseidon2_show_v1
./test/poseidon2_show_v1_boundary
./test/poseidon2_protocol_flow_statement_bound
./test/poseidon2_fischlin_statement_bound_spec
```

测试说明：

- `test/poseidon2_show_v1`
  - 作用：验证较早期 `show` 对象的生成、验证和基础篡改拒绝，包括 `com/show proof/public_ctx/header` 篡改。
  - 跑通支持的结论：show 对象的序列化/形状检查和基础篡改守卫没有坏。
  - 跑通不支持的结论：它更偏 legacy/compat 形态，不能单独证明 final strict public-statement 语义已闭环。
- `test/poseidon2_show_v1_boundary`
  - 作用：验证 `show` 对象最小形状守卫，例如 show proof 为空必须拒绝。
  - 跑通支持的结论：show 对象的基本边界检查仍有效。
  - 跑通不支持的结论：不能说明 proof 语义正确，只能说明形状守卫正确。
- `test/poseidon2_protocol_flow_statement_bound`
  - 作用：跑一遍完整 `Commit -> Issue -> Unblind -> Show -> Verify`，并验证篡改 `m_pub` 会被拒绝。
  - 跑通支持的结论：当前 statement-bound 路径下，完整协议编排可以闭环；最终公开语句中的 `m_pub` 已参与验证。
  - 跑通不支持的结论：不能直接推出所有 tamper 场景都覆盖，也不能代替更细粒度的 binding 测试。
- `test/poseidon2_fischlin_statement_bound_spec`
  - 作用：检查 statement-bound 语义口径，例如显式 `m_pub`、`pk_E`、`public_ctx` 的验证要求。
  - 跑通支持的结论：当前“公开输入必须显式包含 `m_pub`”的接口语义是收紧且一致的；错 `m_pub`、错 `pk_E`、错 `ctx` 会拒绝。
  - 跑通不支持的结论：不能单独推出 proof 内部约束全部已经内生，只能说明对外语义和验证入口符合预期。

### 2.2 strict Rust STARK 主链

WSL:

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref/stark-rs
cargo build --release

cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_verify_full_guard \
  test/poseidon2_cross_backend_consistency \
  test/poseidon2_statement_binding \
  test/poseidon2_trace_replay_binding \
  test/poseidon2_roles_interaction \
  test/poseidon2_fischlin_blind_e2e \
  test/poseidon2_stark_stats \
  test/poseidon2_stark_strict_core_enforcement

./test/poseidon2_verify_full_guard
./test/poseidon2_cross_backend_consistency
./test/poseidon2_statement_binding
./test/poseidon2_trace_replay_binding
./test/poseidon2_roles_interaction
./test/poseidon2_fischlin_blind_e2e
./test/poseidon2_stark_stats
./test/poseidon2_stark_strict_core_enforcement
```

测试说明：

- `test/poseidon2_verify_full_guard`
  - 作用：在 C 侧 `verify_full` AIR 约束评估中，确认合法 trace `violations=0`，篡改域标签后 `violations>0`。
  - 跑通支持的结论：当前 C 侧完整约束评估器至少能区分“合法 trace”和“明显错误 trace”。
  - 跑通不支持的结论：不能直接证明 Rust STARK prover/verifier 与其完全等价。
- `test/poseidon2_cross_backend_consistency`
  - 作用：比较 C 侧 guard 与 strict show/prove 路径在合法样本、错签名、错 commitment、错 `pk` 下是否一致接受/拒绝。
  - 跑通支持的结论：不同后端或不同检查层对关键正负例的判断基本一致。
  - 跑通不支持的结论：不能推出“所有输入空间下都一致”，这里只是样本级一致性。
- `test/poseidon2_statement_binding`
  - 作用：篡改 `statement_version`、`public_input_digest`、`m_pub`，验证 strict 路径都应拒绝。
  - 跑通支持的结论：proof 绑定的公开语句没有只停留在对象外层，show proof 中的语句摘要与 `m_pub` 已参与验证。
  - 跑通不支持的结论：不能单独证明每个公开量都完全内生到 AIR 主约束，但至少说明 verify 不会忽略这些字段。
- `test/poseidon2_trace_replay_binding`
  - 作用：篡改 show proof 内的 commitment/proof 区域，验证 replay 或对象拼接会被拒绝。
  - 跑通支持的结论：show proof 并非“可替换壳子”，proof 字节和 commitment 绑定关系在验证时生效。
  - 跑通不支持的结论：不能单独证明所有序列化字段都不可重放，但能支持“关键 proof/commitment 字段已绑定”。
- `test/poseidon2_roles_interaction`
  - 作用：以三角色视角演示 final 流程，验证 `User / Signer / Verifier` 交互闭环可跑通。
  - 跑通支持的结论：当前 final 演示链已经打通，适合当作答辩展示用例。
  - 跑通不支持的结论：它是 demo，不是穷尽性安全测试。
- `test/poseidon2_fischlin_blind_e2e`
  - 作用：跑 final 风格 blind-sign e2e，验证 issue/unblind/show/verify 全链路闭环。
  - 跑通支持的结论：当前工程实现下，盲签风格主链能走通，且 final witness 语义与 strict 路径一致。
  - 跑通不支持的结论：不能单独把它当成“标准 Fischlin 盲签已完全形式化实现”的证据。
- `test/poseidon2_stark_stats`
  - 作用：收集 strict 主链的 proof 大小、trace 宽度、行数、约束数量、prove/verify 时间、RSS 等指标。
  - 跑通支持的结论：当前 Rust STARK 后端不仅能跑，还能稳定导出论文/报告可用的统计指标。
  - 跑通不支持的结论：它是“统计正确性 + 运行性”测试，不是语义完整性测试。
- `test/poseidon2_stark_strict_core_enforcement`
  - 作用：直接对 strict FFI 与 relation precheck 做核心负例测试，包括错 `m/r/sigma_com/omega2/pk_sig/pk_E/sigma_c/m_pub/public_ctx` 等。
  - 跑通支持的结论：strict 路径的核心公开输入和 witness 关系至少对这些关键篡改项是敏感的，相关 guard/FFI 不会静默放过。
  - 跑通不支持的结论：不能直接说明这些关系都已经完全下沉为 AIR 主约束，也可能有部分拒绝来自前置校验。

### 2.3 一键主回归

WSL:

```bash
bash scripts/run_strict_regression.sh
```

脚本说明：

- `scripts/run_strict_regression.sh`
  - 作用：统一构建 Rust 后端并依次运行：
    - `poseidon2_verify_full_guard`
    - `poseidon2_cross_backend_consistency`
    - `poseidon2_statement_binding`
    - `poseidon2_trace_replay_binding`
    - `poseidon2_roles_interaction`
    - `poseidon2_fischlin_blind_e2e`
    - `poseidon2_stark_stats`
  - 跑通支持的结论：当前 strict 主链、final demo、statement/replay binding 和统计链路整体未坏，适合作为“主回归入口”。
  - 跑通不支持的结论：它不包含所有基础 API、所有 AIR 单测和所有参数搜索脚本，因此不是“全仓库全集测试”。

当前已单独实测通过的 final 演示 / e2e：

```bash
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/poseidon2_roles_interaction \
  test/poseidon2_fischlin_blind_e2e

./test/poseidon2_roles_interaction
./test/poseidon2_fischlin_blind_e2e
```

## 3. `SHA2 vs Poseidon2` 约束数 / proof 对比

### 3.1 verify 路径哈希画像估算

WSL:

```bash
make clean
make PARAMS=sphincs-sha2-192s THASH=simple CC=gcc test/hash_profile_verify
./test/hash_profile_verify

make clean
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc test/hash_profile_verify
./test/hash_profile_verify
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare_hash_profile_verify.ps1
```

测试说明：

- `test/hash_profile_verify`
  - 作用：在真实 `crypto_sign_verify()` 执行时统计 `thash/prf_addr/hash_message` 调用次数，并按 cost model 估算约束成本。
  - 跑通支持的结论：你可以得到“verify 路径使用了多少哈希原语”和“在所选 cost model 下估算约束数是多少”。
  - 跑通不支持的结论：这不是 proof 实测，也不是完整 AIR 约束实测；它是画像和估算。
- `scripts/compare_hash_profile_verify.ps1`
  - 作用：在 Windows 下自动比较 `sha2` 与 `poseidon2` 两组 profile 输出。
  - 跑通支持的结论：同一 cost model 下，你可以稳定复现两种后端的 verify 成本对比。

### 3.2 THASH 级真实 STARK 对比

WSL:

```bash
cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref/stark-rs
cargo build --release

cd /mnt/d/Desktop/My_Sphincs+/sphincsplus/ref
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" \
  test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=benchmark SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=64 \
  ./test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=poseidon2_exact SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=128 \
  ./test/thash_backend_stark_compare

SPX_THASH_BENCH_MODE=sha2_exact SPX_THASH_BENCH_INBLOCKS=2 SPX_THASH_BENCH_ROUNDS=1024 \
  ./test/thash_backend_stark_compare
```

测试说明：

- `test/thash_backend_stark_compare`
  - 作用：对 `THASH` 粒度的 STARK 证明做真实 benchmark / exact 对比，而不是只做 cost model 估算。
  - 跑通支持的结论：在 `THASH` 粒度下，`poseidon2` 与 `sha2` 的 trace/constraint/proof/time 差异可以被真实测量。
  - 跑通不支持的结论：这不是完整 SPHINCS+ 全系统证明成本；它是 `THASH` 局部对比。

模式说明：

- `benchmark`
  - 含义：第一版 `THASH` benchmark AIR，用于粗粒度 benchmark。
  - 支持的结论：能比较“当前 benchmark AIR 口径下”的工程性能。
- `poseidon2_exact`
  - 含义：`Poseidon2 THASH` 的 exact 模式。
  - 支持的结论：能比较接近真实 primitive 语义的 `Poseidon2 THASH` 证明成本。
- `sha2_exact`
  - 含义：`SHA2 THASH` 的 exact 模式。
  - 支持的结论：能比较接近真实 primitive 语义的 `SHA2 THASH` 证明成本。

论文引用提醒：

- 若你引用“约束数更低/证明更快”这类结论，必须写清楚你引用的是：
  - `hash_profile` 估算；
  - 还是 `THASH exact` 实测；
  - 不能把两者混写。

## 4. 参数重搜相关测试

### 4.1 结构筛选

WSL:

```bash
python3 scripts/search_params_poseidon2.py
```

脚本说明：

- `scripts/search_params_poseidon2.py`
  - 作用：在结构参数空间里筛候选组。
  - 跑通支持的结论：参数枚举、筛选规则和输出格式是可执行的，能产出候选参数集。
  - 跑通不支持的结论：不能单独说明这些候选满足安全目标或性能最好。

### 4.2 安全筛选

WSL:

```bash
python3 scripts/eval_security_poseidon2.py
```

脚本说明：

- `scripts/eval_security_poseidon2.py`
  - 作用：对候选参数进行安全筛选或安全估算。
  - 跑通支持的结论：当前安全筛选规则可执行，能把结构候选进一步缩减为满足目标门槛的组。
  - 跑通不支持的结论：不能代替正式密码分析；它只说明“在当前脚本采用的安全模型下通过”。

### 4.3 批量实测

WSL:

```bash
bash scripts/collect_benchmark_params.sh
```

脚本说明：

- `scripts/collect_benchmark_params.sh`
  - 作用：对候选参数批量做签名、验证、STARK 等实测采集。
  - 跑通支持的结论：候选参数集的工程性能和约束相关指标可以批量复现。
  - 跑通不支持的结论：不能单独证明“推荐组一定全局最优”，只是提供可比较数据。

### 4.4 Pareto / 可视化

WSL:

```bash
python3 scripts/analyze_pareto_poseidon2.py
python3 scripts/plot_param_comparison.py
```

脚本说明：

- `scripts/analyze_pareto_poseidon2.py`
  - 作用：基于采集结果分析 Pareto 前沿与推荐候选。
  - 跑通支持的结论：在当前评价维度下，你可以得到一组“互不劣”的候选。
  - 跑通不支持的结论：Pareto 推荐依赖当前指标集和权重，不代表唯一正确答案。
- `scripts/plot_param_comparison.py`
  - 作用：把参数组对比结果画成图表。
  - 跑通支持的结论：论文和答辩所需图表可以从当前数据自动生成。

### 4.5 预算退化与归档

WSL:

```bash
python3 scripts/analyze_budget_degradation_poseidon2.py
bash scripts/package_final_results.sh
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_m6_and_bundle.ps1 -CleanOutputFirst
powershell -ExecutionPolicy Bypass -File scripts/cleanup_workspace.ps1
```

脚本说明：

- `scripts/analyze_budget_degradation_poseidon2.py`
  - 作用：分析预算退化或参数缩减带来的指标变化。
  - 跑通支持的结论：你可以把“推荐参数相对基线的代价/收益”量化出来。
- `scripts/package_final_results.sh`
  - 作用：把当前文档、图表、脚本和结果归档打包。
  - 跑通支持的结论：当前实验材料可以被稳定收集与复现归档。
- `scripts/run_m6_and_bundle.ps1`
  - 作用：Windows 下执行预算分析与归档打包。
  - 跑通支持的结论：在 Windows 环境也能完成相同归档流程。

## 5. benchmark 性能测试

### 5.1 当前 STARK 路径 benchmark

WSL:

```bash
RUNS=30 bash scripts/collect_benchmark_v2.sh
```

输出：

- `logs/benchmark-stark-v2-local.md`

脚本说明：

- `scripts/collect_benchmark_v2.sh`
  - 作用：对当前 strict STARK 主链做多轮 benchmark 采集。
  - 跑通支持的结论：当前 strict 主链的 prove/verify/内存等工程性能可重复测量。
  - 跑通不支持的结论：它测的是当前实现版本，不是跨实现、跨机器的绝对结论。

### 5.2 四组对比 benchmark

WSL:

```bash
RUNS=20 bash scripts/collect_benchmark_4way.sh
```

输出：

- `logs/benchmark-4way-local.md`

脚本说明：

- `scripts/collect_benchmark_4way.sh`
  - 作用：采集四组配置的 benchmark 对比。
  - 跑通支持的结论：你可以拿到“基线 vs Poseidon2 vs blind-sign/stark 变体”等多组工程性能比较。
  - 跑通不支持的结论：结论依赖当前机器和采样轮数，不能脱离环境直接绝对化。

### 5.3 参数候选 benchmark

WSL:

```bash
python3 scripts/search_params_poseidon2.py
python3 scripts/eval_security_poseidon2.py

# 全量 M4：先跑 STARK 指标
TOP_K=0 ENABLE_STARK=1 ENABLE_SIGNVERIFY=0 RUNS_STARK=1 \
  bash scripts/collect_benchmark_params.sh

# 从全部 M4-ok 中抽取子集，再全量补跑 sign/verify，并做全局 Pareto
bash scripts/run_param_signverify_global_pareto.sh
```

若批量任务中途中断，可直接断点续跑：

```bash
# 继续 M4 全量 STARK
bash scripts/resume_param_search.sh stark

# 继续 M4-ok 的 sign/verify 补跑
bash scripts/resume_param_search.sh signverify
```

其中 `signverify` 续跑完成后会默认自动刷新一次全局 Pareto 结果；如只想补跑、不立即分析，可设置 `RUN_PARETO_AFTER=0`。

输出：

- `logs/params-benchmark-v1-full.csv`
- `logs/params-m4-ok-for-signverify-v1.csv`
- `logs/params-signverify-m4-ok-v1.csv`
- `logs/params-m5-merged-v1.csv`
- `logs/params-pareto-frontier-v1.csv`
- `logs/params-final-candidates-v1.md`

脚本说明：

- `scripts/collect_benchmark_params.sh`
  - 作用：给候选参数集做批量 benchmark；当 `TOP_K=0` 时表示不截断，按输入 CSV 全量执行。
  - 跑通支持的结论：参数组之间的工程表现可以形成统一表格，适合后续排序和推荐。
- `scripts/select_m4_ok_for_signverify.py`
  - 作用：从全量 `M4` 结果中抽取全部 `status=ok` 候选，并回连到 `M3 security-pass` 的完整参数行。
  - 跑通支持的结论：后续 `sign/verify` 补跑不再只针对少量 finalists，而是面向全部 `M4-ok` 候选。
- `scripts/run_param_signverify_global_pareto.sh`
  - 作用：串联“抽取全部 `M4-ok` 候选 -> 全量补跑 `sign/verify` -> 全局 Pareto”三步。
  - 跑通支持的结论：`M5` 推荐结果来自 `M3 pass ∩ M4 ok ∩ sign/verify ok` 的全集，而不是入围子集。
- `scripts/report_resume_progress.py`
  - 作用：对比输入候选集与当前输出 CSV，报告已完成与剩余候选数，并可导出剩余候选清单。
  - 跑通支持的结论：可以可靠识别长时间批量任务的断点位置与剩余工作量。
- `scripts/resume_param_search.sh`
  - 作用：基于已有落盘结果执行断点续跑，跳过已经写入 `OUT_CSV` 的 `candidate_id`；`signverify` 模式下默认自动刷新全局 Pareto。
  - 跑通支持的结论：中断后可继续完成 `M4 STARK` 或 `M4-ok sign/verify` 批量任务，而无需从头重跑。

## 推荐最小验收集合

如果你只想确认“当前实现没有坏”，建议至少跑：

WSL:

```bash
make -B PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc \
  test/poseidon2_api \
  test/poseidon2_kat \
  test/poseidon2_adapter \
  test/poseidon2_protocol_flow_statement_bound

./test/poseidon2_api
./test/poseidon2_kat
./test/poseidon2_adapter
./test/poseidon2_protocol_flow_statement_bound
```

这组最小集合跑通，支持的结论是：

- `Poseidon2` 基础实现没坏；
- 固定向量没漂移；
- 适配层和 trace 机制没坏；
- strict public-statement 协议流可以闭环。

如果你要确认 strict Rust STARK 主链，再补：

```bash
bash scripts/run_strict_regression.sh
```

这条主回归跑通，支持的结论是：

- strict 主链、final demo、e2e、statement 绑定、trace replay 绑定和统计链路整体都还在工作。
