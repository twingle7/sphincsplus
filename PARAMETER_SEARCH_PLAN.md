# 参数重搜计划 v2（THF 安全模型 + 全内生 AIR 成本）

## 1. 为什么需要重搜

| 旧搜索 (proxy-v1) | 新搜索 (THF + full-AIR) |
|:---|:---|
| 安全模型: `min(8·n, k·a)` | 安全模型: SPHINCS+ 规范的 THF 框架 |
| 忽略多目标攻击 | 计入 log₂(q·k) 和 log₂(q·d) |
| 成本维度: sign_ms, verify_ms, witness_rows | 成本维度: prove_ms (STARK 证明时间) |
| 基于旧混合证明模型 | 基于全内生 AIR |

## 2. 旧搜索慢的原因

之前的参数搜索 pipeline：
```
生成候选 → 结构筛选 → 安全筛选 → [逐候选 benchmark: C sign + C verify + STARK prove] → Pareto
                                     ↑ 瓶颈：每个候选跑实际 STARK，几分钟/个
```

旧搜索有 ~600 个候选通过安全筛选，但只对其中 10 个做了 benchmark（因为太慢）。

## 3. 新方案：成本模型替代全量 benchmark

```
生成候选 → 结构筛选 → THF 安全筛选 → [成本模型估值] → 排序 → [TOP 3-5 实际 STARK benchmark]
                  ↑ 微秒级/候选        ↑ 微秒级/候选          ↑ 仅 3-5 个, ~5 分钟/个
```

### 3.1 成本模型公式

基于 `trace_builder.rs` 的分析推导：

```
total_perms = H_msg + FORS + HT
H_msg_perms = thash_perms(4)  # R + PK + m + domain
FORS_perms = K × [thash_perms(1) + A × thash_perms(2)] + thash_perms(K)
HT_perms = D × [WOTS_LEN × (W-1)/2 × thash_perms(1) + 2×thash_perms(WOTS_LEN) + TREE_HEIGHT × thash_perms(2)]

thash_perms(inblocks) = ceil((1 + n + 32 + inblocks×n) / 48) + 1

trace_rows = next_pow2(total_perms × 32)
prove_seconds ≈ 127 × (trace_rows/131072) × (log₂(trace_rows)/17)
proof_bytes ≈ 95000 × sqrt(trace_rows/131072)
```

**验证**：dev 参数估算 3559 perms, 实际 3686（误差 3.5%）。证明时间在同一个 pow2 区间。

### 3.2 候选排序维度

| 维度 | 方向 | 权重 |
|:---|:---|:---|
| prove_seconds（估算） | 最小化 | 主排序键 |
| sig_bytes（C 侧计算） | 最小化 | 次排序键 |
| overall_sec（估算） | 最大化 | 安全富余 |

## 4. 执行计划

### Step 1: 评估旧候选集（10 分钟）

```bash
cd ref
python scripts/cost_model_full_air.py \
    --input-csv logs/params-search-struct-pass-v1.csv \
    --output-csv logs/params-cost-model-v2.csv \
    --q 65536 --target-bits 121
```

这会输出：
- 所有候选的 THF 安全评估
- 安全通过的候选及其估算成本
- 按证明时间排序

### Step 2: 选择 Top 3-5 候选

从排序列表中人工选择：
- 最快证明 + 121-bit 达标
- 不同 k·a 组合（紧凑 vs 保守）
- 不同 h/d 组合（层数多 vs 层数少）

### Step 3: 实际 STARK benchmark（15-30 分钟）

对每个 top 候选：
1. 生成参数头文件 `params-sphincs-poseidon2-candidate-N.h`
2. `cargo test` → 实际 prove_seconds, proof_bytes
3. 与估算值对比，修正成本模型

### Step 4: 最终推荐（30 分钟）

输出论文表格：
- 推荐参数组（1-2 组）
- 实际证明时间、证明体积
- 安全评估（THF 模型）
- 与 SPHINCS+-128s 基线的对比

## 5. 实际运行结果

已在 960 个旧候选上运行成本模型。结果：

| 排名 | 候选ID | n | d | k | a | k·a | FORS安全 | perms | rows | prove |
|:---:|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 1 | **13** | 16 | 6 | 14 | 12 | 168 | 148.2 | 5630 | 262K | ~269s |
| 2 | 29 | 16 | 6 | 17 | 10 | 170 | 149.9 | 5646 | 262K | ~269s |
| 3 | 45 | 16 | 6 | 22 | 8 | 176 | 155.5 | 5681 | 262K | ~269s |

**最佳候选：id=13（n=16, h=60, d=6, k=14, a=12, w=16）**
- FORS 安全：148.2 bit（保守估计，紧致后更高）
- 预估证明时间：~4.5 分钟（262K 行）
- 预估证明体积：~134 KB

候选 13 与 dev 参数（d=4）处于不同的 pow2 区间（262K vs 131K），证明时间约 2x。但这是满足安全约束的最小代价。

## 6. 时间估算

| 步骤 | 时间 |
|:---|:---|
| 成本模型运行（Step 1） | ~1 分钟 |
| 人工选择候选（Step 2） | ~10 分钟 |
| 实际 benchmark（Step 3） | ~15-30 分钟（3 候选 × 5 分钟） |
| 报告整理（Step 4） | ~10 分钟 |
| **总计** | **~1 小时** |

vs 旧搜索：全量 benchmark 600 候选 × 5 分钟 = **50 小时**。速度提升 **~50x**。
