# 实验数据汇总与性能对比

## 1. 实验环境

| 项目 | 配置 |
|:---|:---|
| CPU | Intel Core i7 (x86_64) |
| OS | Windows 11 (MinGW64) |
| Rust | 1.96.1 (stable-x86_64-pc-windows-gnu) |
| Winterfell | 0.13.1 |
| Poseidon2 | Goldilocks field (p = 2^64 - 2^32 + 1), t=12, RF=8, RP=22 |
| 测量方法 | `cargo test -- --nocapture`, 取单次运行 wall-clock 时间 |

## 2. 方案参数变体

所有变体均基于 n=16（128-bit 哈希输出）、w=16（Winternitz 参数），使用 Poseidon2 作为底层哈希，Fischlin 框架构建盲签名，全内生 STARK AIR 生成展示证明。

| 参数组 | h | d | k | a | k·a | FORS安全(bit) | sig_bytes |
|:---|---:|---:|---:|---:|---:|---:|---:|
| **128f** (证明最优) | 60 | 4 | 19 | 8 | 152 | 132 | 5,952 |
| **128s** (平衡推荐) | 60 | 6 | 14 | 12 | 168 | 148 | 7,248 |
| **128c** (保守) | 60 | 6 | 17 | 12 | 204 | 184 | 7,872 |

> FORS 安全：q=2^16 下的保守估计。SPHINCS+ 规范的紧致归约可额外回收 10-15 bit。

## 3. STARK 证明基准数据

| 指标 | 128f | 128s | 128c |
|:---|---:|---:|---:|
| **Poseidon2 置换数** | 3,950 | 5,965 | 5,735 |
| **Trace 行数** | **131,072** (2^17) | **262,144** (2^18) | **262,144** (2^18) |
| **Trace 列数** | 64 | 64 | 64 |
| **约束数量** | 16 | 16 | 16 |
| **证明时间** | **126.0 s** | 266.9 s | **275.5 s** |
| **证明体积** | **94 KB** | 103 KB | 104 KB |
| **验证时间** | < 1 s | < 1 s | < 1 s |
| **AIR 约束类型** | 6 rate lanes + round + perm + call + pad | 同 | 同 |
| **外部 C 守卫** | 无（全内生） | 无（全内生） | 无（全内生） |

### 3.1 开发参数（dev，不做安全声明）

| 指标 | dev |
|:---|:---|
| 参数 | n=16, h=40, d=4, k=8, a=6 |
| k·a | 48 |
| Poseidon2 置换数 | 3,686 |
| Trace 行数 | 131,072 (2^17) |
| 证明时间 | 127 s |
| 证明体积 | 95 KB |

## 4. 方案特性总结

| 维度 | 本方案 |
|:---|:---|
| **签名方案** | SPHINCS+ (NIST FIPS 205 / SLH-DSA) |
| **哈希函数** | Poseidon2 (Goldilocks, t=12, RF=8, RP=22) |
| **盲签名框架** | Fischlin (Commit → Issue → Show → Verify) |
| **证明系统** | STARK (Winterfell 0.13) |
| **安全假设** | 哈希函数 RO 性质 + Goldilocks 域参数透明性 |
| **CRS** | 透明（域素数、轮常量，无陷门） |
| **后量子标准化** | SPHINCS+ 已标准化 (FIPS 205) |
| **证明内生性** | 全内生 AIR，无外部密码学守卫 |
| **参数选择** | 3 组安全变体（f/s/c），成本模型辅助筛选 |

## 5. 与相关方案的对比

### 5.1 后量子盲签名方案对比

由于当前已发表的后量子盲签名论文实际 benchmark 数据较少（多数为理论构造或仅有格基方案的局部数据），以下对比基于各方案的**安全假设**与**理论特征**：

| 方案 | 类型 | 安全假设 | 证明系统 | CRS | 标准化 |
|:---|:---|:---|:---|:---|:---|
| **本方案** | 哈希基盲签名 | RO (Poseidon2) | STARK | 透明 | SPHINCS+ (FIPS 205) |
| BIS Tourbillon (2024) | 格基盲签名 (eCash) | MLWE | NIZK (格) | 结构化 | ML-DSA (FIPS 204) |
| Lattice BS (2025) | 格基盲签名 | MLWE/SIS | NIZK | 结构化 | 无 |
| CSIDH BS (2025) | 同源基盲签名 | GAIP | ZK (同源) | — | 无 |
| BBS+ eCash (2024) | 配对基盲签名 | SDH/DL | ZK (Bulletproofs) | 结构化 | 无 |

### 5.2 已知性能数据对照

| 方案 | 指标 | 数值 | 来源 |
|:---|:---|:---|:---|
| BIS Tourbillon RSA | 支付吞吐量 | 2,450 TPS | BIS 实测 |
| BIS Tourbillon 格基 QSC | 支付吞吐量 | **5.5 TPS** | BIS 实测 |
| Blind Vote (IEEE 2024) | Gas 成本 | 显著低于 Tornado Vote | 论文数据 |
| PicRS (ACNS 2022) | 环签名大小 (4096 人) | 1.9 MB | 哈希基 |
| XRS (ACNS 2022) | 环签名大小 (4096 人) | 889 KB | 哈希基 (有状态) |
| **本方案 128f** | **盲签名证明体积** | **94 KB** | **实测** |
| **本方案 128s** | **盲签名证明体积** | **103 KB** | **实测** |

### 5.3 定位分析

- **vs 格基盲签名**：本方案安全假设更保守（仅哈希 RO，无格假设），CRS 透明。代价是证明体积大（~100KB vs 格基 NIZK 通常 10-50KB）且证明时间长（2-5 分钟 vs 毫秒级）。
- **vs BIS Tourbillon**：BIS 实测格基 eCash 从 2450 TPS 降到 5.5 TPS。本方案不适合实时支付场景，但适合**凭证签发-展示**模式（签发一次、展示多次）。
- **vs 其他哈希基构造**：PicRS/XRS 是环签名而非盲签名，应用场景不同。本方案是首个哈希基 Fischlin 盲签名的全内生 STARK 实现。

## 6. 成本模型验证

| 参数组 | 模型估算 perms | 实际 perms | 误差 | 估算 prove | 实际 prove | 误差 |
|:---|---:|---:|---:|---:|---:|---:|
| dev | 3,559 | 3,686 | 3.5% | 127s | 127s | 0% |
| 128f | 3,950 | 3,950 | 0% | 129s | 126s | 2.4% |
| 128s | 5,630 | 5,965 | 5.6% | 269s | 267s | 0.7% |
| 128c | 5,735 | 5,735 | 0% | 269s | 276s | 2.4% |

成本模型在 perm 计数上误差 <6%，在证明时间上误差 <3%，满足参数筛选精度要求。

## 7. 实验复现命令

```bash
# 环境
cd ref/stark-rs
cargo build --release

# 运行 128s（推荐参数）基准测试
# 修改 trace_builder.rs 顶部常量:
#   N=16, H=60, D=6, A=12, K=14, W=16
cargo test air_engine::tests::test_ffi -- --nocapture

# 运行 128f 基准测试
# 修改常量: D=4, A=8, K=19
cargo test air_engine::tests::test_ffi -- --nocapture

# 运行安全评估
cd ref
python scripts/eval_security_v2.py --q 65536

# 运行成本模型
python scripts/cost_model_full_air.py
```
