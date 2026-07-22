# 交付物 #13: 《密码学报》论文逐章规划

> 目标期刊：《密码学报》(CCF B, 中国密码学会主办)
> 对标论文：孙思维等, "SPHINCS+-SM3", 2023, Vol. 10, No. 6
> 规划日期：2026-07-22

---

## 论文标题（初步）

**"SPHINCS+-Poseidon2: 基于Fischlin框架的哈希基后量子盲签名——构造、安全分析与实现"**

备选：
- "面向区块链隐私保护的SPHINCS+-Poseidon2 Fischlin盲签名方案"
- "基于SPHINCS+和Poseidon2的Fischlin盲签名：协议设计、安全归约与STARK实现"

---

## 章节总览

| 章 | 标题 | 篇幅 | 核心功能 | 主要证据来源 |
|----|------|------|---------|------------|
| 1 | 引言 | 2页 | 问题→gap→贡献 | deliverable #01, #02, #12 |
| 2 | 预备知识 | 3页 | 技术背景 | survey.md §2, deliverable #03 |
| 3 | 方案构造 | 6页 | **核心贡献** | CURRENT_STATUS, air_engine.rs, ffi.h |
| 4 | 安全分析 | 3页 | 归约链 | SECURITY_ANALYSIS, deliverable #07 |
| 5 | 实现与评估 | 4页 | benchmark+对比 | CURRENT_STATUS, deliverable #12 §4 |
| 6 | 相关工作 | 1.5页 | 差异化 | survey.md §3-6, deliverable #02, #03 |
| 7 | 结论 | 0.5页 | 总结+展望 | deliverable #12 §5 |
| | **合计** | **~20页** | | |

---

## 逐章详细规划

### 第1章：引言（2页，~2000字）

**段落结构：**

```
¶1 后量子迁移背景
  - NIST PQC 标准化完成 (FIPS 204/205, 2024)
  - 标准签名 → 完成；隐私保护原语（盲签名）→ 尚未
  - 区块链隐私保护的量子威胁（链上数据长期存储，Harvest-now-decrypt-later）

¶2 现有后量子盲签名路线
  - 格基路线：del Pino-Katsumata (CRYPTO'22), Beullens (CCS'23), Argo (CCS'24)
    → 高效但依赖结构化代数假设
  - 同源基：CSI-Otter (CRYPTO'23) → 紧凑但安全性仍在评估
  - 哈希基路线：此前仅有理论讨论 ← 点出 gap

¶3 Fischlin框架与哈希基盲签名的理论可行性
  - Fischlin 通用构造 (2006→2015→2022→2026)
  - Bouillaguet et al. (IEEE S&P 2026): 任意hash-and-sign可编译为Fischlin盲签名
  - Herranz-Louiso (ePrint 2025): 哈希基盲签名可行性分析
  - 核心gap：通用编译器存在 + 理论可行 → 但无具体SPHINCS+实例

¶4 本工作的三个技术挑战
  1. Poseidon2如何适配SPHINCS+的THASH接口（SM-TCR/SM-DSPR/SM-PRE/SM-UD）
  2. Fischlin协议的SPHINCS+具体实例化（sigma_blind = SPHINCS+签名，无数学去盲）
  3. STARK证明如何覆盖整个crypto_sign_verify（~2000次Poseidon2置换的全内生AIR）

¶5 本文贡献（编号列表）
  1. 给出了首个基于SPHINCS+的Fischlin盲签名具体实例
  2. 将Poseidon2适配为SPHINCS+的可调哈希函数，验证其满足THF四性质
  3. 设计了覆盖全部SPHINCS+验证的Full-AIR STARK证明系统（23,861行×64列，53约束）
  4. 完成了完整的Rust+C工程实现，通过9项回归测试
  5. 给出了系统化的性能基准和安全参数分析

¶6 论文结构
  第2节介绍预备知识；第3节详述方案构造；第4节给出安全分析；
  第5节报告实现与性能评估；第6节讨论相关工作；第7节总结全文。
```

**关键决策点：**
- 是否在引言中提区块链场景？→ 提一句（1-2句），作为"应用背景"而非"主要贡献"。这是《密码学报》而非FC
- 贡献列表要不要编号？→ 要。《密码学报》惯例
- 与SPHINCS+-SM3论文的关系？→ 在¶5或¶6中引用，定位为"同类工作的延续"

---

### 第2章：预备知识（3页，~3000字）

**目的：** 让读者（密码学研究者，但不一定是SPHINCS+或STARK专家）能理解后续章节。不需要从零教起，但需要给出足够的符号定义和安全性定义。

**§2.1 SPHINCS+签名方案（1页）**
```
- 三层结构：WOTS+ → FORS → XMSS-MT hypertree
- 关键参数：(n, h, d, k, a, w) 的含义
- THF接口：Th(P, T, M) → {0,1}^n
- "simple" vs "robust" 实例化
- 安全模型：EUF-CMA，归约到THF四性质
- 引用规范 [Bernstein et al., CCS 2019]
```

**§2.2 Fischlin盲签名框架（0.7页）**
```
- 四阶段协议：Commit → Issue → Finalize → Show
- ⚠️ 关键说明：Fischlin框架中没有数学"去盲"操作
  sigma_blind被原样保留，blindness来自承诺的hiding性质
- 安全定义：OMUF (One-More Unforgeability) + Blindness
- 引用 [Fischlin CRYPTO 2006; Fuchsbauer CRYPTO 2015; Bouillaguet IEEE S&P 2026]
```

**§2.3 Poseidon2海绵构造（0.7页）**
```
- Goldilocks域: p = 2^64 - 2^32 + 1
- 状态: t=12 (rate=6, capacity=6)
- 置换: R_F=8 full rounds + R_P=22 partial rounds
- S-box: x → x^3 (gcd(3, p-1)=1 → permutation)
- 海绵模式: absorb + squeeze
- 在ZK电路中的效率优势
- 引用 [Grassi et al., AFRICACRYPT 2023]
```

**§2.4 STARK证明系统（0.6页）**
```
- AIR (Algebraic Intermediate Representation):
  执行跟踪矩阵 + 多项式约束
- 协议流程: trace → LDE → FRI → Merkle openings
- 关键属性: 透明(无trusted setup), 后量子安全, 对数级proof size
- Winterfell: 生产级Rust实现，Goldilocks原生
- 引用 [Ben-Sasson et al., ITCS 2020]
```

**关键决策点：**
- §2.2中要不要画Fischlin协议流程图？→ 要。一张图胜过一千字
- 表格：SPHINCS+参数含义表 → 放这里还是§3？→ 放这里，§3直接引用
- 符号表要不要单独列？→ 《密码学报》通常不需要，在正文首次出现时定义即可

**证据映射：**
- survey.md §2.1-2.4 → 四小节各自对应
- deliverable #03 → §2.2 Fischlin变体谱系（简化为当前使用的版本）

---

### 第3章：方案构造（6页，~6000字）**【核心贡献章】**

**这是论文最重要的章节。** 三个子章节分别对应三个技术层次：哈希适配 → 协议实例化 → 证明系统。

**§3.1 Poseidon2作为SPHINCS+可调哈希（2页）**

```
3.1.1 THASH实例化
  - Th(P, T, M) = Poseidon2_Sponge(P || T || M).squeeze(n)
  - P: pub_seed (padding到rate)
  - T: 32-byte ADRS (编码hypertree位置)
  - M: message (pad10*1到rate)
  - 域标签: THASH_F=0x11, THASH_H=0x12, THASH_TL=0x13
  - 图表: THASH调用流程图

3.1.2 ADRS编码与多目标防护
  - ADRS结构: layer(4B) + tree_addr(12B) + tree_idx(4B) + keypair_addr(4B) + chain_addr(4B) + hash_addr(4B) + type(4B)
  - 多目标防护原理: ADRS作为独立前缀 → ROM中模拟为独立RO
  - 表格: ADRS各字段在WOTS+/FORS/HT中的具体取值

3.1.3 参数选择
  - 开发参数: n=16, h=63, d=7, k=10, a=12, w=16 (128-bit目标)
  - 基准参数: (candidate 9) n=16, h=60, d=6
  - 与SPHINCS+-SM3参数的关系
```

**§3.2 Fischlin盲签名协议实例化（2页）**

```
3.2.1 协议角色与流程
  - 角色: Holder, Issuer, Verifier
  - 流程图（与CURRENT_STATUS.md的ASCII图对应，但画成正式图片）

3.2.2 协议详细步骤
  Step 1 - Prepare & Issue Request:
    com = Poseidon2_Sponge(m || r).squeeze()
    发送 com → Issuer

  Step 2 - Issue Response:
    sigma_blind = SPHINCS+_sign(sk_sig, com)
    发送 sigma_blind → Holder

  Step 3 - Finalize Credential:
    验证 SPHINCS+_verify(pk_sig, com, sigma_blind) = 1
    凭证witness: (sigma_com=sigma_blind, m, r, omega2)
    sigma_C = Bind(pk_E, com || sigma_blind; omega2)

  Step 4 - Show:
    pi_F = FullAIR.Prove(pk_sig, pk_E, com, m_pub, sigma_C, w)
    出示 Sigma = (sigma_C, pi_F) → Verifier
    验证: FullAIR.Verify(pk_sig, pk_E, m_pub, sigma_C, pi_F) ∈ {0,1}

3.2.3 公开输入与绑定
  - ctx_hash = Blake3(pk_sig || pk_E || com || m_pub || public_ctx || sigma_C)
  - 绑定到proof header (296 bytes)
  - 证明在验证时重新计算并比对
  - 意义：防跨上下文重放 + 半盲签名支持(public_ctx)

3.2.4 与Bouillaguet编译器的关系
  - 本文是Bouillaguet通用编译器的SPHINCS+具体实例
  - 差异点：我们的sigma_C绑定机制是原编译器未覆盖的工程增强
```

**§3.3 Full-AIR STARK证明系统（2页）**

```
3.3.1 设计原则
  - "全内生"：AIR覆盖crypto_sign_verify的全部执行，无需外部C guard
  - 与legacy混合证明（lib.rs）的对比：旧方案需要外部验证作为security guard

3.3.2 执行跟踪
  - 跟踪构建器: trace_builder.rs遍历crypto_sign_verify → 记录每步状态
  - 跟踪规模: 23,861行 × 64列 (128-bit params)
  - 列布局表:
    cols 0-3:   当前轮状态
    col 4:      轮计数器
    col 5:      置换索引
    col 6:      调用类型 (THASH_F/H/TL, Commit, SigmaC, ...)
    col 7:      pad标志
    cols 8-9:   前一轮carry
    cols 10-15: 速率通道 (current)
    cols 16-27: 预计算期望下一状态 (核心约束依据)
    cols 28-38: 辅助列 (absorb数据、地址解析等)
    cols 39-52: 海绵连续性状态
    col 53-57:  约束辅助列
    cols 58-63: 保留

3.3.3 AIR约束（53条）
  - 约束分类:
    ① 核心置换约束 (16条): 速率/容量通道等式、S-box、MDS矩阵
    ② 吸收绑定约束 (12条): THASH absorb[0..5] → domain+pub_seed+addr
    ③ 状态携带约束 (12条): sponge continuity across permutation blocks
    ④ THASH吸收验证 (8条): domain tag + address consistency
    ⑤ 布尔约束 (4条): pad flag, round counter MSB
    ⑥ 复制约束 (3条): boundary assertions (com_output, root_row)

  - 关键约束详解（选2-3个代表性约束给出数学表达式）:
    例: 速率通道等式（full round）
    例: 根断言边界约束（root_row）
    例: 海绵连续性carry约束

3.3.4 证明生成与验证
  - 证明参数: blowup=8, queries=27, ~108-bit conjectured security
  - 证明尺寸: ~85 KB
  - 证明格式: magic "PFP2" + version=2
  - 生成: spx_p2_rust_generate_pi_f_full_air()
  - 验证: spx_p2_rust_verify_pi_f_full_air()
```

**关键决策点：**
- §3.1要不要包含与SPHINCS+-SM3的详细对比？→ 不需要。在§6相关工作里对比。§3.1专注于"我们做了什么"
- §3.3的约束要不要全部列出？→ 不。选代表性约束给数学表达式，其余用文字+表格概述。全部53条放附录
- §3.2的流程图 → 让读者能不看文字就理解协议（审稿人通常先扫图）

**证据映射：**
- ref/stark-rs/src/air_engine.rs → §3.3
- ref/stark-rs/src/trace_builder.rs → §3.3.2
- ref/show/show_poseidon2.c → §3.2
- ref/hash_poseidon2_adapter.c → §3.1
- CURRENT_STATUS.md → 全章数据来源
- SECURITY_ANALYSIS.md §1 → §3.1的THASH适配

---

### 第4章：安全分析（3页，~3000字）

**目的：** 给出从底层哈希到顶层盲签名的完整安全归约链。这是《密码学报》审稿人最关注的理论深度部分。

**§4.1 安全模型与归约框架（0.5页）**
```
- 归约链: Poseidon2 → THF四性质 → SPHINCS+ EUF-CMA → Fischlin OMUF
- 每层沿用已有安全定理：
  第1→2层: ROM中海绵构造 → THF (SPHINCS+规范§7)
  第2→3层: THF四性质 → EUF-CMA (SPHINCS+规范Theorem 1-2)
  第3→4层: EUF-CMA → OMUF (Bouillaguet et al. Theorem 3)
- 图：四层归约链
```

**§4.2 Poseidon2满足THF四性质（1.2页）**
```
4.2.1 SM-TCR (单函数多目标碰撞抵抗)
  - 论证: ROM中，不同ADRS前缀 → 独立RO → 碰撞概率 = q²/2^n
  - Poseidon2轮数充分性: RF=8, RP=22 → 30轮 vs 已知攻击阈值~18轮

4.2.2 SM-DSPR (单函数多目标决定性第二原像抵抗)
  - 论证: 同上ROM bound + 域标签隔离不同THASH调用

4.2.3 SM-PRE (单函数多目标原像抵抗)
  - 论证: ROM中海绵输出的原像抵抗归约到Poseidon2置换的单向性

4.2.4 SM-UD (单函数多目标不可区分性)
  - 论证: 海绵构造在ROM中的标准不可区分性结果

4.2.5 多目标安全边际
  - 对比: 标准SPHINCS+ (q_s=2^64) vs 盲签名场景 (q_s=2^16~2^20)
  - 更小的q_s → 更大的安全边际
  - 表格: 不同q_s下的安全比特数
```

**§4.3 Fischlin盲签名安全性（0.8页）**
```
4.3.1 Blindness
  - com = Poseidon2(m || r) 的hiding性质
  - 即使sigma_blind被原样保留，Signer无法链接出示凭证到签发会话
  - r的高熵保证: r ∈ {0,1}^256 → 承诺统计hiding

4.3.2 One-More Unforgeability
  - 归约到SPHINCS+ EUF-CMA + 承诺binding
  - 承诺binding: 若敌手能打开c为两个不同的(m,r)，则攻破Poseidon2碰撞抵抗
  - 与Bouillaguet et al. Theorem 3的关系

4.3.3 STARK Soundness
  - STARK证明的knowledge soundness保证 π_F有效 → witness存在
  - ~108-bit conjectured security (blowup=8, queries=27)
  - 注意：这是conjectured而非provable security (STARK非标准模型可证)
```

**§4.4 参数安全性评估（0.5页）**
```
- 开发参数 (n=16): FORS安全性 k·a - log(q·k) → ~100+ bit
- 与SPHINCS+规范 Table 3的对应
- 盲签名场景下q_s缩减带来的安全增益
- 表格: 参数安全评估汇总
```

**关键决策点：**
- §4.2要不要自己重新推导THF bound？→ 不需要。直接引用SPHINCS+规范，论证Poseidon2满足前提条件即可。这是SPHINCS+-SM3论文的方法论（见SECURITY_ANALYSIS.md §1.2）
- SM-UD要不要扩展到标准模型？→ 不要。SPHINCS+本身就是ROM方案（特别是"simple" THASH），扩展无意义
- STARK soundness要不要给形式化证明？→ 不要。引用FRI原始论文 + Winterfell文档即可

**证据映射：**
- SECURITY_ANALYSIS.md → 全章
- deliverable #07 → 四层归约链
- survey.md §2.1 (SPHINCS+安全模型) → §4.1
- SPHINCS+规范 Theorem 1-2 → §4.2

---

### 第5章：实现与评估（4页，~4000字）

**目的：** 证明方案是可工作的，给出诚实的性能数字和局限性。

**§5.1 实现概览（0.5页）**
```
- C层: SPHINCS+ core + Poseidon2置换 + Fischlin协议 (ref/show/, ref/hash_poseidon2_adapter.*)
- Rust层: Winterfell STARK prover (ref/stark-rs/)
- FFI层: C ↔ Rust 接口 (ref/stark/ffi.*)
- 代码规模: ~X行C + ~Y行Rust
- 架构图
```

**§5.2 测试与正确性验证（0.5页）**
```
- 9项严格回归测试
- 测试覆盖:
  - 协议流 (poseidon2_protocol_flow)
  - Fischlin声明规范 (poseidon2_fischlin_statement_spec)
  - 全量guard (poseidon2_verify_full_guard)
  - 跨后端一致性 (poseidon2_cross_backend_consistency)
  - 声明绑定 (poseidon2_statement_binding)
  - 跟踪重放绑定 (poseidon2_trace_replay_binding)
  - 角色交互 (poseidon2_roles_interaction)
  - Fischlin盲签名端到端 (poseidon2_fischlin_blind_e2e)
  - STARK统计 (poseidon2_stark_stats)
  - + 1个补充严格核心测试 (poseidon2_stark_strict_core_enforcement)
```

**§5.3 性能基准（1.5页）**
```
5.3.1 实验环境
  - CPU, RAM, OS, Winterfell版本, Rust版本

5.3.2 核心性能指标（128-bit开发参数）
  - 表格:
    | 指标 | 值 |
    |------|-----|
    | 跟踪行数 | 23,861 (next pow2: 32,768) |
    | 列数 | 64 (实际使用: 58) |
    | Poseidon2置换次数 | 2,091 |
    | AIR约束数 | 53 |
    | 证明时间 | ~37 s |
    | 验证时间 | ~4 ms |
    | 证明尺寸 | ~85 KB |
    | 内存峰值 | ~4.6 GB |

5.3.3 与格基方案对比
  - 表格对比 Beullens (CCS'23), Argo (CCS'24)
  - 重点：不是比"谁更快"，而是展示不同假设路径的性能特征差异

5.3.4 参数对性能的影响
  - 对比开发参数(n=16) vs 基准参数(candidate 9)
  - 讨论blowup factor对proof size/prove time的影响
```

**§5.4 区块链场景适用性评估（1页）**
```
5.4.1 匿名凭证场景
  - 凭证生命周期模型: 签发(37s, 一次性) → 出示(4ms, 多次)
  - 与W3C VC的集成路径

5.4.2 链上验证成本
  - Ethereum L1 gas估算: ~1.5M-2.5M gas ≈ $90-150
  - 降低成本的路径: STARK-to-SNARK wrapping, proof aggregation, 链下验证

5.4.3 产业技术栈验证
  - TSN, H33.ai等项目的技术选型与本方案一致
  - 说明：产业实践验证了Poseidon2+SPHINCS++STARK技术路线的可行性

5.4.4 当前局限
  - STARK proving time (~37s) 限制实时场景
  - 硬编码n=16，参数化(n=24等)尚未完成
  - 无形式化UC proof，无侧信道防护
```

**§5.5 与SPHINCS+-SM3的对比（0.5页）**
```
- 贡献维度对比表:
  | 维度 | SPHINCS+-SM3 [密码学报 2023] | 本文 |
  |------|---------------------------|------|
  | 哈希替换 | SM3 → SPHINCS+ THASH | Poseidon2 → SPHINCS+ THASH |
  | 盲签名 | 无 | Fischlin框架完整实例化 |
  | ZK证明 | 无 | Full-AIR STARK (53约束) |
  | 安全归约 | THF四性质 → EUF-CMA | THF → EUF-CMA → OMUF |
  | 实现 | C | C + Rust (Winterfell) |
  | 应用场景 | 标准数字签名 | 盲签名 + 区块链隐私 |
```

**关键决策点：**
- §5.4要不要包含？→ 要。虽然《密码学报》是密码学刊而非区块链刊，但应用场景验证增加了论文的"实践价值"维度
- §5.5要不要放在Related Work而不是评估里？→ 放评估里更好。因为这里是对比"同类工作的贡献维度"，而非general related work
- 实验是否需要在多平台上跑？→ 《密码学报》通常接受单平台benchmark。如果有时间可以加一个对比平台

**证据映射：**
- CURRENT_STATUS.md → 全章数据
- ref/TESTING.md → §5.2
- scripts/collect_benchmark_v2.sh → §5.3 数据来源
- deliverable #12 §4 → §5.4 链上成本分析
- SECURITY_ANALYSIS.md §2 → 参数安全评估

---

### 第6章：相关工作（1.5页，~1500字）

**目的：** 系统化地定位本文与现有工作的关系，展示对文献的掌握。

**§6.1 SPHINCS+哈希替换（0.3页）**
```
- SPHINCS+-SM3 [密码学报 2023]: SM3替换SHAKE → 同为哈希替换范式
- 其他SPHINCS+变体: Haraka, SHA-256 instances
- 本文差异化: 替换目标不是国密合规，而是ZK友好 + 盲签名支持
```

**§6.2 后量子盲签名（0.5页）**
```
- 格基路线: del Pino-Katsumata (CRYPTO'22), Beullens (CCS'23),
  Agrawal (CCS'22), Kastner (CRYPTO'24)
- 同源基: CSI-Otter (CRYPTO'23), Katsumata et al. (DCC'24)
- 哈希基理论: Bouillaguet et al. (IEEE S&P'26), Herranz-Louiso (ePrint'25)
- 本文定位: 哈希基路线首个具体实现
- 关键区分: 本方案无数学去盲操作（Fischlin范式），格基方案有代数去盲
```

**§6.3 ZK友好哈希与STARK证明（0.4页）**
```
- ZK哈希: Poseidon, Poseidon2, Monolith, Griffin, Anemoi
- STARK证明签名: Quan (IEEE Access'22), 其他SNARK-based签名证明
- 本文特色: Poseidon2同时服务SPHINCS+验证和STARK AIR — 协同设计
```

**§6.4 区块链隐私保护（0.3页）**
```
- 产业方案: Zcash (Groth16 SNARK), Monero (Bulletproofs), Tornado Cash
- 后量子区块链隐私: Buser et al. (ACM Surveys'22), TSN, H33.ai
- 本文: 提供纯哈希基后量子隐私的密码学基础
```

**关键决策点：**
- 每个小节的篇幅严格控制——审稿人先扫这里，信息密度要高
- 不要只说"XX做了YY"，而要给出"XX做了YY，但我们的ZZ不同在于..."
- 引用国内工作（SPHINCS+-SM3等）展示对国内社区的了解

**证据映射：**
- survey.md §3-6 → 全章
- deliverable #02 → 2025-2026文献gap
- deliverable #03 → Fischlin谱系
- deliverable #04 → ZK哈希对比
- deliverable #06 → 参考论文映射

---

### 第7章：结论（0.5页，~500字）

```
¶1 总结
  - 本文给出了首个SPHINCS+ Fischlin盲签名实例
  - Poseidon2-STARK协同设计使哈希基盲签名实用化
  - 四层安全归约链保证了从哈希函数到盲签名的完整安全性

¶2 未来工作
  - 参数可扩展性: n=24 (192-bit安全), n=32 (256-bit安全)
  - STARK证明优化: 递归证明组合、GPU/FPGA加速、更紧凑的proof
  - 形式化安全: UC模型下的组合安全性证明
  - 侧信道防护: 盲签名场景中的timing/power分析防护
  - 标准制定: CFRG/IETF的后量子盲签名标准推进
```

---

## 附录（可选）

```
A. 完整AIR约束列表 (53条约束的数学表达式)
B. 执行跟踪列布局完整表
C. 参数安全性评估详细计算
```

---

## 需要制作的关键图表清单

| # | 图表 | 所在章节 | 类型 |
|----|------|---------|------|
| 1 | SPHINCS+三层结构示意图 | §2.1 | 图 |
| 2 | Fischlin四阶段协议流程图 | §2.2 | 图 |
| 3 | Poseidon2海绵结构图 | §2.3 | 图 |
| 4 | THASH调用流程图（域标签+ADRS） | §3.1 | 图 |
| 5 | 本方案协议角色与交互 | §3.2 | 图（核心图） |
| 6 | 执行跟踪列布局表 | §3.3 | 表 |
| 7 | AIR约束分类与数量表 | §3.3 | 表 |
| 8 | 四层安全归约链 | §4.1 | 图 |
| 9 | 不同q_s下的安全比特数 | §4.2 | 表 |
| 10 | 实现架构（C-Rust-FFI） | §5.1 | 图 |
| 11 | 核心性能指标表 | §5.3 | 表 |
| 12 | 与格基方案性能对比表 | §5.3 | 表 |
| 13 | 与SPHINCS+-SM3贡献维度对比 | §5.5 | 表 |
| 14 | 后量子盲签名方案全景对比 | §6.2 | 表 |

---

## 参考文献清单（核心引用，约25-30篇）

### 直接相关（必须引用）
1. Bernstein et al., "The SPHINCS+ Signature Framework," CCS 2019
2. Bouillaguet et al., "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026
3. Herranz & Louiso, "Hash-Based Blind Signatures: First Steps," ePrint 2025
4. Grassi et al., "Poseidon2: A Faster Version of the Poseidon Hash Function," AFRICACRYPT 2023
5. Ben-Sasson et al., "DEEP-FRI: Sampling Outside the Box Improves Soundness," ITCS 2020
6. Fischlin, "Round-Optimal Composable Blind Signatures in the CRS Model," CRYPTO 2006
7. Fuchsbauer et al., "Practical Round-Optimal Blind Signatures in the Standard Model," CRYPTO 2015
8. 孙思维等, "SPHINCS+-SM3: 基于SM3的无状态数字签名算法," 密码学报 2023

### 后量子盲签名对比
9. del Pino & Katsumata, "A New Framework for More Efficient Round-Optimal Lattice-Based Blind Signature," CRYPTO 2022
10. Beullens et al., "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal," CCS 2023
11. Argo et al., "Practical Post-Quantum Signatures for Privacy," CCS 2024
12. Kastner et al., "Pairing-Free Blind Signatures from Standard Assumptions in the ROM," CRYPTO 2024

### ZK哈希与证明系统
13. Grassi et al., "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems," 2019
14. Grassi et al., "Monolith: Circuit-Friendly Hash Functions," ToSC 2024

### 区块链/应用
15. Buser et al., "A Survey on Exotic Signatures for Post-quantum Blockchain," ACM CSUR 2022
16. Valenta & Rowan, "Blindcoin: Blinded, Accountable Mixes," FC 2015

### 标准与规范
17. NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard," 2024
18. NIST IR 8413, "Status Report on the Third Round of the NIST PQC Standardization Process," 2022

---

## 与SPHINCS+-SM3论文的结构对比

| 维度 | SPHINCS+-SM3 [2023] | 本文规划 |
|------|-------------------|---------|
| 篇幅 | ~12页 | ~20页 |
| 核心贡献层数 | 1层 (哈希替换) | 3层 (哈希 + 盲签名 + STARK) |
| 协议设计 | 无 (直接使用SPHINCS+) | 有 (Fischlin四阶段) |
| ZK证明 | 无 | 有 (Full-AIR STARK) |
| 安全归约深度 | 2层 (THF→EUF-CMA) | 4层 (Poseidon2→THF→EUF-CMA→OMUF) |
| 实现语言 | C | C + Rust (FFI) |
| 实验部分 | 参数分析为主 | benchmark + 场景验证 |
| 应用场景 | 标准数字签名 | 盲签名 + 区块链隐私 |

**本文不应被视为SM3论文的简单扩展，而是在其基础上的三个方向的同时推进。**

---

*规划完成：2026-07-22。进入写作阶段前建议确认：(1) 标题选择；(2) 区块链场景在论文中的篇幅比例；(3) §3.3约束列表的详细程度。*
