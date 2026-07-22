# 交付物 #6: 参考论文分析 — 投稿去向与实验设计

## 概述

本交付物分析 6 篇与本项目贡献度类似的论文（工程组合创新 + 完整实现）。每篇分析：贡献类型、投稿去向、实验设计、与本项目对比。

---

## 1. SPHINCS+-SM3 (孙思维等, 2023)

### 基本信息
- **标题:** "SPHINCS+-SM3: 基于SM3的无状态数字签名算法"
- **发表:** 《密码学报》, 2023, Vol. 10(6): 1266-1278
- **领域:** 国内 CCF B 类期刊（密码学一级学报）
- **贡献类型:** ⭐⭐⭐⭐ 工程替换型 — 将 SPHINCS+ 的哈希后端从 SHA-256 替换为 SM3（中国商用密码哈希标准）

### 贡献分析
- **核心贡献:** 首次用 SM3 实例化 SPHINCS+ 的 THF，给出 2 组满足 NIST 安全类别 1 的参数
- **创新类型:** "替换哈希" — 不是新算法设计，而是将现有哈希嵌入到现有框架中
- **理论深度:** 低 — 未提出新安全性证明，直接引用 SPHINCS+ 规范的 Theorem 1-2
- **工程量:** 中等 — 需要将 SM3 的海绵构造改写为 THASH 模式

### 与本项目的相似度: ⭐⭐⭐⭐⭐
- **相同点:**
  - 底层框架不变（SPHINCS+），仅替换哈希组件
  - 安全性论证使用同样的模块化 THF 方法
  - 给出目标安全级别的参数实例
- **不同点:**
  - SM3 替换 SHA-256（国家合规需求），本项目 Poseidon2 替换 SHA-256（ZK 证明效率需求）
  - 本项目额外包含 Fischlin 盲签名 + STARK 层（技术上更复杂）
  - 本项目有完整的代码实现和 benchmark（该文可能仅有参数分析）

### 实验设计
- 参数搜索：在 n=16/24/32 下给出 SM3 实例化的 k, a, h, d 参数
- 与标准 SPHINCS+ 参数对比签名大小和哈希次数
- 未实现完整 C 代码（推测基于参数分析）

### 对本项目的启示
1. **投稿去向:** 《密码学报》明确接收"哈希替换+参数分析"类的工程密码学论文。本项目的复杂度高于该文，因此在《密码学报》发表是可行的
2. **实验设计借鉴:** 参数表格 + 与标准方案的对比
3. **论文结构参考:** 背景 → SM3 简介 → THF 适配 → 参数选择 → 安全性分析 → 结论

---

## 2. Argo et al. — "Practical Post-Quantum Signatures for Privacy" (CCS 2024)

### 基本信息
- **标题:** "Practical Post-Quantum Signatures for Privacy"
- **发表:** ACM CCS 2024, CCF A（安全四大顶会之一）
- **DOI:** 10.1145/3658644.3670297
- **作者:** Sven Argo, Tim Güneysu, Corentin Jeudy, Georg Land, Adeline Roux-Langlois, Olivier Sanders
- **引用:** 16 次 (截至 2026)
- **贡献类型:** ⭐⭐⭐⭐⭐ 工程实现型 — 将格基盲签名/群签名/匿名凭证从设计文档变为可运行代码

### 贡献分析
- **核心贡献:** **第一个**完整的后量子隐私签名的实现和基准测试，覆盖：
  - 盲签名 (blind signatures)
  - 群签名 (group signatures)
  - 匿名凭证 (anonymous credentials)
  所有方案均为格基
- **创新类型:** 不是新方案——而是将已有方案**首次实现**并进行全面的性能分析
- **理论深度:** 低（不提出新安全性证明）
- **工程量:** 高 — 多个独立方案的 C/Rust 实现 + 端到端 benchmark

### 与本项目的相似度: ⭐⭐⭐⭐⭐ (最接近的对标论文)
- **相同点:**
  - "首次完整实现"类型的论文
  - 不提出新方案，验证已有方案的可部署性
  - 使用 benchmark 作为主要评估手段
  - 在 CCS (CCF A) 发表
- **不同点:**
  - Argo 实现的是格基方案（多种），本项目是哈希基方案（一种但含 Fischlin + STARK）
  - Argo 是"广度型"（多个方案），本项目是"深度型"（一个方案但全栈：SPHINCS+ → Poseidon2 → Fischlin → STARK）
  - Argo 不含 ZK 证明系统（格基方案不需要额外 ZK 层），本项目包含完整的 STARK 证明

### 实验设计 (可直接借鉴!)
**Table 1:** 各方案的签名/凭证尺寸对比（字节数）
**Table 2:** KeyGen, Sign, Verify 的时间（微秒/毫秒），在不同安全级别下
**Table 3:** 盲签名协议的 User/Signer 计算量
**Table 4:** 匿名凭证的 Issuance/Presentation/Verification 时间
**Figure 1:** 签名尺寸 vs 安全性 trade-off 图
**Figure 2:** 各方案在不同 CPU 上的性能 scaling

### 对本项目的启示
1. **这篇论文证明了"纯工程实现"可以在 CCS 发表** — 关键是它是该方向的"第一个"
2. **实验设计模板:** 本项目的实验应包含类似的表格和图表
3. **论文叙述策略:** Argo 的 introduction 以"尽管已有理论方案，但无人实现，无法评估实际性能"开篇——这正是本项目的策略

---

## 3. Herranz & Louiso — "Hash-Based Blind Signatures: First Steps" (ePrint 2025)

### 基本信息
- **标题:** "Hash-Based Blind Signatures: First Steps"
- **发表:** IACR [[ePrint 2025/209](https://eprint.iacr.org/2025/209)7](https://eprint.iacr.org/2025/2097)（预印本，尚未正式发表）
- **贡献类型:** ⭐⭐⭐ 问题定义型 — 识别挑战和设计空间

### 贡献分析
- **核心贡献:** 首次系统分析哈希基盲签名的可行性，提出三个挑战
- **创新类型:** 问题空间探索，未给出完整解决方案
- **实现:** 用 MSS (Merkle Signature Scheme) + MPC-in-the-Head 做原型验证
- **实验:** Benchmark 仅涉及签名大小和 proof 电路大小的估算

### 与本项目的对比
| 维度 | Herranz 2025 | 本项目 |
|------|------------|--------|
| 底层签名 | MSS (有状态) | **SPHINCS+ (无状态, NIST 标准)** |
| 证明系统 | ZKBoo (MPC-in-the-Head) | **Winterfell STARK** |
| 哈希函数 | 通用哈希 | **Poseidon2 (ZK 友好)** |
| 实现状况 | 原型, 电路估算 | 完整实现, 端到端 benchmark |
| Prove Time | 未给出 | **37s** |
| Proof Size | 估算 ~500KB+ | **85KB** |

### 投稿去向分析
- 以 ePrint 预印本形式发布，尚未正式发表
- 如果投稿，可能目标：PKC, ACISP, CANS 等应用密码学会议
- 该文的问题定义规模不足以支撑顶会接受（缺乏完整实现和 benchmark），本项目的完整性远超过它

---

## 4. Bouillaguet et al. — "Blinding Post-Quantum Hash-and-Sign Signatures" (IEEE S&P 2026)

### 基本信息
- **发表:** IEEE S&P 2026 (Oakland), CCF A
- **DOI:** 10.1109/SP63933.2026.00032
- **贡献类型:** ⭐⭐⭐⭐⭐ 理论框架型 — 通用编译器

### 实验设计
- 对 UOV (多元) 和 Wave (编码基) 两种签名方案给出编译器实例化的 benchmark
- **Table:** 编译器 overhead（签名尺寸增幅、证明时间）
- **Figure:** Proof size vs security level
- 未实现 SPHINCS+ 实例化

### 对本项目的启示
1. 该文在 S&P (顶会) 发表，说明"Fischlin 编译器"这一方向受社区认可
2. 该文明确提及 SPHINCS+ 是适用的，但未实现 → 直接引用作为 related work 并在该框架下定位本文
3. 该文的实验作为 compiler overhead 的基线——本项目的 37s prove time 应与此对比

---

## 5. CAPSS — Feneuil & Rivain ([ePrint 2025/061](https://eprint.iacr.org/2025/061))

### 基本信息
- **标题:** "CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures"
- **发表:** IACR [ePrint 2025/061](https://eprint.iacr.org/2025/061)
- **贡献类型:** ⭐⭐⭐ 框架定义型 — 定义了"SNARK 友好签名"的概念

### 贡献分析
- 不是盲签名
- 但设计哲学相同：**哈希+证明共设计**
- 提出了 SNARK 友好签名的设计准则（小域、低乘法深度、无按位运算）

### 与本项目的关系
- Reference 引用：作为"证明友好密码学设计"的 prior art
- 与本项目有相同的哲学（证明友好设计），但应用于不同问题（标准签名 vs 盲签名）

---

## 6. Liu et al. — "A hash-based post-quantum ring signature scheme for the Internet of Vehicles" (JSA 2025)

### 基本信息
- **发表:** Journal of Systems Architecture, 2025 (CCF B 期刊, 嵌入式系统/体系结构方向)
- **DOI:** 10.1016/j.sysarc.2025.103345
- **贡献类型:** ⭐⭐⭐⭐ 工程实现+场景应用型

### 贡献分析
- **核心贡献:** 构造了基于哈希的后量子环签名，应用于车联网匿名认证
- **创新:** 哈希基环签名的车联网适配（非新签名方案，而是工程适配）
- **实验:**
  - 签名/验证时间对比（与 Dilithium、Falcon、SPHINCS+ 对比）
  - 在不同车载设备上的性能 profiling
  - 通信开销对比（CAN bus 数据包大小）

### 对本项目的启示
1. **投稿去向验证:** JSA (CCF B) 接收"密码学方案+物联网场景"的工程论文
2. **实验借鉴:** 设备 profiling + 场景 benchmark (不仅是纯算法 benchmark)
3. **论文结构:** 算法描述 → 场景适配 → 安全性分析 → 实验（算法 + 场景） → 结论

---

## 7. 综合对比：6 篇论文的投稿规律

| 论文 | 贡献类型 | 投稿去向 | CCF等级 | 接收理由 |
|------|---------|---------|---------|---------|
| SPHINCS+-SM3 | 哈希替换 | 《密码学报》 | B (国内) | 首个 SM3 实例化 + 参数分析 |
| Argo et al. | 首次完整实现 | CCS | A | 首个 PQ 隐私签名 benchmark |
| Herranz | 问题定义+原型 | ePrint (预印本) | 无 | 探索性工作，未正式发表 |
| Bouillaguet | 通用编译器+理论归约 | IEEE S&P | A | 新颖性高的理论贡献 |
| CAPSS | 框架定义 | ePrint (预印本) | 无 | 设计准则提案 |
| Liu et al. | 工程适配+场景 | JSA | B | 哈希基方案 + 车联网场景 |

**规律总结:**

1. **"首次实现"可以在 CCF A 发表** (Argo, CCS'24) — 但需要有足够的工程复杂度（多个方案）或方向重要性
2. **"组件替换"可以在 CCF B 发表** (SPHINCS+-SM3, 密码学报) — 但需要明确的应用需求驱动（国密合规）
3. **纯问题定义/框架建议** 通常留在 ePrint 预印本 — 需要实现或 benchmark 才能正式发表
4. **工程适配+应用场景** 在 CCF B 期刊（JSA 等）可发表 — 场景是加分项

### 本项目的投稿策略推断

| 投稿目标 | 可行性 | 理由 |
|---------|--------|------|
| CCF A (CCS, S&P) | ⚠️ 挑战性 | 需要更强的实验（多参数/对比格基方案）+ 更强的叙事 |
| CCF B (JSA, 密码学报, ACISP) | ✅ 可行 | 与 SPHINCS+-SM3 和 Liu et al. 同级别贡献 |
| CCF C (CANS, ISPEC, FC) | ✅ 安全 | 贡献远超常规 CCF C 论文 |

**推荐策略:** **B 为主, A 为冲刺, C 为保底**

---

## 参考文献

- [Argo et al. 2024] S. Argo, T. Güneysu, C. Jeudy, G. Land, A. Roux-Langlois, O. Sanders, "Practical Post-Quantum Signatures for Privacy," CCS 2024. [DOI: 10.1145/3658644.3670297](https://doi.org/10.1145/3658644.3670297)
- [Bouillaguet et al. 2026] C. Bouillaguet et al., "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. [DOI: 10.1109/SP63933.2026.00032](https://doi.org/10.1109/SP63933.2026.00032)
- [Herranz-Louiso 2025] J. Herranz, H. Louiso, "Hash-Based Blind Signatures: First Steps," IACR [[ePrint 2025/209](https://eprint.iacr.org/2025/209)7](https://eprint.iacr.org/2025/2097).
- [Feneuil-Rivain 2025] T. Feneuil, M. Rivain, "CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures," IACR [ePrint 2025/061](https://eprint.iacr.org/2025/061).
- [孙思维等 2023] 孙思维等, "SPHINCS+-SM3: 基于SM3的无状态数字签名算法," 《密码学报》, 2023, 10(6): 1266-1278. [DOI: 10.13868/j.cnki.jcr.000536](https://doi.org/10.13868/j.cnki.jcr.000536)
- [Liu et al. 2025] S. Liu et al., "A hash-based post-quantum ring signature scheme for the Internet of Vehicles," JSA, 2025. [DOI: 10.1016/j.sysarc.2025.103345](https://doi.org/10.1016/j.sysarc.2025.103345)
- [Bernstein et al. 2019] D. J. Bernstein et al., "The SPHINCS+ Signature Framework," CCS 2019. [DOI: 10.1145/3319535.3363229](https://doi.org/10.1145/3319535.3363229)
- [Beullens et al. 2023] W. Beullens et al., "Lattice-Based Blind Signatures," CCS 2023. [DOI: 10.1145/3576915.3616613](https://doi.org/10.1145/3576915.3616613)
