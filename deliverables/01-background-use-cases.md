# 交付物 #1: 背景与使用场景

## 1. 抗量子盲签名：动机与需求

### 1.1 后量子迁移的紧迫性

NIST 于 2024 年正式发布了首批后量子密码（PQC）标准，包括 CRYSTALS-Dilithium（ML-DSA）、Falcon（FN-DSA）和 SPHINCS+（SLH-DSA）[NIST IR 8413, 2022]。这三个方案解决了**标准数字签名**的后量子安全问题。然而，在隐私保护的密码学领域——盲签名、群签名、匿名凭证——相应的后量子迁移尚未完成。

传统盲签名方案（如 RSA 盲签名 [Chaum, 1983]、Schnorr 盲签名 [Schnorr, 2001]）的安全性依赖于离散对数问题或大整数分解问题，在 Shor 算法面前不堪一击。当前部署中的隐私系统——从 TLS 1.3 的 Privacy Pass 协议 [RFC 9578] 到 W3C 的可验证凭证标准——几乎全部基于配对或离散对数假设，面临量子威胁。

### 1.2 后量子盲签名的三条技术路线

目前，后量子盲签名有三条主要技术路线：

**路线 1: 格基方案。** 格上的 SIS/LWE 困难问题是后量子密码的主流基础。近年来的里程碑包括：
- del Pino 和 Katsumata [CRYPTO 2022] 提出了首个基于模 SIS/LWE 的轮数最优（2 轮）盲签名，通过 Trapdoor 抽样实现 Fischlin 框架的格基实例化
- Beullens, Lyubashevsky, Nguyen, Seiler [CCS 2023] 进一步改进了效率，签名大小缩减至 20 KB，是目前最紧凑的标准假设格基盲签名
- Argo et al. [CCS 2024] 首次对后量子盲签名、群签名、匿名凭证完成了**完整的工程实现和基准测试**，证明了格基隐私方案的可部署性
- Kastner, Nguyen, Reichle [CRYPTO 2024] 提出了无需 Pairing 的标准假设盲签名

格基方案的**优势**在于：紧凑性（~20 KB 签名）、丰富代数结构支持高级功能。**劣势**在于：（1）依赖结构化格假设（Ring/Module SIS/LWE），这些假设的安全边际仍在研究之中；（2）部分高效方案需要 ad-hoc 假设（如 NTRU）。

**路线 2: 同源基方案。** Katsumata et al. [CRYPTO 2023, DCC 2024] 构造了基于 CSIDH-512 的同源盲签名（CSI-Otter），实现 4-8 KB 的签名大小。同源方案的**优势**在于更小的公钥和签名尺寸（目前后量子盲签名中最小的）。**劣势**在于：（1）CSIDH-512 的安全性仍在评估中；（2）计算效率低（类群作用计算慢）；（3）同源密码生态仍不够成熟。

**路线 3: 哈希基方案（本项目的路线）。** 使用纯粹的哈希函数安全性，不依赖任何数论假设。Bouillaguet et al. [IEEE S&P 2026] 证明任何后量子 Hash-and-Sign 签名方案可以通过 Fischlin 框架编译为盲签名。本项目的贡献正是这条路线：**用 SPHINCS+（NIST 标准）+ Poseidon2（ZK 友好哈希）+ STARK（透明零知识证明）给出第一个具体实例化**。

三条路线的核心对比：

| 维度 | 格基 (Lattice) | 同源基 (Isogeny) | 哈希基 (Hash-based, 本文) |
|------|---------------|-----------------|------------------------|
| 底层假设 | Ring/Module SIS/LWE | CSIDH 群作用求逆 | 哈希函数（ROM） |
| 后量子成熟度 | 高（NIST 标准） | 中（仍在评估） | **最高（NIST FIPS 205）** |
| 签名大小 | ~20 KB (Beullens) | ~4-8 KB (CSI-Otter) | ~85 KB (含 STARK proof) |
| 轮数 | 2 (最优) | 2 (最优) | 2 (最优) |
| 证明系统 | MPC-in-the-Head / 格基 ZK | 无（Schnorr 变体） | **STARK（对数级 proof size）** |
| 密码学保守性 | 中 | 低 | **极高（无代数结构）** |

### 1.3 使用场景一：匿名凭证与 Privacy Pass

**协议描述：** 匿名凭证系统允许用户向 Verifier 证明自己拥有 Issuer 签发的某个属性（如"年龄 > 18"），而不暴露具体身份。工作流程如下：

1. **Issuance（签发）:** User 与 Issuer 运行 Fischlin 协议。User 将消息 m（包含属性声明和随机盲化因子 r）盲化为 com，Issuer 对 com 签名得到 σ_blind。User 去盲化得到凭证 σ。
2. **Presentation（出示）:** User 选择性地披露 m 中的部分属性（如仅披露"年龄 > 18"而隐藏姓名），对未披露部分生成 STARK 零知识证明 π，证明存在有效的 Issuer 签名。
3. **Verification（验证）:** Verifier 检查 π 的有效性和披露属性。Verifier 无法将此次出示与签发会话关联（unlinkability）。

**实际部署场景：**
- **Privacy Pass (IETF RFC 9578):** 当前广泛部署于 CDN 和 Web 服务的匿名认证协议。目前基于 RSA 盲签名与 VOPRF（verifiable oblivious pseudorandom function）。迁移到后量子版本需要 PQ 盲签名或 PQ VOPRF。
- **Apple iCloud Private Relay:** 使用 RSA 盲签名实现匿名令牌。后量子迁移的必要候选。
- **W3C Verifiable Credentials:** 数字身份标准的底层可以通过盲签名实现 issuer unlinkability。

**本项目的适配性：** 在上述场景中，证明时间（~37s）发生在 User 端（Presentation 阶段），而非每次交互。对于凭证周期为小时/天级别的应用（如每日一次的年龄验证），37 秒的证明生成是可以接受的。Verifier 端仅需 ~4 ms 验证——这是每次交互的成本。

### 1.4 使用场景二：电子投票

**协议描述：** 盲签名在电子投票中用于实现 **投票者的不可链接性**：

1. Voter 在本地生成选票 b，用随机数 r 盲化得到 blinded ballot b'。
2. 选举机构（Issuer）验证 Voter 的身份（确保有投票权且未重复投票），对 b' 签名。
3. Voter 去盲化得到签名后的选票 (b, σ)。
4. Voter 通过匿名信道（如 mix-net）提交 (b, σ) 到计票中心。
5. 计票中心验证签名 σ 的有效性，计入选票 b，但无法将 (b, σ) 与步骤 1-2 中的任何 Voter 关联。

**后量子考虑：** 电子投票需要长期隐私——选票记录可能几十年后仍可被追溯。如果当前使用 RSA 盲签名，Shor 算法有能力在量子计算机可用时逆向链接所有历史投票。因此电子投票是后量子盲签名**需求最紧迫**的场景之一。

### 1.5 使用场景三：区块链隐私交易

**协议描述：** 在区块链中，盲签名可以实现交易的 **发送方匿名** 和 **不可链接性**：

1. User 通过盲签名向 Issuer（链上智能合约或链下机构）请求 UTXO 所有权凭证。
2. User 生成 STARK 证明 π，证明其持有有效凭证，而不暴露凭证本身。
3. 链上验证者检查 π 的有效性，记录交易但不记录凭证内容。
4. 不同交易之间无法通过凭证链接到同一 User。

**与现有方案的对比：**
- **Zcash (Sprout/Sapling/Orchard 协议):** 使用 Groth16 zk-SNARKs + Pedersen commitment。方案需要 Trusted Setup（Orchard 使用 Halo 2 递归证明消除 Setup）。但仍依赖离散对数假设（Jubjub/BLS12-381 曲线上的 Pedersen hash）。
- **Monero (RingCT):** 使用环签名 + Bulletproofs 实现发送方匿名和金额隐藏。同样依赖离散对数假设。
- **本项目方案:** 使用 STARK（无需 Trusted Setup）+ Poseidon2（Goldilocks 域原生）。是**完全透明的后量子隐私方案**。

**适配性分析：** 区块链的吞吐量需求（~100-10,000 TPS）与传统 STARK proving（~37s）构成矛盾。解决方案包括：
- **Rollup 模式:** User 生成证明（37s，离线），将证明批量提交到 L1 或 L2
- **Proof aggregation:** 聚合多个用户的 STARK proof，降低链上验证成本
- **Asynchronous credential model:** 凭证一次签发（天/周级），后续每笔交易仅出示证明（快速验证 4ms）

### 1.6 半盲签名（Partially Blind Signature）

半盲签名 [Abe and Fujisaki, CRYPTO 1996] 是盲签名的扩展：Signer 和 User 在签名时可以**共享一部分双方都同意的公开信息**（称为 info 或 tag）。这部分信息在签发时对 Signer 可见，但在出示时仍然被绑定到凭证中。

**使用场景：**
- **数字现金:** 银行在签发电子货币时，嵌入面额（如"100 CNY"）作为公开 info。User 不能修改面额，但银行无法追踪这张"100 CNY"被谁在何时花掉。
- **有时间限制的凭证:** 嵌入有效期信息（如"2026-12-31 前有效"），防止凭证无限期重放。
- **部分属性披露的匿名凭证:** Signer 将 User 的部分属性（如"持卡人国籍=CN"）作为公开 info 嵌入签名，Verifier 可以验证这些属性但不知晓其他隐藏属性。

**格基半盲签名：**
- del Pino 和 Katsumata [CRYPTO 2022] 的框架同时支持半盲签名
- 部分揭示机制：通过承诺方案的 Selective Opening 实现

**本项目的半盲签名支持：** 当前实现中，public_ctx 字段（在 proof header 中绑定为 ctx_hash）可以作为半盲签名的公开 info 载体。如果 Signer 在 Issue 阶段与 User 协商一个 public_ctx（例如面额值），该值被嵌入 σ_C 并在 STARK 证明中被绑定，Verifier 验证时就能确认 public_ctx 未被篡改。这意味着**当前架构基本支持半盲签名，无需重大修改**。

### 1.7 与格基方案的详细对比

| 维度 | 格基 (Beullens CCS'23) | 哈希基 (本项目) | 备注 |
|------|----------------------|----------------|------|
| 签发时间 | ~5 ms | ~38 ms (含 Poseidon2 SPHINCS+ 签名) | 签发仅需 SPHINCS+ sign，不需要 STARK |
| Show 证明生成 | ~30 ms (MPC-in-the-Head) | ~37 s (STARK) | STARK 一次性的成本 |
| Show 验证 | ~5 ms | ~4 ms | 相当 |
| 签名/凭证尺寸 | ~20 KB + NIZK proof | ~7 KB (SPHINCS+) + ~85 KB (STARK) | STARK proof 较大但可聚合 |
| 可信设置 | 无 | 无 | 两者都是透明的 |
| 后量子假设 | Ring/Module SIS/LWE | 哈希函数 (ROM) | 哈希基更保守 |
| 安全性归约 | SM-OMUF ← MSIS/MLWE | OMUF ← EUF-CMA ← THF ← Poseidon2 | 哈希基的归约链更模块化 |
| 标准化成熟度 | Dilithium (FIPS 204) | SPHINCS+ (FIPS 205) | 两者都是 NIST 标准 |

## 2. 区块链场景深度分析

### 2.1 为什么区块链需要盲签名

区块链本质上是**公开透明**的账本。Bitcoin 和 Ethereum 中，每笔交易的发送方、接收方和金额对全网可见。这种透明性在许多场景下是不可接受的：
- 企业供应链金融（商业机密暴露）
- 个人薪资支付（隐私侵犯）
- 合规 DeFi（KYC/AML 要求与隐私矛盾）

盲签名 + ZK proof 提供了一种平衡：**链上仅验证证明的正确性，不获取明文数据**。这正是 Zcash（通过 SNARK）、Monero（通过环签名+Bulletproofs）和 Tornado Cash（通过 Merkle tree + SNARK）的核心理念。

### 2.2 本方案的区块链适配架构

```
┌────────────────────────────────────────────────┐
│                   Off-chain                      │
│                                                  │
│  User ◄──── Fischlin Issue ────► Issuer         │
│    │                                                     │
│    ▼                                                     │
│  Generate STARK Proof (37s, 一次性的)         │
│    │                                                     │
└────┼─────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│              On-chain (L1/L2)                   │
│                                                      │
│  Verifier Smart Contract:                       │
│    - Check π (4ms)                               │
│    - Check public_ctx binding               │
│    - Update state (e.g., transfer token)   │
│                                                      │
└─────────────────────────────────────┘
```

**关键设计决策：**
1. **一次签发，多次出示:** STARK proof 仅需生成一次（37s 离线），后续每次交易仅需出示和验证（4ms）
2. **Proof 聚合:** 多个 User 的 STARK proofs 可以通过递归 STARK 聚合为一个 proof ，进一步降低链上成本
3. **绑定公开上下文:** ctx_hash 机制确保 proof 绑定到特定的链上状态，防止跨链重放

### 2.3 参考区块链会议论文模式

Buser et al. [ACM Computing Surveys, 2022] 的综述 "A Survey on Exotic Signatures for Post-quantum Blockchain" 系统化梳理了区块链中后量子盲签名/环签名/适配器签名的研究现状，明确指出盲签名是区块链隐私的**部署就绪度最高**的隐私原语。该文发表在一区综述期刊。

Argo et al. [CCS 2024] 的 "Practical Post-Quantum Signatures for Privacy" 是**与我们贡献模式最接近的论文**——将格基盲签名/群签名/匿名凭证从纸面设计变成实际可运行的代码实现，并给出了完整的基准测试。该文发表在 CCS（CCF A），说明**工程实现+基准测试**的工作可以在顶会发表，只要它是该方向的**第一个完整的系统实现**。

## 3. 总结

本项目的应用定位为：
1. **最保守后量子假设的隐私保护** — 仅依赖哈希函数，无代数结构假设
2. **最长远的隐私保证** — ROM 下的哈希基安全不受结构化攻击进展的影响
3. **区块链互补场景** — 与格基方案互补：格基方案适合高频交易（证明快、尺寸小），哈希基方案适合长周期高安全凭证（签发一次、使用多日）

主要竞争不是替代格基方案，而是在**安全假设多样性和稳健性**方面提供另一种选择——这是密码工程中的经典"不把鸡蛋放在一个篮子里"原则。

---

## 参考文献

- [Chaum 1983] D. Chaum, "Blind Signatures for Untraceable Payments," CRYPTO 1982. [DOI: 10.1007/978-1-4757-0602-4_18](https://doi.org/10.1007/978-1-4757-0602-4_18)
- [Abe-Fujisaki 1996] M. Abe and E. Fujisaki, "How to Date Blind Signatures," CRYPTO 1996. [DOI: 10.1007/3-540-68697-5_3](https://doi.org/10.1007/3-540-68697-5_3)
- [Fischlin 2006] M. Fischlin, "Round-Optimal Composable Blind Signatures in the Common Reference String Model," CRYPTO 2006. [DOI: 10.1007/11818175_4](https://doi.org/10.1007/11818175_4)
- [NIST IR 8413] NIST, "Status Report on the Third Round of the NIST PQC Standardization Process," 2022. [PDF](https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf)
- [del Pino-Katsumata 2022] R. del Pino and S. Katsumata, "A New Framework for More Efficient Round-Optimal Lattice-Based (Partially) Blind Signature via Trapdoor Sampling," CRYPTO 2022. [DOI: 10.1007/978-3-031-15979-4_11](https://doi.org/10.1007/978-3-031-15979-4_11)
- [Beullens et al. 2023] W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler, "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal," CCS 2023. [DOI: 10.1145/3576915.3616613](https://doi.org/10.1145/3576915.3616613)
- [Argo et al. 2024] S. Argo, T. Güneysu, C. Jeudy, G. Land, A. Roux-Langlois, "Practical Post-Quantum Signatures for Privacy," CCS 2024. [DOI: 10.1145/3658644.3670297](https://doi.org/10.1145/3658644.3670297)
- [Kastner et al. 2024] J. Kastner, K. Nguyen, M. Reichle, "Pairing-Free Blind Signatures from Standard Assumptions in the ROM," CRYPTO 2024. [DOI: 10.1007/978-3-031-68376-3_7](https://doi.org/10.1007/978-3-031-68376-3_7)
- [Katsumata et al. 2023] S. Katsumata, Y.-F. Lai, J. T. LeGrow, L. Qin, "CSI-Otter: Isogeny-Based (Partially) Blind Signatures," CRYPTO 2023. [DOI: 10.1007/978-3-031-38548-3_24](https://doi.org/10.1007/978-3-031-38548-3_24)
- [Bouillaguet et al. 2026] C. Bouillaguet, T. Feneuil, J. Maire, M. Rivain, J. Sauvage, D. Vergnaud, "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. [DOI: 10.1109/SP63933.2026.00032](https://doi.org/10.1109/SP63933.2026.00032)
- [Buser et al. 2022] M. Buser et al., "A Survey on Exotic Signatures for Post-quantum Blockchain: Challenges and Research Directions," ACM Computing Surveys, 2022. [DOI: 10.1145/3572771](https://doi.org/10.1145/3572771)
- [RFC 9578] Privacy Pass Working Group, "Privacy Pass Architecture," IETF RFC 9578, 2024. [Link](https://www.rfc-editor.org/rfc/rfc9578)
- [SPHINCS+ NIST] NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard," 2024. [PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
- [Grassi et al. 2023] L. Grassi, D. Khovratovich, M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon Hash Function," AFRICACRYPT 2023. [DOI: 10.1007/978-3-031-37679-5_8](https://doi.org/10.1007/978-3-031-37679-5_8)
