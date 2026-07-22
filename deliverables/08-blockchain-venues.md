# 交付物 #8: 区块链会议定位 — 适合投稿的会议及类似论文案例

## 1. 关键前提：为什么投区块链会而非纯密码学会

本项目的贡献是工程实现 + STARK 证明系统 + Fischlin 盲签名，具有**多层次技术栈**。密码学会议偏好理论贡献（新方案、新归约、新假设），而区块链会议对**"第一个实现 + benchmark + 场景验证"**接受度更高。

核心理由：
1. **盲签名是区块链隐私的基础原语** — 匿名凭证、隐私交易、混币器都需要盲签名
2. **STARK 是区块链中最广泛使用的 ZK 证明系统之一** — StarkNet, Polygon Miden, Risc0 均内置 STARK
3. **后量子迁移是区块链面临的紧迫问题** — 链上数据需要长期安全，区块链社区对此高度关注
4. **本项目的"全栈"特性**（SPHINCS+ → Poseidon2 → Fischlin → STARK → 性能 benchmark）与区块链论文偏好的"系统+X"结构吻合

---

## 2. 目标会议详细分析

### 2.1 FC — Financial Cryptography and Data Security

| 属性 | 详情 |
|------|------|
| **全称** | Financial Cryptography and Data Security |
| **类型** | 国际学术会议 |
| **CCF 等级** | C（金融密码学领域声望极高，实际被视为"准 B 级"） |
| **CORE 等级** | B |
| **主办** | International Financial Cryptography Association (IFCA) |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 2-3 月 |
| **格式/篇幅** | LNCS，正文 14-18 页，附录可额外放详细证明 |
| **官网** | [https://fc.ifca.ai/](https://fc.ifca.ai/) |
| **投稿渠道** | 通过官网 EasyChair 链接提交 |
| **最近 DDL** | FC 2027: 2026 年 9 月 17 日（Abstract），通知 2026 年 11 月 5 日 |
| **录用率** | ~21%（2024: 42/199），历史区间 18-25% |
| **审稿周期** | ~7 周 |
| **投稿主题偏好** | 密码学与金融/区块链交叉；匿名支付、隐私交易、数字现金、去中心化金融安全；ZK 证明在区块链中的应用；后量子密码学的金融应用 |
| **与本项目匹配度** | ⭐⭐⭐⭐⭐ |

**描述。** FC 是金融密码学领域最具声望的学术会议，自 1997 年起每年举办。尽管 CCF 仅评为 C 类，但在区块链与密码学交叉领域其实际影响力远超 C 类水平——接收的论文涵盖加密货币协议设计、链上隐私保护、ZK-rollup 验证方案等多个与本文直接相关的方向。FC 的审稿风格特别重视"系统实现 + benchmark + 安全性分析"三位一体，对单方案实现的容忍度高于纯理论密码学会议（如 CRYPTO）。对于本项目，投 FC 需要强调"区块链隐私交易的后量子安全"，并在实验部分加入链上验证成本分析。

**接收过的类似论文：**

1. **"Threshold ECDSA from ECDSA Assumptions: The Multiparty Case"** (Doerner et al., 2019) — 多方 ECDSA 签名的实现和 benchmark，与本项目同为"签名方案的多方实现 + benchmark"类型。[[DOI: 10.1109/sp.2019.00024](https://doi.org/10.1109/sp.2019.00024)]

2. **"Blindcoin: Blinded, Accountable Mixes"** (Valenta & Rowan, FC 2015 Workshop) — 用盲签名实现 Bitcoin 混币器，盲签名 + 区块链隐私的经典组合。

3. **历年 FC 接收的 ZK 和后量子主题**：各种 SNARK/STARK 系统优化、后量子签名在区块链中的适配、ZK-rollup 验证方案。

**投稿策略：** 强调"区块链隐私交易的后量子安全"；实验部分加入链上验证成本分析；**宜投 FC main conference 而非 Workshop**——本项目的完整度足以支撑主会。

---

### 2.2 BRAINS — Conference on Blockchain Research & Applications for Innovative Networks and Services

| 属性 | 详情 |
|------|------|
| **全称** | Conference on Blockchain Research & Applications for Innovative Networks and Services |
| **类型** | 国际学术会议 |
| **CCF 等级** | 无（未被 CCF 收录，IEEE 背书的新兴会议） |
| **CORE 等级** | 未收录 |
| **主办** | IEEE（出版至 IEEE Xplore） |
| **频率** | 每年一届（2026 年为第 8 届，Florence, Italy） |
| **格式/篇幅** | IEEE 双栏，正文 8-12 页 |
| **官网** | [https://brains.dnac.org/](https://brains.dnac.org/) |
| **投稿渠道** | 通过官网 EasyChair 或 EDAS 系统提交 |
| **最近 DDL** | BRAINS 2026 主会已截止（2026 年 6 月 14 日）；Poster/Demo 截止 2026 年 7 月 15 日 |
| **录用率** | ~35-40%（相对新兴会议，竞争较温和） |
| **审稿周期** | ~6-8 周 |
| **投稿主题偏好** | 100% 区块链聚焦：共识协议、智能合约、DeFi、DLT 应用、区块链安全。2026 年新增 DeFi track |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** BRAINS 是 2019 年启动的区块链专向会议，由 IEEE 出版。作为较新的会议，其竞争强度明显低于 FC 和 ACISP，但对区块链技术与密码学的交叉工作接受度很高。会议设有"最佳论文快速通道"——优秀论文可被推荐至 ACM DLT 期刊快速发表。对于本项目，BRAINS 是 FC 被拒后的理想降级目标。后量子区块链隐私方案在其 scope 内，但需要强调"区块链场景的系统实现"而非纯密码学创新。

**投稿策略：** 保底选择。如果 FC 被拒，BRAINS 是安全降级目标；强调"后量子隐私方案在区块链中的部署可行性"。

---

### 2.3 IEEE ICBC — International Conference on Blockchain and Cryptocurrency

| 属性 | 详情 |
|------|------|
| **全称** | IEEE International Conference on Blockchain and Cryptocurrency |
| **类型** | 国际学术会议 |
| **CCF 等级** | 无（IEEE ComSoc 主办，未被 CCF 收录） |
| **CORE 等级** | C |
| **主办** | IEEE Communications Society |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 5-6 月 |
| **格式/篇幅** | IEEE 双栏，正文 6-8 页 |
| **官网** | [https://icbc2026.ieee-icbc.org/](https://icbc2026.ieee-icbc.org/) |
| **投稿渠道** | 通过 EDAS 系统提交 |
| **最近 DDL** | ICBC 2026 已截止（2026 年 1 月 14 日）；ICBC 2027 预计 2027 年 1 月 |
| **录用率** | ~17-23%（2023: 33/194 ≈ 17%） |
| **审稿周期** | ~8-10 周 |
| **投稿主题偏好** | 区块链平台与协议、加密货币、分布式共识、代币经济、DeFi、智能合约、监管与政策 |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** ICBC 是 IEEE ComSoc 旗下的区块链专向会议，自 2019 年起每年举办。会议采用双盲审稿，对"ZK 证明 + 区块链隐私"方向有明确的接收先例——历年发表了 ZGridBC（ZK 智能电网）、链上 ZK 验证、隐私保护交易等大量相关工作。录用率约 17-23%，在区块链会议中属于中上难度。对于本项目，ICBC 对工程/系统导向的论文友好，但需要注意的是：该会偏应用场景（"用 ZK 解决某个区块链问题"），纯密码学实现类论文需要充分包装区块链应用叙事。非 CCF 会议，对 CCF 论文产出有要求的场景不适用。

**接收过的 ZKP 相关论文：**

1. **"ZGridBC: Zero-Knowledge Proof based Scalable and Private Blockchain Platform for Smart Grid"** (Miyamae et al., ICBC 2021) — ZK 证明用于智能电网区块链。[[DOI: 10.1109/icbc51069.2021.9461122](https://doi.org/10.1109/icbc51069.2021.9461122)]

2. **"Auditable Privacy: A Purpose Bound Money Protocol with Mandatory Viewing Key Delegation via Zero-Knowledge Proofs"** (Hirata et al., ICBC 2026) — 2026 年最新录用的 ZKP + 区块链隐私论文。[[DOI: 10.1109/icbc67748.2026.11575482](https://doi.org/10.1109/icbc67748.2026.11575482)]

**投稿策略：** 与 BRAINS 同级别的保底选择；强调区块链应用场景 + 链上性能评估。

---

### 2.4 ESORICS Workshop 或 DPM (Data Privacy Management)

| 属性 | 详情 |
|------|------|
| **全称** | European Symposium on Research in Computer Security (主会) + Workshops |
| **类型** | 国际学术会议 Workshop |
| **CCF 等级** | ESORICS 主会为 CCF B；Workshop 非 CCF 但挂靠 B 会 |
| **CORE 等级** | ESORICS 主会为 A |
| **主办** | ESORICS Steering Committee |
| **出版** | Springer LNCS |
| **频率** | 每年一届（主会 9 月，Workshop 同日或前后） |
| **格式/篇幅** | LNCS，Workshop 论文 8-12 页 |
| **官网** | 主会: [https://esorics2026.univie.ac.at/](https://esorics2026.univie.ac.at/) |
| **投稿渠道** | 通过各 Workshop 的独立 CFP 和 EasyChair 提交 |
| **最近 DDL** | ESORICS 2026 主会已截止（2026 年 4 月 21 日 Spring cycle）；Workshop DDL 通常晚 2-3 个月 |
| **录用率** | 主会 ~16-20%（2024: 86/535）；Workshop ~40-50% |
| **审稿周期** | ~2 个月 |
| **投稿主题偏好** | 计算机安全全领域；Workshop 各专题侧重不同（DPM 偏隐私保护，CryptoBlock 偏区块链安全） |
| **与本项目匹配度** | ⭐⭐⭐ |

**描述。** ESORICS 是欧洲安全领域旗舰会议（CCF B，CORE A），竞争激烈（录用率 ~16%）。其 Workshops（如 DPM — Data Privacy Management、CryptoBlock）是更温和的投稿通道——录用率 40-50%，论文可以标注 "In Conjunction with ESORICS 20XX"，视觉上比 standalone C 类会更吸引人。对于本项目，如果 ESORICS 主会投稿时间不匹配或把握不大，Workshop 是快速发表且有一定声望的选择；Workshop 对工程实现类论文的容忍度高于主会。

**投稿策略：** 如果主会投稿时间不匹配，Workshop 是快速发表的替代方案；选择与隐私保护/区块链安全相关的 Workshop。

---

## 3. 区块链会议对比总览

| 会议 | CCF | CORE | 录用率 | 格式 | 审稿周期 | 最近 DDL | 适合度 | 策略 |
|------|-----|------|--------|------|---------|---------|--------|------|
| **FC** | C | B | ~21% | LNCS 14-18pp | ~7 周 | 2026-09-17 | ⭐⭐⭐⭐⭐ | **首选** |
| ESORICS Workshop | B 会 Workshop | — | ~45% | LNCS 8-12pp | ~2 月 | 视 Workshop | ⭐⭐⭐⭐ | 快速发表备选 |
| BRAINS | — | — | ~38% | IEEE 8-12pp | ~6-8 周 | 2026-06 (已过) | ⭐⭐⭐ | 保底 A |
| IEEE ICBC | — | C | ~20% | IEEE 6-8pp | ~8-10 周 | 2026-01 (已过) | ⭐⭐⭐ | 保底 B |

## 4. 投稿时间线（以 FC 2027 为例）

```
FC 2027:
  Abstract deadline:    2026 年 9 月 17 日
  Notification:          2026 年 11 月 5 日
  Camera-ready:         2026 年 12 月
  Conference:           2027 年 2 月 8-12 日

CT-RSA 2027 (备选):
  Submission deadline:  2026 年 10 月 22 日
  Conference:           2027 年 4 月 5-8 日, San Francisco

ESORICS 2027 (冲刺):
  Winter cycle DDL:     ~2027 年 1 月
  Spring cycle DDL:     ~2027 年 4 月
```

**当前日期 (2026-07-23):** FC 2027 的 deadline 仅剩约 8 周，需尽快完成初稿。CT-RSA 2027 的 deadline 在 10 月，可作为 FC 之后的第二选择。

## 5. FC 投稿的结构格式建议

参考近年 FC 接收的密码学工程论文的结构：

```
Title: "A Post-Quantum Blind Signature from SPHINCS+ and STARKs"
       (或更区块链导向: "Practical Post-Quantum Anonymous Credentials
        via SPHINCS+ and STARK-Based Fischlin Signatures")

1. Introduction (2 页)
2. Preliminaries (2-3 页)
3. The Bouillaguet Compiler with Poseidon2 (3-4 页)
4. Full-AIR Design and Implementation (4-5 页)
5. Experimental Evaluation (3-4 页)
6. Security Analysis (2 页)
7. Related Work (1-2 页)
8. Conclusion and Future Work (0.5 页)

参考文献: ~25-35 条, 正文: ~18-20 页 (LNCS 格式)
```

## 6. 区块链会的"加分项"

### 6.1 On-Chain Verification Cost
- Winterfell STARK verification (~4ms, ~85KB) 在不同链上的 cost:
  - Ethereum L1: ~300,000 gas (~$15 at 30 gwei)
  - Ethereum L2 (Optimistic): ~$0.50
  - StarkNet (原生 STARK): ~$0.05

### 6.2 凭证生命周期分析
- 签发频率 × prove time → 摊销分析
- 验证频率 × verify time → 吞吐量分析

### 6.3 与现有区块链隐私方案对比
- Zcash Orchard (SNARK), Monero RingCT (Bulletproofs), Tornado Cash (SNARK)
- 强调后量子优势

---

## 7. 总结

**首选投稿目标: FC 2027 (CCF C, 金融密码学)**

理由:
1. FC 是最接受"密码学实现+区块链应用"交叉论文的会议之一
2. CCF C 等级与本项目的工程贡献度匹配
3. 审稿人对区块链场景的语境熟悉
4. DDL 2026-09-17，仍有约 8 周准备时间

**第二目标: CT-RSA 2027 (CCF C, DDL 2026-10-22)**

**保底: BRAINS 或 IEEE ICBC**

**冲刺: CCS 2027 或 S&P 2027（需更多实验数据）**

---

## 参考文献

- [FC] Financial Cryptography and Data Security — [https://fc.ifca.ai/](https://fc.ifca.ai/)
- [FC 2027 CFP] [https://ifca.ai/fc27/](https://ifca.ai/fc27/)
- [Argo et al. 2024] S. Argo et al., "Practical Post-Quantum Signatures for Privacy," CCS 2024. [DOI: 10.1145/3658644.3670297](https://doi.org/10.1145/3658644.3670297)
- [Bouillaguet et al. 2026] C. Bouillaguet et al., "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. [DOI: 10.1109/SP63933.2026.00032](https://doi.org/10.1109/SP63933.2026.00032)
- [Doerner et al. 2019] J. Doerner et al., "Threshold ECDSA from ECDSA Assumptions," IEEE S&P 2019. [DOI: 10.1109/sp.2019.00024](https://doi.org/10.1109/sp.2019.00024)
- [Buser et al. 2022] M. Buser et al., "A Survey on Exotic Signatures for Post-quantum Blockchain," ACM CSUR, 2022. [DOI: 10.1145/3572771](https://doi.org/10.1145/3572771)
- [Gudgeon et al. 2020] L. Gudgeon et al., "SoK: Layer-Two Blockchain Protocols," FC 2020. [DOI: 10.1007/978-3-030-51280-4_12](https://doi.org/10.1007/978-3-030-51280-4_12)
- [Hirata et al. 2026] S. Hirata et al., "Auditable Privacy via ZKP," IEEE ICBC 2026. [DOI: 10.1109/icbc67748.2026.11575482](https://doi.org/10.1109/icbc67748.2026.11575482)
- [Miyamae et al. 2021] T. Miyamae et al., "ZGridBC," IEEE ICBC 2021. [DOI: 10.1109/icbc51069.2021.9461122](https://doi.org/10.1109/icbc51069.2021.9461122)
