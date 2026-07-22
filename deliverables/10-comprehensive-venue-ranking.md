# 交付物 #10: 投稿目标综合分析 — 20 个期刊/会议详细评估与推荐排序

> 整合安全、密码学、区块链、国内四个方向，每个 venue 包含 DDL、偏好、相似论文实例、匹配度。

---

## 投稿目标总览

| # | 名称 | 类型 | CCF | 方向 | 推荐档位 |
|---|------|------|-----|------|---------|
| 1 | FC | 会议 | C | 金融密码学/区块链 | **A 首选** |
| 2 | Inscrypt | 会议 | C | 密码学(国内) | **A 首选** |
| 3 | CANS | 会议 | C | 应用密码学 | **A 首选** |
| 4 | ACISP | 会议 | C | 信息安全(亚太) | **B 高匹配** |
| 5 | CT-RSA | 会议 | C | 应用密码学 | **B 高匹配** |
| 6 | ISPEC | 会议 | C | 安全实践 | **B 高匹配** |
| 7 | PST | 会议 | C | 隐私安全信任 | **B 高匹配** |
| 8 | 《密码学报》 | 期刊 | B(国内) | 密码学 | **B 高匹配** |
| 9 | ESORICS | 会议 | B | 安全(欧洲) | **C 冲刺** |
| 10 | ACNS | 会议 | B | 应用密码学/网络安全 | **C 冲刺** |
| 11 | IEEE ICBC | 会议 | - | 区块链 | **C 冲刺** |
| 12 | Blockchain (IEEE) | 会议 | - | 区块链 | **C 冲刺** |
| 13 | DSN | 会议 | B | 系统安全 | **D 低匹配** |
| 14 | SRDS | 会议 | B | 分布式系统 | **D 低匹配** |
| 15 | ChinaCrypt | 会议 | - | 密码学(国内) | **D 低匹配** |
| 16 | BRAINS | 会议 | - | 区块链 | **D 低匹配** |
| 17 | 《软件学报》 | 期刊 | A(国内) | 计算机科学 | **D 低匹配** |
| 18 | 《信息安全学报》 | 期刊 | -(国内) | 信息安全 | **D 低匹配** |
| 19 | IEEE Access | 期刊 | - | 综合 | **E 保底** |
| 20 | IACR ePrint | 预印本 | - | 密码学 | **E 保底** |

---

## 详细评估

### #1 — Financial Cryptography and Data Security (FC)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C（实际声望 ≈ B 级，金融密码学领域最高级别会议） |
| **主办** | International Financial Cryptography Association (IFCA) |
| **频率/届数** | 每年一届，第 31 届 (FC 2027)，通常在 2-3 月 |
| **格式** | Springer LNCS, 12-20 页正文 + 参考文献 + 附录 |
| **投稿 DDL** | 预估 FC 2027: Abstract 2026年9月中旬, Full paper 2026年9月下旬 |
| **录用率** | ~25-27% |
| **审稿周期** | ~3-4 个月（通知一般在 12 月） |
| **出版** | LNCS, EI/CPCI 收录 |
| **投稿主题偏好** | 密码学与金融/区块链交叉；匿名支付、隐私交易、数字现金、去中心化金融安全；ZK证明在区块链中的应用；后量子密码学的金融应用 |
| **结构偏好** | Introduction (2pp) → Preliminaries (2-3pp) → Construction/Design (4-5pp) → Security Analysis (2pp) → Implementation & Evaluation (3-4pp) → Related Work (1-2pp) → Conclusion |
| **篇幅** | 正文 14-18 页 (LNCS)，不含附录。附录可额外放详细证明 |
| **审稿风格** | 重视系统实现+benchmark+安全性分析三位一体；偏好有区块链应用场景的密码学工作；单方案实现可接受但需充分的性能分析和对比 |

**曾接收的相似论文:**

1. **"Atomic and Fair Data Exchange via Blockchain"** (Tas et al., FC/CCS 2024)
   - 发表: CCS 2024 (同作者组在 FC 有相关工作)
   - 主要贡献: 基于区块链的原子化公平数据交换协议 + VECK(verifiable encryption under committed key)新密码学原语
   - 实验设计: Ethereum 上的 open-source 实现 + gas cost 分析
   - 链接: DOI: 10.1145/3658644.3690248

2. **"Blindcoin: Blinded, Accountable Mixes"** (Valenta & Rowan, FC 2015 Workshop)
   - 主要贡献: 盲签名实现 Bitcoin 混币器
   - 与本项目相似点: 盲签名 + 区块链隐私
   - 关键词: blind signature, Bitcoin mixer, Zerocash

3. **历年 FC 接收的 ZK 和后量子主题:**
   - SoK: Layer-Two Blockchain Protocols
   - 各种 SNARK/STARK 在支付和隐私保护中的应用
   - 后量子密码学对区块链的影响分析

**与本项目匹配度: ⭐⭐⭐⭐⭐**
- FC 是接受"密码学实现 + 区块链应用场景"交叉工作最多的 CCF C 会之一
- 本项目可以从"区块链匿名凭证的后量子安全"角度切入
- **关键要求:** 必须在实验部分加入链上验证成本分析或区块链场景 benchmark

---

### #2 — Inscrypt (International Conference on Information Security and Cryptology)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议（在中国举办） |
| **CCF 等级** | C |
| **主办** | 中国密码学会 (CACR) 承办 |
| **频率/届数** | 每年一届，通常在 11-12 月 |
| **格式** | Springer LNCS, 12-20 页 |
| **投稿 DDL** | 预估 Inscrypt 2027: 2027年6月-7月 |
| **录用率** | ~30-35% |
| **审稿周期** | ~3-4 个月 |
| **出版** | LNCS, EI/CPCI 收录 |
| **投稿主题偏好** | 密码学理论与应用；后量子密码学；系统安全与实现；区块链安全与隐私；零知识证明；隐私保护技术 |
| **结构偏好** | 标准 LNCS 会议论文结构 |
| **篇幅** | 12-18 页正文 |

**曾接收的论文:**
- 历届 Inscrypt 接收了广泛的密码学实现、后量子方案、区块链应用论文
- 审稿风格对中国作者友好（学会内部承办）
- 接收范围广：从密码分析到系统工程实现均在 scope 内

**与本项目匹配度: ⭐⭐⭐⭐⭐**
- **最大优势:** CCF C + 国内举办(省差旅) + LNCS 索引 + 对工程实现容忍度高 + 审稿速度较快
- 可以直接使用英文版稿件，无需翻译
- 竞争的"硬度"低于 FC 和 ACISP，适合作为稳妥的 CCF C 投稿

---

### #3 — CANS (Cryptology and Network Security)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **频率/届数** | 每年一届 |
| **格式** | Springer LNCS, 12-20 页 |
| **投稿 DDL** | 预估 CANS 2027: 2027年5月-6月 |
| **录用率** | ~28-33% |
| **审稿周期** | ~3 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 密码学协议设计与分析；网络安全；后量子密码学；应用密码学实现；区块链安全 |
| **结构偏好** | 标准 LNCS 会议论文 |
| **篇幅** | 12-16 页正文 |

**与本项目匹配度: ⭐⭐⭐⭐⭐**
- CANS 的 scope 明确覆盖"cryptology AND network security"——本项目恰好是密码学方案在分布式系统（区块链）中的应用
- 竞争激烈程度低于 FC，对实现类工作友好
- 建议以"CANS 2027"为备选投稿目标

---

### #4 — ACISP (Australasian Conference on Information Security and Privacy)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **频率/届数** | 每年一届，通常在 7 月 |
| **格式** | Springer LNCS, 12-18 页 |
| **投稿 DDL** | 预估 ACISP 2027: 2027年2月-3月 |
| **录用率** | ~25-30% |
| **审稿周期** | ~2-3 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 信息安全与隐私；密码学协议；后量子密码学；应用密码学；区块链安全 |
| **篇幅** | 12-16 页正文 |

**曾接收的论文:**
- ACISP 历史接收了相当数量的后量子密码学实现和参数选择论文
- 作为一个地区性会议 (Australasian)，其竞争强度略低于 FC/ESORICS
- 对亚洲作者投稿友好

**与本项目匹配度: ⭐⭐⭐⭐**
- 后量子密码是 ACISP 的常设 topic
- 匹配度低于 FC（没有区块链 focus），但投稿竞争更温和

---

### #5 — CT-RSA (Cryptographers' Track at RSA Conference)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **频率/届数** | 每年一届，通常在 2 月 (与 RSA Conference 同期) |
| **格式** | Springer LNCS, 12-20 页 |
| **投稿 DDL** | 预估 CT-RSA 2027: 2026年8月-9月 |
| **录用率** | ~22-28% |
| **审稿周期** | ~3 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 密码学在实践中的应用；新的密码学构造和协议；密码学实现和性能评估；后量子密码学 |
| **结构偏好** | 偏好有实践验证（implementation+benchmark）的方案 |
| **篇幅** | 14-18 页正文 |

**与本项目匹配度: ⭐⭐⭐⭐**
- CT-RSA 的核心审美是"密码学在真实世界中的应用"——本项目的"工程实现 + benchmark"与之高度吻合
- CT-RSA 不是理论密码学会议，审稿人不会要求新的安全性定理
- DDL 紧迫（可能在 2026 年 8-9 月）——如果赶不上 FC 2027，可能也赶不上 CT-RSA 2027

---

### #6 — ISPEC (Information Security Practice and Experience)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **频率/届数** | 每年一届 |
| **格式** | Springer LNCS, 12-18 页 |
| **投稿 DDL** | 预估 ISPEC 2027: 2027年5月-6月 |
| **录用率** | ~30-35% |
| **审稿周期** | ~2-3 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 安全实践与经验；密码学实现和部署；安全评估；应用密码学 |
| **篇幅** | 10-14 页正文 |

**与本项目匹配度: ⭐⭐⭐⭐**
- ISPEC 是 CCF C 会议中**最明确的"工程实践"导向会议**——会议名就叫 "Practice and Experience"
- 对"第一个实现"类型的贡献接受度高于纯理论会议
- 审稿周期快（2-3个月），适合时间敏感投稿

---

### #7 — PST (International Conference on Privacy, Security and Trust)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **频率/届数** | 每年一届，通常在 8 月 |
| **格式** | IEEE CPS, 8-12 页 |
| **投稿 DDL** | 预估 PST 2027: 2027年4月-5月 |
| **录用率** | ~32-38% |
| **审稿周期** | ~2-3 个月 |
| **出版** | IEEE Xplore, EI/CPCI |
| **投稿主题偏好** | 隐私保护技术；安全协议；信任管理；匿名凭证；区块链隐私 |
| **篇幅** | 8-10 页正文 |

**与本项目匹配度: ⭐⭐⭐⭐**
- PST 对 "Privacy" 方向的论文天然友好——盲签名是核心的隐私原语
- IEEE 格式比 LNCS 更紧凑（8-10页），对实验密度要求较低
- 录用率较高，是稳妥的 CCF C 选择

---

### #8 — 《密码学报》(Journal of Cryptologic Research)

| 属性 | 详情 |
|------|------|
| **类型** | 中文学术期刊 |
| **CCF 等级** | B（中文密码学最高级别期刊） |
| **主办** | 中国密码学会 |
| **频率** | 双月刊 |
| **格式** | 中文，~15-20 页 |
| **投稿 DDL** | 滚动接受 (rolling submission) |
| **审稿周期** | 6-12 个月 |
| **投稿主题偏好** | 密码学理论与应用；后量子密码；密码协议；国密算法 |
| **篇幅** | 15-18 页中文正文 |

**曾接收的相似论文 (关键证据):**

1. **孙思维等, "SPHINCS+-SM3: 基于SM3的无状态数字签名算法"** (2023, Vol.10, No.6, pp.1266-1278)
   - 主要贡献: 首次用 SM3 实例化 SPHINCS+ THF，给出2组满足NIST安全类别1的参数
   - 实验: 参数搜索 + 与标准 SPHINCS+ 参数签名大小对比
   - **启示:** 该文的贡献类型（哈希替换+参数分析）工程量低于本项目，已经发表。本项目复杂度高于该文，投《密码学报》极大可能被接收

**与本项目匹配度: ⭐⭐⭐⭐**
- 中文期刊，对中文母语者无语言障碍
- CCF B 等级 > CCF C 会议，学位申请权重更高
- 有直接的 SPHINCS+-SM3 先例
- 审稿周期长（6-12月），时间敏感者需权衡

---

### #9 — ESORICS (European Symposium on Research in Computer Security)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | B |
| **频率/届数** | 每年一届，通常在 9 月 |
| **格式** | Springer LNCS, 14-22 页 |
| **投稿 DDL** | 预估 ESORICS 2027: 2027年3月-4月 |
| **录用率** | ~20-24% |
| **审稿周期** | ~3-4 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 计算机安全全领域；密码学协议安全分析；网络安全；隐私保护；系统安全 |
| **篇幅** | 16-20 页正文 |

**接收过的类似论文:**
- ESORICS 接收了部分密码学协议实现论文
- 但不如此列表中的"工程友好型"会议 (FC, ISPEC, PST) 多
- 更偏好有安全分析（形式化或实验）的工作

**与本项目匹配度: ⭐⭐⭐（冲刺级别）**
- CCF B 级别意味着竞争更激烈，审稿人更挑剔
- ESORICS 作为综合性安全会议，密码学实现类论文占比不高
- 如果论文写得足够好 + 实验做得足够全面，可以尝试冲刺

---

### #10 — ACNS (Applied Cryptography and Network Security)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | B |
| **频率/届数** | 每年一届，通常在 6 月 |
| **格式** | Springer LNCS, 14-20 页 |
| **投稿 DDL** | 预估 ACNS 2027: 2027年1月 |
| **录用率** | ~22-26% |
| **审稿周期** | ~3 个月 |
| **出版** | LNCS, EI/CPCI |
| **投稿主题偏好** | 应用密码学；网络安全；后量子密码学；密码学协议 |
| **篇幅** | 14-18 页正文 |

**与本项目匹配度: ⭐⭐⭐（冲刺级别）**
- ACNS 的"Applied Cryptography"定位与本项目的工程实现方向吻合
- CCF B 等级，竞争较高
- 近年来接收的后量子密码论文以格基和编码基方案为主，哈希基的较少——这既有风险（审稿人不熟悉）也有机会（新颖性更高）

---

### #11 — IEEE ICBC (International Conference on Blockchain and Cryptocurrency)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 (IEEE ComSoc 主办) |
| **频率/届数** | 每年一届，通常在 5 月 |
| **格式** | IEEE CPS, 8-10 页 |
| **投稿 DDL** | 预估 ICBC 2027: 2027年1月 |
| **录用率** | ~30-40% |
| **审稿周期** | ~2-3 个月 |
| **出版** | IEEE Xplore, EI/CPCI |
| **投稿主题偏好** | 区块链系统与协议；加密货币；智能合约安全；隐私保护技术；分布式账本应用 |
| **篇幅** | 6-8 页正文（较紧凑） |

**接收过的 ZKP 相关论文 (关键证据):**

1. **"ZGridBC: Zero-Knowledge Proof based Scalable and Private Blockchain Platform for Smart Grid"** (Miyamae et al., ICBC 2021)
   - DOI: 10.1109/icbc51069.2021.9461122
   - ZK 证明用于智能电网区块链

2. **"Location-aware Verification for Autonomous Truck Platooning Based on Blockchain and Zero-knowledge Proof"** (Li et al., ICBC 2021)
   - DOI: 10.1109/icbc51069.2021.9461116
   - ZK 证明 + 区块链用于车联网

3. **"Auditable Privacy: A Purpose Bound Money Protocol with Mandatory Viewing Key Delegation via Zero-Knowledge Proofs"** (Hirata et al., ICBC 2026)
   - DOI: 10.1109/icbc67748.2026.11575482
   - 2026 年最新录用的 ZKP + 区块链隐私论文

**与本项目匹配度: ⭐⭐⭐**
- ICBC 接收了大量 ZKP + 区块链的论文，但多数是应用导向的（"用 ZK 解决某个区块链问题"），而非密码学实现导向的（"实现一个新的密码学方案并 benchmarks"）
- 本项目可以适配 ICBC 的叙事模式，但需要增加区块链应用场景分析
- 非 CCF 会议，对 CCF 论文产出有要求的场景不适用

---

### #12 — IEEE Blockchain (International Conference on Blockchain)

| 属性 | 详情 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 |
| **频率/届数** | 每年一届 |
| **格式** | IEEE CPS, 8-10 页 |
| **投稿 DDL** | 预估 2027: 2027年3月-4月 |
| **录用率** | ~30-38% |
| **审稿周期** | ~2-3 个月 |
| **出版** | IEEE Xplore, EI/CPCI |

**接收过的 ZK 相关论文:**

1. **"PRFX: A Privacy-Preserving Prefix Summation Protocol on Blockchain with Zero-Knowledge Proof"** (Ismayilov et al., IEEE Blockchain 2024)
   - DOI: 10.1109/blockchain62396.2024.00054
   - ZK 证明用于区块链隐私

2. **"Privacy-Preserving Energy Trading Using Blockchain and Zero Knowledge Proof"** (Hou et al., IEEE Blockchain 2022)
   - DOI: 10.1109/blockchain55522.2022.00064
   - 19 引用

**与本项目匹配度: ⭐⭐⭐**
- 同 IEEE ICBC，非 CCF 收录
- 对应用场景的要求高于对密码学深度的要求

---

### #13 — DSN (International Conference on Dependable Systems and Networks)

| 属性 | 详情 |
|------|------|
| **CCF 等级** | B |
| **投稿主题偏好** | 系统安全、容错、可靠性 |
| **与本项目匹配度: ⭐⭐**
- DSN 的综合方向与本项目交叉较小
- 只有在论文强调"系统级安全性"时才有投稿意义

---

### #14 — SRDS (Symposium on Reliable Distributed Systems)

| 属性 | 详情 |
|------|------|
| **CCF 等级** | B |
| **投稿主题偏好** | 分布式系统、区块链协议 |
| **与本项目匹配度: ⭐⭐**
- 更偏分布式系统协议而非密码学实现

---

### #15 — ChinaCrypt (中国密码学会年会)

| 属性 | 详情 |
|------|------|
| **类型** | 国内学术会议 |
| **CCF 等级** | 无 |
| **频率** | 每年一届，通常在 10-11 月 |
| **格式** | 中文/英文, ~8-12 页 |
| **投稿 DDL** | 通常 7-8 月 |
| **审稿周期** | 1-2 个月 |
| **投稿主题偏好** | 密码学全领域；国密算法；后量子密码；密码工程 |
| **篇幅** | 8-10 页 |

**与本项目匹配度: ⭐⭐**
- **最大价值不在论文出版，而在学术社交** — 参会可以认识国内密码学审稿人（密码学报编委、国家密码管理局专家）
- 建议以"workshop/快速发表 + 社交"的心态投稿
- 不论是否 CCF，都值得提交（审稿快、社交价值高）

---

### #16 — BRAINS (Conference on Blockchain Research & Applications)

| 属性 | 详情 |
|------|------|
| **CCF 等级** | 无 |
| **审稿周期** | ~2-3 月 |
| **录用率** | ~35-40% |
| **与本项目匹配度: ⭐⭐**
- 保底选项

---

### #17 — 《软件学报》(Journal of Software)

| 属性 | 详情 |
|------|------|
| **CCF 等级** | A (国内) |
| **审稿周期** | 12-18 月 |
| **与本项目匹配度: ⭐⭐**
- 审稿周期过长 + 对单方案实现贡献度要求高
- 不推荐作为主投稿目标

---

### #18 — 《信息安全学报》(Journal of Information Security)

| 属性 | 详情 |
|------|------|
| **CCF 等级** | 无 (中科院新刊) |
| **审稿周期** | 3-9 月 |
| **与本项目匹配度: ⭐⭐**
- 时间敏感的备选
- 后量子安全是其常设栏目

---

### #19 — IEEE Access

| 属性 | 详情 |
|------|------|
| **类型** | 开源期刊 |
| **CCF 等级** | 无 |
| **审稿周期** | 1-3 月 (快速) |
| **接收率** | ~35-40% |
| **版面费** | $1,950 (开源费用) |
| **与本项目匹配度: ⭐ (仅作保底)**

---

### #20 — IACR ePrint Archive

| 属性 | 详情 |
|------|------|
| **类型** | 密码学预印本 |
| **CCF 等级** | 无 |
| **投稿 DDL** | 随时 |
| **与本项目匹配度: ⭐ (作为优先占位或附加)**

建议在正式投稿前将论文上传至 ePrint —— 这可以在审稿周期内确立时间优先权，并获得社区反馈。

---

## 综合推荐排序

### 第一档 (A) — 首选投稿目标

| 排序 | 会议/期刊 | CCF | 推荐理由 |
|------|---------|-----|---------|
| **1** | **FC 2027** | C | 金融密码学顶会，最接受"密码学实现+区块链"交叉。DDL 约 2026年9月 |
| **2** | **Inscrypt 2027** | C | CCF C + LNCS + 国内举办 + 审稿快 + 竞争温和。DDL 约 2027年6-7月 |
| **3** | **CANS 2027** | C | 应用密码学，对实现类工作友好。DDL 约 2027年5-6月 |

### 第二档 (B) — 高匹配度备选

| 排序 | 会议/期刊 | CCF | 说明 |
|------|---------|-----|------|
| **4** | **《密码学报》** | B | 中文 CCF B，有 SPHINCS+-SM3 先例。Rolling submission |
| **5** | **ACISP 2027** | C | 信息安全(亚太)，后量子是常设 topic。DDL 约 2027年2-3月 |
| **6** | **CT-RSA 2027** | C | 密码学实践，偏好有 benchmark 的工作。DDL 约 2026年8-9月 |
| **7** | **ISPEC 2027** | C | "Practice and Experience"，审稿快。DDL 约 2027年5-6月 |
| **8** | **PST 2027** | C | 隐私会议，录用率较高。DDL 约 2027年4-5月 |

### 第三档 (C) — 冲刺目标

| 排序 | 会议 | CCF | 说明 |
|------|------|-----|------|
| **9** | **ESORICS 2027** | B | 竞争激烈但声望高。DDL 约 2027年3-4月 |
| **10** | **ACNS 2027** | B | 应用密码学。DDL 约 2027年1月 |
| **11** | **IEEE ICBC 2027** | - | 区块链会，非 CCF 但出版快 |
| **12** | **IEEE Blockchain 2027** | - | 同上 |

### 第四档 (D) — 特定场景适用

| 排序 | 会议/期刊 | 说明 |
|------|---------|------|
| **13** | **ChinaCrypt** | 非 CCF 但社交价值高 |
| **14** | **BRAINS** | 保底区块链会 |
| **15** | **《信息安全学报》** | 审稿快的保底中文期刊 |

### 第五档 (E) — 纯保底

| 排序 | 选项 | 说明 |
|------|------|------|
| **16** | **IEEE Access** | 快速出版，但需版面费 |
| **17** | **IACR ePrint** | 优先占位，非正式出版 |

---

## 推荐的投稿时间线

```
2026年Q3-Q4 (当前-12月)
  │
  ├── 2026年8-9月: CT-RSA 2027 DDL (第一轮投稿)
  ├── 2026年9月:   FC 2027 DDL (第一轮投稿) ★最推荐
  ├── 2026年10月:  ChinaCrypt 2026 (如果有的话，快速发一篇中文版)
  │
  ├── 2026年12月:  FC 2027 notification
  │                 ├─ Accept → 结束!
  │                 └─ Reject → 修改后进入第二轮
  │
2027年Q1-Q2
  │
  ├── 2027年1月:   ACNS 2027 DDL
  ├── 2027年2-3月: ACISP 2027 DDL
  ├── 2027年3-4月: ESORICS 2027 DDL
  ├── 2027年5-6月: ISPEC / CANS 2027 DDL
  ├── 2027年6-7月: Inscrypt 2027 DDL ★最稳妥
  │
  └── 《密码学报》rolling submission — 可随时投稿中文版
```

### 最优策略

```
FC 2027 (英文, CCF C, 9月DDL)
  → 如12月被拒 → Inscrypt 2027 (英文, CCF C, 6-7月DDL)
    → 如再被拒 → IEEE Access 或 《信息安全学报》
    
      + 并行投稿 《密码学报》(中文版, CCF B, rolling)
        (两版差异 >30%)
```

---

## 参考文献

- [FC] https://fc.ifca.ai/ — Financial Cryptography and Data Security
- [Inscrypt] International Conference on Information Security and Cryptology, Springer LNCS
- [CANS] Cryptology and Network Security, Springer LNCS
- [ACISP] Australasian Conference on Information Security and Privacy, Springer LNCS
- [CT-RSA] Cryptographers' Track at RSA Conference, Springer LNCS
- [孙思维等 2023] 孙思维等, "SPHINCS+-SM3," 《密码学报》, 2023, 10(6): 1266-1278
- [Argo et al. 2024] S. Argo et al., "Practical Post-Quantum Signatures for Privacy," CCS 2024
- [Bouillaguet et al. 2026] C. Bouillaguet et al., "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026
- [Tas et al. 2024] E. N. Tas et al., "Atomic and Fair Data Exchange via Blockchain," CCS 2024
- [Hirata et al. 2026] S. Hirata et al., "Auditable Privacy via ZKP," IEEE ICBC 2026
- [Miyamae et al. 2021] T. Miyamae et al., "ZGridBC," IEEE ICBC 2021
- [Li et al. 2021] W. Li et al., "Blockchain and ZKP for Autonomous Truck Platooning," IEEE ICBC 2021
