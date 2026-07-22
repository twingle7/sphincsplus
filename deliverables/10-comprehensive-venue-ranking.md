# 交付物 #10: 投稿目标综合分析 — 20 个期刊/会议详细评估与推荐排序

> 整合安全、密码学、区块链、国内四个方向，每个 venue 包含完整的属性表格、描述段落、官网与投稿链接、相似论文实例。
> 与交付物 #8、#9 互为补充——#8 侧重区块链会策略分析，#9 侧重国内期刊会议，#10 为全局排名与时间线。

---

## 投稿目标总览

| # | 名称 | 类型 | CCF | 方向 | 推荐档位 |
|---|------|------|-----|------|---------|
| 1 | FC | 会议 | C | 金融密码学/区块链 | **A 首选** |
| 2 | Inscrypt | 会议 | C | 密码学(国内举办) | **A 首选** |
| 3 | CANS | 会议 | C | 应用密码学 | **A 首选** |
| 4 | ACISP | 会议 | C | 信息安全(亚太) | **B 高匹配** |
| 5 | CT-RSA | 会议 | C | 密码学实践 | **B 高匹配** |
| 6 | ISPEC | 会议 | B | 安全实践与经验 | **B 高匹配** |
| 7 | PST | 会议 | C | 隐私安全信任 | **B 高匹配** |
| 8 | 《密码学报》 | 期刊 | T2 (≈B) | 密码学 | **B 高匹配** |
| 9 | ESORICS | 会议 | B | 安全(欧洲) | **C 冲刺** |
| 10 | ACNS | 会议 | C | 应用密码学/网络安全 | **C 冲刺** |
| 11 | IEEE ICBC | 会议 | — | 区块链 | **C 冲刺** |
| 12 | Blockchain (IEEE) | 会议 | — | 区块链 | **C 冲刺** |
| 13 | DSN | 会议 | B | 系统安全 | **D 低匹配** |
| 14 | SRDS | 会议 | B | 分布式系统 | **D 低匹配** |
| 15 | ChinaCrypt | 会议 | — | 密码学(国内) | **D 低匹配** |
| 16 | BRAINS | 会议 | — | 区块链 | **D 低匹配** |
| 17 | 《软件学报》 | 期刊 | A/T1 | 计算机科学 | **D 低匹配** |
| 18 | 《信息安全学报》 | 期刊 | T2 | 信息安全 | **D 低匹配** |
| 19 | IEEE Access | 期刊 | — | 综合 | **E 保底** |
| 20 | IACR ePrint | 预印本 | — | 密码学 | **E 保底** |

---

## 详细评估

### #1 — Financial Cryptography and Data Security (FC)

| 属性 | 详情 |
|------|------|
| **全称** | Financial Cryptography and Data Security |
| **类型** | 国际学术会议 |
| **CCF 等级** | C（实际声望 ≈ B 级，金融密码学领域最高级别会议） |
| **CORE 等级** | B |
| **主办** | International Financial Cryptography Association (IFCA) |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，第 31 届 (FC 2027)，2027 年 2 月 8-12 日 |
| **格式/篇幅** | LNCS，正文 14-18 页 + 附录 |
| **官网** | [https://fc.ifca.ai/](https://fc.ifca.ai/)；FC 2027: [https://ifca.ai/fc27/](https://ifca.ai/fc27/) |
| **投稿 DDL** | FC 2027: 2026 年 9 月 17 日（Abstract & Full paper） |
| **录用率** | ~21%（2024: 42/199），历史区间 18-25% |
| **审稿周期** | ~7 周（通知通常在 11 月） |
| **投稿主题偏好** | 密码学与金融/区块链交叉；匿名支付、隐私交易、ZK 证明应用；后量子密码金融应用 |
| **与本项目匹配度** | ⭐⭐⭐⭐⭐ |

**描述。** FC 自 1997 年起每年举办，是金融密码学领域最具声望的会议。尽管 CCF 仅评为 C 类，但在区块链与密码学交叉方向其实际影响力远超 C 类水平。FC 审稿偏好"系统实现 + benchmark + 安全性分析"三位一体，对单方案实现容忍度高。本项目从"区块链匿名凭证的后量子安全"角度切入最为契合。关键要求：实验部分需加入链上验证成本分析。

**曾接收的相似论文：**

1. **"Atomic and Fair Data Exchange via Blockchain"** (Tas et al., CCS 2024) — 区块链原子化公平数据交换协议，含 Ethereum 开源实现 + gas cost 分析。[[DOI: 10.1145/3658644.3690248](https://doi.org/10.1145/3658644.3690248)]

2. **"Blindcoin: Blinded, Accountable Mixes"** (Valenta & Rowan, FC 2015 Workshop) — 盲签名实现 Bitcoin 混币器。

---

### #2 — Inscrypt (International Conference on Information Security and Cryptology)

| 属性 | 详情 |
|------|------|
| **全称** | International Conference on Information Security and Cryptology |
| **类型** | 国际学术会议（在中国举办，IACR in cooperation） |
| **CCF 等级** | C |
| **CACR 等级** | B（2025 年从 C 提升） |
| **主办** | 中国密码学会 (CACR) 合作，每年由国内不同高校承办 |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，第 22 届 (Inscrypt 2026)，2026 年 11 月 7-9 日，香港 |
| **格式/篇幅** | LNCS，正文 12-18 页 |
| **官网** | [https://inscrypt2026.comp.polyu.edu.hk](https://inscrypt2026.comp.polyu.edu.hk) |
| **投稿 DDL** | Inscrypt 2026 两轮均已截止；Inscrypt 2027 预计 2027 年 5-7 月 |
| **录用率** | ~25-30%（2025 西安: 79/315） |
| **审稿周期** | ~5-6 周（两轮审稿制） |
| **投稿主题偏好** | Track 1 密码学（含后量子密码专章）+ Track 2 安全（含区块链安全与隐私） |
| **与本项目匹配度** | ⭐⭐⭐⭐⭐ |

**描述。** Inscrypt 是 CACR 与 IACR 合作的国际会议，每年在中国不同城市举办，Springer LNCS 出版。它是国内学者发表密码学英文论文的最佳选择之一——CCF C 满足学术业绩要求、LNCS 提供 EI/CPCI 索引、国内举办无须出国差旅。Inscrypt 2025 的 LNCS Part I 设有"后量子密码"专章，表明该会对 PQC 方向有明确的接收意愿。CACR 2025 年将其从 C 类提升至 B 类。竞争强度低于 FC 和 ACISP。

---

### #3 — CANS (Cryptology and Network Security)

| 属性 | 详情 |
|------|------|
| **全称** | Cryptology and Network Security |
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | CANS Steering Committee |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届 |
| **格式/篇幅** | LNCS，正文 12-16 页 |
| **官网** | 每年不同；CANS 2026: [https://uow-ic2.github.io/cans2026/](https://uow-ic2.github.io/cans2026/) |
| **投稿 DDL** | CANS 2026 已截止（2026 年 6 月 19 日）；CANS 2027 预计 2027 年 5-6 月 |
| **录用率** | ~25-30% |
| **审稿周期** | ~8 周 |
| **投稿主题偏好** | 密码学协议设计与分析、网络安全、后量子密码学、应用密码学实现、区块链安全 |
| **与本项目匹配度** | ⭐⭐⭐⭐⭐ |

**描述。** CANS 的 scope 明确覆盖"cryptology AND network security"——本项目恰好是密码学方案在分布式系统（区块链）中的应用，匹配度极高。CANS 的竞争激烈程度低于 FC 和 ACISP，对密码学实现类工作友好。作为 CCF C 会议中的稳健选择，CANS 适合时间线与 Inscrypt 互补投稿。

---

### #4 — ACISP (Australasian Conference on Information Security and Privacy)

| 属性 | 详情 |
|------|------|
| **全称** | Australasian Conference on Information Security and Privacy |
| **类型** | 国际学术会议 |
| **CCF 等级** | C（中国密码学会也推荐） |
| **CORE 等级** | B |
| **主办** | ACISP Steering Committee |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 7 月 |
| **格式/篇幅** | LNCS，正文 12-16 页 |
| **官网** | [https://acisp.org/](https://acisp.org/) |
| **投稿 DDL** | ACISP 2026 已截止；ACISP 2027 预计 2027 年 2-3 月 |
| **录用率** | ~30%（2024: 70/232），历史区间 24-39% |
| **审稿周期** | ~7-8 周 |
| **投稿主题偏好** | 信息安全与隐私、密码学协议、后量子密码学、应用密码学、区块链安全 |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** ACISP 是亚太地区信息安全领域历史悠久的会议（CCF C，CORE B），后量子密码是其常设 topic。会议接受 SoK 论文，审稿对亚洲作者友好。竞争强度略低于 FC/ESORICS，但高于 Inscrypt/CANS。录用率约 30%，在 C 类会中属于较易接收的范畴。

---

### #5 — CT-RSA (Cryptographers' Track at RSA Conference)

| 属性 | 详情 |
|------|------|
| **全称** | Cryptographers' Track at RSA Conference |
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **CORE 等级** | B |
| **主办** | RSA Conference（与 IACR 合作） |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，2027 年 4 月 5-8 日，San Francisco |
| **格式/篇幅** | LNCS，正文 14-18 页 |
| **官网** | 与 RSA Conference 同步：[https://www.rsaconference.com/](https://www.rsaconference.com/) |
| **投稿 DDL** | **CT-RSA 2027: 2026 年 10 月 22 日**（仍开放！） |
| **录用率** | ~23-39%（2025: 18/46 ≈ 39%） |
| **审稿周期** | ~5-6 个月（较长） |
| **投稿主题偏好** | 密码学在实践中的应用；新密码学构造和协议；密码学实现和性能评估；**后量子密码学**；区块链与分布式账本安全 |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** CT-RSA 的核心理念是"密码学在真实世界中的应用"——这与本项目的"工程实现 + benchmark"定位高度吻合。会议不是理论密码学会议，审稿人不会要求新的安全性定理，但偏好有实践验证的方案。DDL 在 2026 年 10 月 22 日，是 FC 之后的理想备选投稿目标。录用率在 C 类会中偏高（23-39%），但审稿周期较长（5-6 个月）。

---

### #6 — ISPEC (Information Security Practice and Experience)

| 属性 | 详情 |
|------|------|
| **全称** | Information Security Practice and Experience |
| **类型** | 国际学术会议 |
| **CCF 等级** | **B** |
| **CORE 等级** | B |
| **主办** | ISPEC Steering Committee |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届；ISPEC 2026 年 11 月 6-8 日，西安 |
| **格式/篇幅** | LNCS，正文 10-14 页 |
| **官网** | ISPEC 2026: [EasyChair CFP](https://easychair.org/conferences/?conf=ispec2026) |
| **投稿 DDL** | **ISPEC 2026 Round 2: 2026 年 8 月 7 日**（仍开放！） |
| **录用率** | ~23-31% |
| **审稿周期** | ~4 周（极快） |
| **投稿主题偏好** | 安全实践与经验、密码学实现和部署、安全评估、应用密码学 |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** ISPEC 是 CCF B 类会议中**最明确的"工程实践"导向会议**——会议名就叫 "Practice and Experience"。对"第一个实现"类型的贡献接受度高于纯理论会议。审稿速度极快（4 周），且 2026 年 Round 2 的 DDL（8 月 7 日）仍开放——这是目前所有 venue 中**DDL 最近且 CCF 等级最高**的投稿机会。适合时间敏感的投稿。ISPEC 2026 在西安举办，无须出国。

---

### #7 — PST (International Conference on Privacy, Security and Trust)

| 属性 | 详情 |
|------|------|
| **全称** | International Conference on Privacy, Security and Trust |
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | PST Steering Committee（IEEE Computer Society 技术协办） |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 8 月 |
| **格式/篇幅** | IEEE 双栏，正文 8-10 页 |
| **官网** | [https://www.pstnet.ca/](https://www.pstnet.ca/) |
| **投稿 DDL** | PST 2026 已截止（2026 年 4 月 28 日）；PST 2027 预计 2027 年 4-5 月 |
| **录用率** | ~32-38% |
| **审稿周期** | ~5 周 |
| **投稿主题偏好** | 隐私保护技术、安全协议、信任管理、匿名凭证、区块链隐私、**后量子密码**（PST 2025 CFP 明确列出） |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** PST 对"Privacy"方向的论文天然友好——盲签名是核心隐私原语，且 CFP 明确列出了后量子密码。IEEE 格式比 LNCS 更紧凑（8-10 页），对实验密度要求较低，录用率较高，是稳妥的 CCF C 选择。

---

### #8 — 《密码学报》(Journal of Cryptologic Research)

| 属性 | 详情 |
|------|------|
| **全称** | 密码学报（Journal of Cryptologic Research） |
| **类型** | 中文学术期刊（2023 年起中英文双语出版） |
| **CCF 等级** | T2 级（≈ B 类）；CCF 推荐中文期刊 |
| **CACR 等级** | 中国密码学会推荐中文期刊 |
| **主办** | 中国密码学会、北京信息科学技术研究院、中国科学技术出版社 |
| **ISSN** | 2095-7025 |
| **频率** | 双月刊 |
| **格式/篇幅** | 中文（或英文），正文 15-18 页 |
| **官网** | [http://www.jcr.cacrnet.org.cn](http://www.jcr.cacrnet.org.cn) |
| **投稿渠道** | 官网在线投稿系统 |
| **投稿 DDL** | 滚动接受 |
| **审稿周期** | 6-12 个月 |
| **费用** | **不收版面费、审稿费**，录用后支付稿费 |
| **收录** | **北大核心（2023 版）**、CSCD 核心、CSTPCD、Scopus |
| **投稿主题偏好** | 密码学全领域：对称/公钥密码、**后量子密码**、安全协议、密码工程、区块链 |
| **与本项目匹配度** | ⭐⭐⭐⭐ |

**描述。** 中国密码学会官方旗舰期刊，国内密码学最高级别中文期刊。有直接的 SPHINCS+-SM3 先例（孙思维等, 2023），本文的复杂度高于该文，投中概率极大。不收任何费用，双向匿名审稿。缺点是审稿周期长（6-12 月），对时间敏感的投稿需权衡。

---

### #9 — ESORICS (European Symposium on Research in Computer Security)

| 属性 | 详情 |
|------|------|
| **全称** | European Symposium on Research in Computer Security |
| **类型** | 国际学术会议 |
| **CCF 等级** | **B** |
| **CORE 等级** | **A** |
| **主办** | ESORICS Steering Committee |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 9 月 |
| **格式/篇幅** | LNCS，正文 16-20 页 |
| **官网** | [https://esorics2026.univie.ac.at/](https://esorics2026.univie.ac.at/) |
| **投稿 DDL** | ESORICS 2026 两轮均已截止；ESORICS 2027 Winter 约 2027 年 1 月 |
| **录用率** | ~16%（2024: 86/535），竞争激烈 |
| **审稿周期** | ~2 个月/轮（两轮审稿制） |
| **投稿主题偏好** | 计算机安全全领域：密码学协议安全分析、网络安全、隐私保护、系统安全 |
| **与本项目匹配度** | ⭐⭐⭐（冲刺级别） |

**描述。** ESORICS 是欧洲安全旗舰会议（CCF B，CORE A），竞争激烈（录用率 ~16%）。作为综合性安全会议，密码学实现类论文占比不高，更偏好有形式化安全分析或系统级评估的工作。如果论文写得足够好且实验全面，可作为冲刺目标。Workshop（如 DPM, CryptoBlock）是更温和的替代通道。

---

### #10 — ACNS (Applied Cryptography and Network Security)

| 属性 | 详情 |
|------|------|
| **全称** | Applied Cryptography and Network Security |
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **CORE 等级** | B |
| **主办** | ACNS Steering Committee |
| **出版** | Springer LNCS（EI/CPCI 收录） |
| **频率** | 每年一届，通常在 6 月 |
| **格式/篇幅** | LNCS，正文 14-18 页 |
| **官网** | 每年不同；ACNS 2026: [https://acns2026.github.io/](https://acns2026.github.io/) |
| **投稿 DDL** | ACNS 2026 已截止；ACNS 2027 预计 2027 年 1 月 |
| **录用率** | ~23%（2025: 55/241），均值 19.6% |
| **审稿周期** | ~8 周（两轮审稿制） |
| **投稿主题偏好** | 应用密码学、网络安全、后量子密码学、密码学协议、区块链安全 |
| **与本项目匹配度** | ⭐⭐⭐（冲刺级别） |

**描述。** ACNS 的"Applied Cryptography"定位与本项目的工程实现方向吻合。设有 Best Student Paper Award（EUR 1,500）。近年来接收的后量子密码论文以格基和编码基为主，哈希基较少——这既是风险（审稿人不熟悉），也是机会（新颖性更高）。竞争激烈（~20%），建议作为冲刺目标。

---

### #11 — IEEE ICBC (International Conference on Blockchain and Cryptocurrency)

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
| **投稿 DDL** | ICBC 2026 已截止（2026 年 1 月 14 日）；ICBC 2027 预计 2027 年 1 月 |
| **录用率** | ~17-23% |
| **审稿周期** | ~8-10 周 |
| **投稿主题偏好** | 区块链系统与协议；加密货币；智能合约安全；隐私保护技术；分布式账本 |
| **与本项目匹配度** | ⭐⭐⭐ |

**描述。** ICBC 接收了大量 ZKP + 区块链的论文，但多数是应用导向的（"用 ZK 解决区块链问题"），而非密码学实现导向的。本项目可适配 ICBC 叙事模式但需增加区块链应用场景分析。非 CCF 会议，对 CCF 论文产出有要求的场景不适用。

---

### #12 — IEEE Blockchain (International Conference on Blockchain)

| 属性 | 详情 |
|------|------|
| **全称** | IEEE International Conference on Blockchain |
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 |
| **主办** | IEEE Computer Society（与 IEEE Cybermatics 同地举办） |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届；2026 年 11 月 30 日-12 月 4 日，Montbeliard, France |
| **格式/篇幅** | IEEE 双栏，正文 6-8 页 |
| **官网** | [https://ieee-cybermatics2026.org/call-for-papers/blockchain](https://ieee-cybermatics2026.org/call-for-papers/blockchain) |
| **投稿 DDL** | IEEE Blockchain 2026 已截止（2026 年 6 月 15 日）；2027 预计 2027 年 6 月 |
| **录用率** | ~30-38% |
| **审稿周期** | ~10-12 周 |
| **投稿主题偏好** | 区块链共识、智能合约、DLT、区块链安全与隐私 |
| **与本项目匹配度** | ⭐⭐⭐ |

**描述。** 100% 区块链聚焦，对 ZK 证明 + 区块链的论文有明确的接收先例（PRFX 隐私求和协议、能源交易隐私保护等）。非 CCF 会议，出版速度快，但对中国学位申请的 CCF 论文要求无贡献。

---

### #13 — DSN (International Conference on Dependable Systems and Networks)

| 属性 | 详情 |
|------|------|
| **全称** | International Conference on Dependable Systems and Networks |
| **类型** | 国际学术会议 |
| **CCF 等级** | **B** |
| **CORE 等级** | A |
| **主办** | IEEE/IFIP |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届；DSN 2026: 2026 年 6 月 22-25 日，Charlotte, USA |
| **格式/篇幅** | IEEE 双栏 |
| **官网** | [https://dsn2026.github.io/](https://dsn2026.github.io/) |
| **投稿 DDL** | DSN 2026 已截止（2025 年 12 月）；DSN 2027 预计 2026 年 11-12 月 |
| **录用率** | ~20%（2024: 42/204） |
| **审稿周期** | ~4 个月 |
| **投稿主题偏好** | 系统安全、容错、可靠性 |
| **与本项目匹配度** | ⭐⭐ |

**描述。** DSN 聚焦系统可靠性与容错，密码学协议设计不在其核心 scope 内。仅当论文强调"盲签名作为区块链隐私基础设施的系统级可靠性"时才有投稿意义。不推荐作为主要投稿目标。

---

### #14 — SRDS (International Symposium on Reliable Distributed Systems)

| 属性 | 详情 |
|------|------|
| **全称** | International Symposium on Reliable Distributed Systems |
| **类型** | 国际学术会议 |
| **CCF 等级** | **B** |
| **CORE 等级** | A |
| **主办** | IEEE |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届；SRDS 2026: 2026 年 9 月 21-25 日，Rome |
| **官网** | [https://srds-conference.org/](https://srds-conference.org/) |
| **投稿 DDL** | SRDS 2026 已截止（2026 年 5 月 8 日）；SRDS 2027 预计 2027 年 4-5 月 |
| **录用率** | ~30%（2024: 26/87） |
| **审稿周期** | ~8-10 周 |
| **投稿主题偏好** | 分布式系统可靠性、安全性、共识协议 |
| **与本项目匹配度** | ⭐⭐ |

**描述。** SRDS 偏分布式系统协议而非密码学实现。区块链共识相关论文偶有接收，但密码学方案论文需极强的分布式系统叙事包装。不推荐。

---

### #15 — ChinaCrypt (中国密码学会年会)

| 属性 | 详情 |
|------|------|
| **全称** | 中国密码学会年会 |
| **类型** | 国内学术会议 |
| **CCF 等级** | 无（未被 CCF 推荐目录收录） |
| **CACR 等级** | 中国密码学会年会 |
| **主办** | 中国密码学会，每年由不同高校承办 |
| **出版** | 优秀论文推荐至《密码学报》；不独立出版论文集 |
| **频率** | 每年一届，通常在 10-11 月；2026 年 10 月 23-25 日，青岛 |
| **格式/篇幅** | 中文/英文，LaTeX 排版，一般不超过 12 页 |
| **官网** | [https://www.cacrnet.org.cn](https://www.cacrnet.org.cn) |
| **投稿 DDL** | 通常在 7-10 月（2026 年待公布） |
| **审稿周期** | 极快——约 10 天通知 |
| **投稿主题偏好** | 密码学全领域；后量子密码；密码工程；区块链 |
| **与本项目匹配度** | ⭐⭐⭐（学术社交价值高于出版价值） |

**描述。** 国内密码学学术交流的核心平台。审稿极快、不收费用。最大价值在学术社交——与会者可结识《密码学报》编委和国家密码管理局专家。不论是否 CCF 都值得提交。

---

### #16 — BRAINS (Conference on Blockchain Research & Applications)

| 属性 | 详情 |
|------|------|
| **全称** | Conference on Blockchain Research & Applications for Innovative Networks and Services |
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 |
| **主办** | IEEE |
| **出版** | IEEE Xplore（EI/CPCI 收录） |
| **频率** | 每年一届；BRAINS 2026: 2026 年 10 月 13-16 日，Florence, Italy |
| **官网** | [https://brains.dnac.org/](https://brains.dnac.org/) |
| **投稿 DDL** | BRAINS 2026 主会已截止（2026 年 6 月 14 日） |
| **录用率** | ~35-40% |
| **审稿周期** | ~6-8 周 |
| **投稿主题偏好** | 100% 区块链聚焦：共识协议、智能合约、DeFi、DLT 安全 |
| **与本项目匹配度** | ⭐⭐⭐ |

**描述。** 新兴区块链专向会议，竞争温和，录用率较高。优秀论文可快速推荐至 ACM DLT 期刊。适合作为 FC 被拒后的安全降级目标。

---

### #17 — 《软件学报》(Journal of Software)

| 属性 | 详情 |
|------|------|
| **全称** | 软件学报（Journal of Software） |
| **类型** | 中文学术期刊 |
| **CCF 等级** | **A 类 / T1 级** |
| **主办** | 中科院软件研究所、CCF |
| **ISSN** | 1000-9825 |
| **频率** | 月刊 |
| **审稿周期** | 12-18 个月 |
| **收录** | 北大核心、CSCD、**EI** |
| **投稿主题偏好** | 计算机科学全领域：信息安全是其子方向 |
| **与本项目匹配度** | ⭐⭐ |

**描述。** CCF A 类中文期刊，2025 年有"抗量子密码与区块链应用"专题。但审稿周期过长（12-18 月），且对系统性贡献要求极高。单方案实现难以满足要求，不推荐作为主目标。

---

### #18 — 《信息安全学报》(Journal of Cyber Security)

| 属性 | 详情 |
|------|------|
| **全称** | 信息安全学报（Journal of Cyber Security） |
| **类型** | 中文学术期刊 |
| **CCF 等级** | **T2 级**（CCF 高质量科技期刊，2025 版）；B 类（旧版 CCF 推荐） |
| **主管** | 中国科学院 |
| **主办** | 中科院信息工程研究所、中国科技出版传媒 |
| **主编** | 方滨兴 院士 |
| **ISSN** | 2096-1146 |
| **创刊** | 2016 年 |
| **频率** | 双月刊 |
| **审稿周期** | 1-3 个月（官方），实际完整周期 3-12 个月 |
| **收录** | **CSCD 核心**、CSTPCD、**Scopus** |
| **投稿主题偏好** | 网络安全全领域；密码学与隐私保护；区块链安全 |
| **与本项目匹配度** | ⭐⭐⭐ |

**描述。** 2016 年创刊（已运行约 10 年），由方滨兴院士主编。2019 年出版过"后量子密码"专刊。审稿周期较《密码学报》短，PQC 发文量可观。但未被北大核心 2023 版收录，对部分高校学位申请论文要求可能不满足。适合作为时间敏感的保底中文期刊。

---

### #19 — IEEE Access

| 属性 | 详情 |
|------|------|
| **全称** | IEEE Access |
| **类型** | 开源期刊（Open Access） |
| **CCF 等级** | 无 |
| **主办** | IEEE |
| **频率** | 连续出版 |
| **审稿周期** | ~4 周（极快） |
| **录用率** | ~20%（官方），年发文 >10,000 篇 |
| **版面费** | ~$1,950 USD |
| **收录** | SCI（IF ~4.2）、EI、Scopus |
| **投稿主题偏好** | 所有 IEEE 相关领域；已发表大量后量子区块链论文 |
| **与本项目匹配度** | ⭐⭐（仅作保底） |

**描述。** IEEE 的开源 mega-journal，审稿极快（4 周），SCI Q2（IF ~4.2）。已发表大量后量子区块链论文（PP-PQB 综述、CRYSTALS-Dilithium 在区块链中的应用等）。但版面费高（~$1,950），国内部分高校不认可其为 CCF 论文。仅作最后保底。

---

### #20 — IACR ePrint Archive

| 属性 | 详情 |
|------|------|
| **全称** | IACR Cryptology ePrint Archive |
| **类型** | 密码学预印本（非正式出版） |
| **CCF 等级** | 无 |
| **投稿 DDL** | 随时 |
| **投稿主题偏好** | 密码学全领域 |
| **与本项目匹配度** | ⭐ |

**描述。** 密码学领域最权威的预印本平台。建议在正式投稿前上传至 ePrint 以确立时间优先权并获得社区反馈。不计入 CCF 论文出版。

---

## 综合推荐排序

### 第一档 (A) — 首选投稿目标

| 排序 | 会议/期刊 | CCF | 最近 DDL | 推荐理由 |
|------|---------|-----|---------|---------|
| **1** | **FC 2027** | C | **2026-09-17** ★ | 金融密码学顶会，最接受"密码学实现+区块链"交叉 |
| **2** | **Inscrypt 2027** | C | ~2027-05 | CCF C + LNCS + 国内举办 + 后量子专章 |
| **3** | **CANS 2027** | C | ~2027-05 | 应用密码学，对实现类工作友好 |

### 第二档 (B) — 高匹配度备选

| 排序 | 会议/期刊 | CCF | DDL | 说明 |
|------|---------|-----|-----|------|
| **4** | **《密码学报》** | T2 | Rolling | CCF T2，有 SPHINCS+-SM3 先例，不收费用 |
| **5** | **CT-RSA 2027** | C | **2026-10-22** ★ | 密码学实践，DDL 仍在开放 |
| **6** | **ISPEC 2026 R2** | B | **2026-08-07** ★ | 审稿 4 周，在西安举办，DDL 最近 |
| **7** | **ACISP 2027** | C | ~2027-02 | 亚太安全，后量子是常设 topic |
| **8** | **PST 2027** | C | ~2027-04 | 隐私会议，录用率较高 |

### 第三档 (C) — 冲刺目标

| 排序 | 会议 | CCF | DDL | 说明 |
|------|------|-----|-----|------|
| **9** | **ESORICS 2027** | B | ~2027-01 | CORE A，竞争激烈（~16%） |
| **10** | **ACNS 2027** | C | ~2027-01 | 应用密码学，Best Student Paper Award |

### 第四档 (D) — 特定场景适用

| 排序 | 会议/期刊 | 说明 |
|------|---------|------|
| **11** | IEEE ICBC | 非 CCF，区块链专向 |
| **12** | IEEE Blockchain | 非 CCF，区块链专向 |
| **13** | ChinaCrypt | 非 CCF，学术社交价值高 |
| **14** | BRAINS | 非 CCF，保底区块链会 |
| **15** | 《信息安全学报》 | CCF T2，审稿较快 |
| **16** | 《软件学报》 | CCF A，审稿过长 |
| **17** | DSN | 系统方向，匹配度低 |
| **18** | SRDS | 分布式系统方向，匹配度低 |

### 第五档 (E) — 纯保底

| 排序 | 选项 | 说明 |
|------|------|------|
| **19** | IEEE Access | 快速出版，版面费 ~$1,950 |
| **20** | IACR ePrint | 优先占位，非正式出版 |

---

## 推荐的投稿时间线

```
2026年Q3 (当前)
  │
  ├── 2026-08-07: ISPEC 2026 Round 2 DDL ★ CCF B, 4周审稿
  ├── 2026-09-17: FC 2027 DDL ★ 首选
  ├── 2026-10-22: CT-RSA 2027 DDL ★ CCF C, 仍在开放
  ├── 2026-10-23: ChinaCrypt 2026, 青岛 (DDL 待公布)
  │
2026年Q4
  │
  ├── 2026-11-05: FC 2027 notification
  │                 ├─ Accept → 结束!
  │                 └─ Reject → 修改后进入第二轮
  │
2027年Q1-Q2
  │
  ├── 2027-01: ESORICS 2027 Winter DDL / ACNS 2027 DDL
  ├── 2027-02-03: ACISP 2027 DDL
  ├── 2027-04-05: PST 2027 / SRDS 2027 DDL
  ├── 2027-05-06: ISPEC 2027 / CANS 2027 DDL
  ├── 2027-06-07: Inscrypt 2027 DDL ★ 最稳妥
  │
  └── 《密码学报》rolling submission — 可随时投稿中文版
```

### 最优策略

```
FC 2027 (英文, CCF C, 9月DDL) ★ 第一轮
  → 如12月被拒 → Inscrypt 2027 (英文, CCF C, 6-7月DDL)
    → 如再被拒 → IEEE Access 或 《信息安全学报》
    
      + 并行投稿 《密码学报》(中文版, CCF T2, rolling)
        (两版差异 >30%)
        
      + ISPEC 2026 R2 (快速曝光: 8月DDL → 4周通知)
```

---

## 参考文献

- [FC] Financial Cryptography and Data Security — [https://fc.ifca.ai/](https://fc.ifca.ai/)
- [FC 2027 CFP] [https://ifca.ai/fc27/](https://ifca.ai/fc27/)
- [Inscrypt 2026] [https://inscrypt2026.comp.polyu.edu.hk](https://inscrypt2026.comp.polyu.edu.hk)
- [CANS 2026] [https://uow-ic2.github.io/cans2026/](https://uow-ic2.github.io/cans2026/)
- [CT-RSA] [https://www.rsaconference.com/](https://www.rsaconference.com/)
- [ISPEC 2026] [EasyChair CFP](https://easychair.org/conferences/?conf=ispec2026)
- [PST] [https://www.pstnet.ca/](https://www.pstnet.ca/)
- [ACNS 2026] [https://acns2026.github.io/](https://acns2026.github.io/)
- [ESORICS 2026] [https://esorics2026.univie.ac.at/](https://esorics2026.univie.ac.at/)
- [IEEE Blockchain 2026] [https://ieee-cybermatics2026.org/](https://ieee-cybermatics2026.org/)
- [IEEE Access] [https://ieeeaccess.ieee.org/](https://ieeeaccess.ieee.org/)
- [IACR ePrint] [https://eprint.iacr.org/](https://eprint.iacr.org/)
- [孙思维等 2023] 孙思维等, "SPHINCS+-SM3," 《密码学报》, 2023, 10(6): 1266-1278. [DOI: 10.13868/j.cnki.jcr.000536](https://doi.org/10.13868/j.cnki.jcr.000536)
- [Argo et al. 2024] S. Argo et al., "Practical Post-Quantum Signatures for Privacy," CCS 2024. [DOI: 10.1145/3658644.3670297](https://doi.org/10.1145/3658644.3670297)
- [Bouillaguet et al. 2026] C. Bouillaguet et al., "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. [DOI: 10.1109/SP63933.2026.00032](https://doi.org/10.1109/SP63933.2026.00032)
- [Tas et al. 2024] E. N. Tas et al., "Atomic and Fair Data Exchange via Blockchain," CCS 2024. [DOI: 10.1145/3658644.3690248](https://doi.org/10.1145/3658644.3690248)
- [Hirata et al. 2026] S. Hirata et al., "Auditable Privacy via ZKP," IEEE ICBC 2026. [DOI: 10.1109/icbc67748.2026.11575482](https://doi.org/10.1109/icbc67748.2026.11575482)
- [Miyamae et al. 2021] T. Miyamae et al., "ZGridBC," IEEE ICBC 2021. [DOI: 10.1109/icbc51069.2021.9461122](https://doi.org/10.1109/icbc51069.2021.9461122)
- [Li et al. 2021] W. Li et al., "Blockchain and ZKP for Autonomous Truck Platooning," IEEE ICBC 2021. [DOI: 10.1109/icbc51069.2021.9461116](https://doi.org/10.1109/icbc51069.2021.9461116)
