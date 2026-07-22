# 交付物 #11: 20 个投稿目标精细调研 — 全维度分析

> 每个 venue 包含 13 项信息：类型、CCF、主办方、频率、DDL、投稿系统、格式、审稿周期、主题偏好、结构偏好、相似论文、匹配度、投稿策略。

---

## 1. FC — Financial Cryptography and Data Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C（金融密码学领域实际声望等同于 B 级顶会） |
| **主办方** | International Financial Cryptography Association (IFCA) |
| **频率与届数** | 每年一届。FC 2026 已于 2026 年 2 月举办，FC 2027 预计 2027 年 2-3 月 |
| **投稿 DDL** | FC 2027: Abstract ~2026年9月15日, Full paper ~2026年9月22日（基于 FC 2024/2025/2026 模式推算：每年 9 月中下旬） |
| **投稿方式** | EasyChair 投稿系统; CFP 发布在 https://fc.ifca.ai/ |
| **格式要求** | Springer LNCS 模板；正文 14-20 页 + 参考文献 + 附录；LaTeX `\documentclass{llncs}` |
| **审稿周期** | ~3 个月（9月投稿 → 12月 notification） |
| **录用率** | ~25-27% |
| **出版** | Springer LNCS, EI/CPCI-S 双收录 |

### 主题与结构偏好
- **主题:** 密码学在金融系统中的应用；区块链、加密货币、智能合约安全；隐私保护的支付和交易系统；后量子安全与金融基础设施的交叉；匿名凭证和数字身份
- **结构:** FC 审稿人期待：(1) 密码学构造 → (2) 安全性分析 → (3) **系统实现和 benchmark** → (4) **金融/区块链应用场景验证**。纯密码学方案而无应用场景分析在 FC 不易被接受
- **篇幅建议:** Introduction (2pp) → Preliminaries (2pp) → Design (4-5pp) → Security (2pp) → **Implementation & Evaluation (3-4pp)** → Blockchain Application (1-2pp) → Related Work (1pp) → Conclusion

### 曾接收的相似论文实例

1. **"Atomic and Fair Data Exchange via Blockchain"** (Tas, Seres, Zhang et al., CCS 2024)
   - DOI: 10.1145/3658644.3690248
   - 主要贡献：提出 VECK (Verifiable Encryption under Committed Key) 新密码学原语 + 基于区块链的原子化数据交换协议
   - 实验设计：Ethereum 实现 + gas cost 分析 + 端到端 benchmark
   - 匹配点：密码学构造 + 区块链应用 + 完整实现 + gas cost
   - **为何类似本项目：** "新密码学构造+工程实现+区块链验证"的论文结构

2. **历年 FC 接收的 ZK/隐私主题论文:** FC 有固定的 "Privacy" 和 "Zero-Knowledge" session。2023-2026 届均有 2-3 篇 ZK 证明在区块链隐私应用中的论文。SNARK/STARK 在链上验证的成本分析是 FC 审稿人熟悉的话题

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐⭐** — 最匹配的 CCF C 会议。FC 同时看重密码学深度和区块链应用价值
- **投稿策略:** 实验部分必须加入：(1) on-chain verification cost (Ethereum gas / StarkNet cost)，(2) credential lifecycle analysis (签发频率 × prove time)，(3) 与 Zcash/Monero/Tornado Cash 的隐私方案对比。论文叙事定位为 "A Post-Quantum Anonymous Credential System for Blockchain"
- **关键区分点 vs 其他 FC 论文:** 强调 "hash-based" 的密码学保守性——"the only post-quantum privacy solution that relies solely on hash function security, with no structured lattice or isogeny assumptions"

---

## 2. ESORICS — European Symposium on Research in Computer Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | B（欧洲三大安全会议之一，与 CCS/S&P/Usenix Security 并列但低一档） |
| **主办方** | 欧洲各大学轮值主办，Springer 出版 |
| **频率与届数** | 每年一届，通常在 9 月。ESORICS 2026 将在 2026年9月举办 |
| **投稿 DDL** | ESORICS 2027: 预计 2027年3月-4月（历年模式：春季 DDL，秋季开会） |
| **投稿方式** | EasyChair; CFP 在 https://esorics2026.org/ 等轮值网站发布 |
| **格式要求** | Springer LNCS；正文 16-22 页 |
| **审稿周期** | ~3-4 个月，双盲审稿 |
| **录用率** | ~20-24% |
| **出版** | LNCS, EI/CPCI-S |

### 主题与结构偏好
- **主题:** 全领域计算机安全：网络安全、系统安全、密码学协议、隐私、访问控制、软件安全、AI 安全
- **结构:** 强调安全性论证的严谨性（形式化分析或实验验证均可接受）；对纯实现论文要求有明确的安全贡献

### 曾接收的相似论文
- ESORICS 的 "Applied Cryptography" track 历史上接收了部分后量子密码学和区块链安全的论文
- **注意：** ESORICS 论文的密码学深度通常低于专门密码学会议（CRYPTO/EUROCRYPT），但高于 FC/ACISP。对"工程实现"的接受度低于 ISPEC/PST。本项目投 ESORICS 需要强化安全性分析章节

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐（冲刺）** — CCF B 竞争激烈；需要强调"首个 SPHINCS+ Fischlin-STARK 实例化"的 novelty + 充分的安全归约链
- **投稿策略:** 如需投 ESORICS，建议增加形式化安全实验（game-based proof sketch）或威胁模型分析；CCF B 对学位申请有加成

---

## 3. ACNS — Applied Cryptography and Network Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | B（应用密码学领域仅次于 CCS/S&P 的综合性会议） |
| **主办** | 各大学轮值, Springer LNCS |
| **投稿 DDL** | ACNS 2027: 预计 2027年1月（历年 Summer 开会，Winter DDL） |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 14-20 页正文 |
| **审稿** | ~3 月, 录用率 ~22-26% |
| **主题偏好** | "Applied Cryptography" 包含密码学实现、协议设计和安全分析；"Network Security" 包含网络协议安全、区块链安全 |

### 曾接收的相似论文
1. **"Security Comparisons and Performance Analyses of Post-quantum Signature Algorithms"** (Raavi et al., ACNS 2021)
   - LNCS, DOI: 10.1007/978-3-030-78375-4_17, 41 引用
   - 主要贡献: PQC 签名算法 (Dilithium, Falcon, SPHINCS+) 的全面安全性对比和性能分析
   - **与本项目相似度: ⭐⭐⭐⭐** — PQC 签名 benchmark 论文在 ACNS 成功发表，证明此类工作 route 可行

2. **"Post-Quantum Cryptography for Linux File System Integrity"** (Wiesböck et al., ACNS 2025)
   - LNCS, DOI: 10.1007/978-3-031-95767-3_3
   - PQC 在真实系统中的应用——审稿人接受"实现+部署"类论文

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐（冲刺）** — CCF B；有历史先例表明 PQC 实现可发表
- **投稿策略:** 强化 "Applied" 角度——不仅是 benchmark，还要讨论部署场景

---

## 4. ACISP — Australasian Conference on Information Security and Privacy

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | 澳大利亚/新西兰各大学轮值, Springer LNCS |
| **投稿 DDL** | ACISP 2027: 预计 2027年2月-3月（历年 7 月开会，年初 DDL） |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 12-18 页 |
| **审稿** | ~2-3 月, 录用率 ~25-30% |
| **主题偏好** | 信息安全与隐私全领域，后量子密码学近年成为常设 track |
| **特点** | 澳大利亚地区会议，对亚洲学者投稿友好，竞争强度低于 FC/ESORICS |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐** — 后量子密码学的常设 track + 温和竞争
- **投稿策略:** 强调 SPHINCS+ 的 NIST 标准化背景（澳大利亚在 NIST PQC 标准化中参与度较高）

---

## 5. CANS — Cryptology and Network Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | 各大学轮值, Springer LNCS |
| **投稿 DDL** | CANS 2027: 预计 2027年5月-6月 |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 12-18 页 |
| **审稿** | ~3 月, 录用率 ~28-33% |
| **主题偏好** | Cryptology AND Network Security——密码学协议 + 网络安全应用的交叉 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐⭐** — 会议 scope 明确覆盖"密码学+网络/区块链"交叉，是项目最匹配的 CCF C 会议之一
- **投稿策略:** 可以作为 FC 被拒后的首选投稿目标

---

## 6. CT-RSA — Cryptographers' Track at RSA Conference

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C（但密码学圈内声望极高——"RSA 的密码学 track"） |
| **主办** | RSA Conference, Springer LNCS |
| **投稿 DDL** | CT-RSA 2027: 预计 2026年8月-9月（每年 2 月开会，前一年夏季 DDL） |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 14-20 页 |
| **审稿** | ~3 月, 录用率 ~22-28% |
| **主题偏好** | 密码学在真实世界中的应用；有新密码学构造但必须有实践验证（implementation + benchmark）；后量子密码学的部署话题 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐** — CT-RSA 偏好 "实践验证" 而非 "纯理论"——项目定位吻合
- **投稿策略:** DDL 紧迫（可能在 2026年8-9月），与 FC 2027 时间冲突。建议优先 FC

---

## 7. ISPEC — Information Security Practice and Experience

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | 各大学轮值, Springer LNCS |
| **投稿 DDL** | ISPEC 2027: 预计 2027年5月-6月 |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 12-18 页 |
| **审稿** | ~2-3 月, 录用率 ~30-35% |
| **主题偏好** | **安全实践与经验**——会议名直接表明偏好。密码学实现、安全系统 benchmark、部署经验、工业应用 |
| **特点** | CCF C 会议中**最明确接受"工程实践/系统实现"论文的 venue** |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐⭐** — 会议 DNA 是 "Practice and Experience"，项目的"首次完整实现+benchmark"天然适配
- **投稿策略:** 强调 implementation challenges 和 engineering lessons learned。ISPEC 审稿人不会要求新密码学定理

---

## 8. PST — International Conference on Privacy, Security and Trust

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **主办** | 各大学轮值, IEEE CPS |
| **投稿 DDL** | PST 2027: 预计 2027年4月-5月（8 月开会） |
| **投稿方式** | EasyChair 或 EDAS |
| **格式** | IEEE CPS 双栏, 8-12 页 |
| **审稿** | ~2-3 月, 录用率 ~32-38% |
| **主题偏好** | 隐私(P) + 安全(S) + 信任(T) 三者交集。盲签名是核心隐私原语，fit 度极高 |
| **特点** | 会议规模较小（~80 篇/年），录用率相对较高，审稿快 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐** — 隐私会议+盲签名=天然匹配。对工程实现友好
- **投稿策略:** 页数限制较紧（8-10pp IEEE），需要精简 Preliminaries 部分

---

## 9. SAC — Selected Areas in Cryptography

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议（加拿大举办） |
| **CCF 等级** | 无（未被 CCF 收录，但密码学圈内声望 ≈ CCF B-C 之间） |
| **主办** | 加拿大各大学轮值, Springer LNCS |
| **投稿 DDL** | SAC 2027: 预计 2027年5月 |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 12-20 页 |
| **审稿** | ~3 月, 录用率 ~25-30% |
| **主题偏好** | 密码学的 selected areas——每年有不同的主题 focus。2020-2025 届涵盖了：后量子密码学、密码学实现、隐私增强技术、区块链密码学 |
| **为什么列入此列表** | SAC 虽未被 CCF 收录，但它是 IACR (International Association for Cryptologic Research) 相关会议，密码学家参会频繁。如果你的目标是"密码学圈内声望"而非"CCF 点数"，SAC 是优质选择 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐**
- **投稿策略:** 关注 SAC 每年的 CFP 主题。如果当年有 "Post-Quantum Cryptography" 或 "Privacy-Enhancing Cryptography" theme，匹配度可达 5 星

---

## 10. ARES — International Conference on Availability, Reliability and Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议（欧洲举办，通常奥地利） |
| **CCF 等级** | C |
| **主办** | SBA Research 等, ACM 出版 |
| **投稿 DDL** | ARES 2027: 预计 2027年3月-4月（8 月开会） |
| **投稿方式** | EasyChair |
| **格式** | ACM 双栏, 8-12 页 |
| **审稿** | ~2-3 月, 录用率 ~30-35% |
| **主题偏好** | 安全、可用性、可靠性的交叉。密码学实现适合投 "Security" track |
| **特点** | 欧洲会议，接收范围广，对应用密码学和系统安全论文友好 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐**
- **投稿策略:** ACM 格式（非 LNCS），需要转换模板。适合作为 CCF C 保底

---

## 11. IEEE ICBC — International Conference on Blockchain and Cryptocurrency

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | 无（IEEE ComSoc 主办，2021 年首届） |
| **投稿 DDL** | ICBC 2027: 预计 2027年1月（5 月开会） |
| **投稿方式** | EDAS |
| **格式** | IEEE CPS 双栏, 8-10 页 |
| **审稿** | ~2-3 月, 录用率 ~30-40% |
| **主题偏好** | 区块链系统和协议；加密货币；智能合约安全；ZK 证明在区块链中的应用；DeFi 安全 |

### 曾接收的 ZKP 相关论文
1. **"ZGridBC: Zero-Knowledge Proof based Scalable and Private Blockchain Platform"** (IEEE ICBC 2021) — DOI: 10.1109/icbc51069.2021.9461122
2. **"Auditable Privacy: A Purpose Bound Money Protocol via ZKP"** (IEEE ICBC 2026) — DOI: 10.1109/icbc67748.2026.11575482
3. **"Location-aware Verification for Autonomous Truck Platooning Based on Blockchain and ZKP"** (IEEE ICBC 2021) — DOI: 10.1109/icbc51069.2021.9461116

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐** — ZKP+区块链主题对路但会议无 CCF 等级
- **投稿策略:** 非 CCF，适合作为快速发表选项；如需要 CCF 论文则不宜作为主投稿目标

---

## 12. IEEE Blockchain (International Conference on Blockchain)

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 |
| **投稿 DDL** | 预计 2027年3月-4月 |
| **投稿方式** | EDAS |
| **格式** | IEEE CPS, 8-10 页 |
| **审稿** | ~2-3 月, 录用率 ~30-38% |
| **曾接收 ZKP 论文:** "PRFX: A Privacy-Preserving Prefix Summation Protocol on Blockchain with ZKP" (2024) — DOI: 10.1109/blockchain62396.2024.00054; "Privacy-Preserving Energy Trading Using Blockchain and ZKP" (2022) — DOI: 10.1109/blockchain55522.2022.00064 |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐** — 同 ICBC，非 CCF

---

## 13. BRAINS — Conference on Blockchain Research & Applications

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | 无 |
| **投稿 DDL** | 预计 2027年5月-6月 |
| **格式** | IEEE, 8-10 页 |
| **审稿** | ~2-3 月, 录用率 ~35-40% |
| **匹配度: ⭐⭐** — 纯保底选项 |

---

## 14. 《密码学报》 — Journal of Cryptologic Research

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 中文学术期刊 |
| **CCF 等级** | B（中文密码学领域最高级别期刊） |
| **主办方** | 中国密码学会 |
| **频率** | 双月刊（每两个月一期） |
| **投稿 DDL** | **滚动接受**（rolling submission），无固定 DDL |
| **投稿方式** | 中国密码学会投稿系统: http://www.jcr.cacrnet.org.cn/ |
| **格式要求** | 中文 LaTeX 或 Word；~15-20 页；摘要须中英文双语 |
| **审稿周期** | 6-12 个月；通常经历 1 轮 major revision |
| **录用率** | ~30-35% |
| **出版** | 纸质+中国知网(CNKI)。**非 EI/SCI 收录**（这是主要劣势——国际可见性低） |
| **主题偏好** | 密码学理论：可证明安全、新密码原语；应用密码学：国密算法、密码协议实现；后量子密码学（近年热门 topic）；密码学与区块链交叉 |
| **结构偏好** | 中文科技论文标准结构：引言→预备知识→方案设计→安全性分析→实验与性能评估→结论 |
| **篇幅** | 15-18 页中文正文 |

### 曾接收的相似论文（直接证据）
1. **孙思维等, "SPHINCS+-SM3: 基于SM3的无状态数字签名算法"** (2023, Vol.10, No.6, pp.1266-1278)
   - 主要贡献: 首次用 SM3 实例化 SPHINCS+ 的 THF（与本项目 Poseidon2 实例化属**同类型贡献**）
   - 实验: 参数搜索 + 签名大小对比
   - **与本项目对比:** 该文贡献度（替换哈希+参数分析）低于本项目（替换哈希+Fischlin编译+STARK实现+benchmark），已成功发表
   - **结论:** 项目投《密码学报》有**极大概率被接收**

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐⭐** — 有 SPHINCS+-SM3 直接先例
- **优势:** CCF B > CCF C；中文母语写作无语言障碍；审稿人对 SPHINCS+ 话题熟悉
- **劣势:** 审稿周期长（6-12月）；非 EI 索引国际可见性低
- **投稿策略:** 需增加 "与国密 SM3/SM4 适配" 的讨论段落（国内审稿人重视）；可引用 SPHINCS+-SM3 作为延续性工作

---

## 15. Inscrypt — International Conference on Information Security and Cryptology

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议（在中国举办） |
| **CCF 等级** | C |
| **主办方** | 中国密码学会(CACR)承办，Springer 出版 |
| **投稿 DDL** | Inscrypt 2027: 预计 2027年6月-7月（11-12月开会） |
| **投稿方式** | EasyChair; CFP 在中国密码学会官网发布 |
| **格式要求** | Springer LNCS；12-20 页；英文撰写 |
| **审稿周期** | ~3-4 月 |
| **录用率** | ~30-35% |
| **出版** | LNCS, EI/CPCI-S 收录 |
| **主题偏好** | 密码学理论与应用；后量子密码学；系统与实现；区块链安全与隐私；零知识证明；隐私保护技术 |
| **结构偏好** | 标准 LNCS 会议论文；支持附录放额外证明和数据 |
| **特点** | CCF C + 国内举办 + LNCS 索引 + 竞争温和——**性价比最高的 CCF C 投稿** |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐⭐**
- **核心优势:** (1) CCF C 可以用于学位要求，(2) LNCS 出版保证国际可见性，(3) 在国内举办节省差旅，(4) 中国密码学会承办意味着审稿人大概率是国内学者，(5) 与 FC 相比竞争低得多
- **投稿策略:** 英文版稿件直接投递，无需翻译；可以强调与中国密码学社区的关联（国密适配讨论）

---

## 16. ProvSec — International Conference on Provable and Practical Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国际学术会议 |
| **CCF 等级** | C |
| **投稿 DDL** | ProvSec 2027: 预计 2027年6月-7月 |
| **投稿方式** | EasyChair |
| **格式** | LNCS, 12-18 页 |
| **审稿** | ~2-3 月, 录用率 ~30-35% |
| **主题偏好** | 可证明安全 + 实用安全的交叉——会议名中的 "Provable and Practical" 恰好是本项目的定位：有理论归约（provable via THF reduction）也有实践实现（practical via STARK benchmark） |

### 匹配度与投稿策略
- **匹配度: ⭐⭐⭐⭐** — "Provable + Practical" 是项目 DNA
- **投稿策略:** 强调项目的 duality：安全性有THF归约链（provable），效率有37s prove time benchmark（practical）

---

## 17. ChinaCrypt — 中国密码学会年会

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 国内学术会议 |
| **CCF 等级** | 无（国内密码学最高级别会议） |
| **主办** | 中国密码学会 |
| **投稿 DDL** | ChinaCrypt 2026: 通常在 7-8 月（10-11月开会） |
| **投稿方式** | 中国密码学会官网投稿系统 |
| **格式** | 中文/英文, 8-12 页 |
| **审稿** | ~1-2 月, 录用率 ~40-50% |
| **价值定位** | 非 CCF 会议，**核心价值在学术社交**。参会可以认识《密码学报》编委、国内密码学团队 PI |
| **匹配度: ⭐⭐⭐（社交价值）** |

---

## 18. 《信息安全学报》 — Journal of Information Security

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 中文学术期刊 |
| **CCF 等级** | 无（中国科学院主办的新刊，2018年创刊） |
| **投稿方式** | 在线投稿系统 |
| **格式** | 中文, 12-18 页 |
| **审稿周期** | 3-9 月（比《密码学报》快） |
| **特点** | 对工程实现类论文容忍度高；后量子安全是常设栏目 |
| **匹配度: ⭐⭐⭐** — 时间敏感时优于《密码学报》 |

---

## 19. IEEE Access

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 开源期刊（OA Journal） |
| **CCF 等级** | 无 |
| **投稿 DDL** | 滚动接受 |
| **投稿方式** | ScholarOne Manuscripts |
| **格式** | IEEE 双栏, 无固定页数限制 |
| **审稿** | 1-3 月（非常快）, 录用率 ~35-40% |
| **版面费** | $1,950 USD |
| **特点** | 快速出版，但 OA 期刊在学术界评价一般（部分高校不认可为学术成果） |
| **匹配度: ⭐** — 仅作最后保底 |

---

## 20. IACR ePrint Archive

### 基本信息
| 维度 | 内容 |
|------|------|
| **类型** | 密码学预印本服务器 |
| **CCF 等级** | 无（非正式出版） |
| **投稿 DDL** | 随时 |
| **投稿方式** | https://eprint.iacr.org/ 直接上传 |
| **格式** | PDF, 任意格式 |
| **作用** | 确立时间优先权 + 获取社区反馈 + 增加论文可见性 |
| **策略** | 在正式投稿到会议/期刊前 1-2 周先传 ePrint。审稿期间论文已经公开被引用，增加影响力 |

---

## 综合推荐排序

| 排序 | Venue | 类型 | CCF | DDL(预估) | 匹配度 | 核心理由 |
|------|-------|------|-----|-----------|--------|---------|
| **1** | **FC 2027** | 会议 | C | 2026年9月 | ⭐⭐⭐⭐⭐ | 金融密码学+区块链，最接受系统类论文 |
| **2** | **Inscrypt 2027** | 会议 | C | 2027年6-7月 | ⭐⭐⭐⭐⭐ | CCF C+LNCS+国内举办+温和竞争 |
| **3** | **CANS 2027** | 会议 | C | 2027年5-6月 | ⭐⭐⭐⭐⭐ | 密码学+网络安全交叉 |
| **4** | **ISPEC 2027** | 会议 | C | 2027年5-6月 | ⭐⭐⭐⭐⭐ | "Practice and Experience" 天然适配 |
| **5** | **《密码学报》** | 期刊 | B | Rolling | ⭐⭐⭐⭐⭐ | SPHINCS+-SM3先例+CCF B |
| **6** | CT-RSA 2027 | 会议 | C | 2026年8-9月 | ⭐⭐⭐⭐ | 密码学实践导向，DDL紧迫 |
| **7** | ACISP 2027 | 会议 | C | 2027年2-3月 | ⭐⭐⭐⭐ | 后量子 track，竞争温和 |
| **8** | PST 2027 | 会议 | C | 2027年4-5月 | ⭐⭐⭐⭐ | 隐私会议，审稿快 |
| **9** | ProvSec 2027 | 会议 | C | 2027年6-7月 | ⭐⭐⭐⭐ | "Provable+Practical" DNA匹配 |
| **10** | SAC 2027 | 会议 | - | 2027年5月 | ⭐⭐⭐⭐ | 密码学圈内声望好 |
| **11** | ESORICS 2027 | 会议 | B | 2027年3-4月 | ⭐⭐⭐ | 冲刺 CCF B |
| **12** | ACNS 2027 | 会议 | B | 2027年1月 | ⭐⭐⭐ | 冲刺 CCF B |
| **13** | IEEE ICBC | 会议 | - | 2027年1月 | ⭐⭐⭐ | 区块链会但无CCF |
| **14** | ChinaCrypt | 会议 | - | 7-8月 | ⭐⭐⭐ | 社交价值高于出版价值 |
| **15** | IEEE Blockchain | 会议 | - | 3-4月 | ⭐⭐⭐ | 同ICBC |
| **16** | ARES 2027 | 会议 | C | 3-4月 | ⭐⭐⭐ | CCF C备选 |
| **17** | 《信息安全学报》 | 期刊 | - | Rolling | ⭐⭐⭐ | 审稿快的中文保底 |
| **18** | BRAINS | 会议 | - | 5-6月 | ⭐⭐ | 纯保底 |
| **19** | IEEE Access | 期刊 | - | Rolling | ⭐ | 最后保底+版面费 |
| **20** | IACR ePrint | 预印本 | - | 随时 | ⭐ | 优先占位 |

### 最佳投稿时间线

```
2026年Q3-Q4 (当前)
  ├── ePrint: 即刻上传 (占位)                     ★ 立即执行
  ├── CT-RSA 2027 DDL: ~2026年8-9月               ★ 备选
  └── FC 2027 DDL: ~2026年9月                      ★★ 首选
       │
       ├── 12月通知: Accept → 结束
       └── Reject → 准备下一轮
       
2027年Q1-Q2
  ├── ACNS DDL: ~1月
  ├── ACISP DDL: ~2-3月
  ├── ESORICS DDL: ~3-4月
  ├── PST DDL: ~4-5月
  ├── SAC DDL: ~5月
  ├── CANS DDL: ~5-6月
  ├── ISPEC DDL: ~5-6月
  └── Inscrypt DDL: ~6-7月                       ★★ 首选备选

长期并行:
  └── 《密码学报》: Rolling, 可同时投稿中文版
```

---

*本文件基于 2026年7月22日可查信息。DDL 为基于历年模式的推算值，具体以各会议公布 CFP 为准。*
