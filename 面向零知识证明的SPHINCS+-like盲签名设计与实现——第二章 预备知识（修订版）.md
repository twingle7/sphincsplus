# 第二章 预备知识

本章系统介绍后续章节所需的密码学基础知识，内容涵盖哈希函数的密码学定义与安全属性、可调哈希函数（Tweakable Hash Functions）、随机预言机模型（ROM）与量子随机预言机模型（QROM）、SPHINCS+签名框架的层次化结构、Poseidon2零知识友好哈希函数的设计原理、零知识证明系统（以STARK为核心），以及盲签名方案的形式化定义与Fischlin通用构造框架。

说明：本章行文中，凡已在第一章参考文献列表中出现的文献，均直接沿用第一章编号（【1】–【31】）；本章新增文献从【32】起顺序编号。

***

## 2.1 哈希函数的密码学定义

### 2.1.1 哈希函数的基本概念

哈希函数（Hash Function）是现代密码学的基础原语之一。一个密码学哈希函数 \(\mathcal{H}\) 是从任意长度（或固定长度）的二进制字符串到固定长度输出的映射，通常表示为：

\[
\mathcal{H} : \{0,1\}^* \to \{0,1\}^n
\]

其中 \(n\) 为输出位长度，称为摘要长度。密码学哈希函数的安全性通常由三类核心安全属性刻画【32】：

- **单向性（One-Wayness / Preimage Resistance）**：对于均匀随机选取的输出 \(y = \mathcal{H}(x)\)，任意概率多项式时间（PPT）对手 \(\mathcal{A}\) 在不知道 \(x\) 的情况下，找到任意 \(x'\) 使得 \(\mathcal{H}(x') = y\) 的概率均为可忽略量（negligible）。
- **抗碰撞性（Collision Resistance）**：任意 PPT 对手找到满足 \(\mathcal{H}(x_1) = \mathcal{H}(x_2)\) 且 \(x_1 \neq x_2\) 的一对 \((x_1, x_2)\) 的概率均为可忽略量。
- **抗第二原像性（Second Preimage Resistance）**：给定任意输入 \(x\)，任意 PPT 对手找到 \(x' \neq x\) 使得 \(\mathcal{H}(x') = \mathcal{H}(x)\) 的概率均为可忽略量。

以上三种安全属性在强度上满足如下蕴含关系：抗碰撞性强于抗第二原像性，抗第二原像性强于单向性。本文所涉及的 SPHINCS+ 构造中，哈希函数安全归约所依赖的具体属性将在各组件分析时说明。

### 2.1.2 量子环境下的哈希安全属性

在量子计算环境下，哈希函数的安全边界需要相应调整。Grover算法可以对大小为 \(N\) 的搜索空间实现 \(O(\sqrt{N})\) 查询复杂度的量子加速【2】，其对哈希函数的主要影响如下：针对单向性的暴力搜索攻击从经典 \(O(2^n)\) 降至量子 \(O(2^{n/2})\)，对抗碰撞性的生日攻击复杂度亦相应下降。为在后量子环境下保持 \(\lambda\) 位安全级别，哈希函数输出长度至少需设置为 \(2\lambda\) 位（针对单向性）。此外，Hülsing、Rijneveld与Song在研究多目标哈希安全属性时【33】，引入了多目标第二原像抵抗（MT-SPR）与多目标单向性（MT-OW）等概念，为哈希基签名在多用户/多签名场景下的量子安全分析提供了精确的复杂度估计工具。

***

## 2.2 可调哈希函数

### 2.2.1 定义

可调哈希函数（Tweakable Hash Function，THF）是SPHINCS+框架的核心抽象工具，由Bernstein等人在SPHINCS+论文中正式引入【8】。其形式化定义如下：

设 \(\mathcal{P}\)、\(\mathcal{T}\)、\(\mathcal{M}\) 与 \(\mathcal{MD}\) 分别为公共参数空间、调整值（Tweak）空间、消息空间与摘要空间。一个可调哈希函数族 \(\mathbf{Th}\) 为一映射族：

\[
\mathbf{Th} : \mathcal{P} \times \mathcal{T} \times \mathcal{M} \to \mathcal{MD}
\]

其中 \(P \in \mathcal{P}\) 为每密钥对绑定一次的公共种子，\(T \in \mathcal{T}\) 为调整值（每次哈希调用唯一），\(M \in \mathcal{M}\) 为输入消息。

### 2.2.2 安全属性

在 SPHINCS+ 的安全分析中，可调哈希函数主要通过以下两类性质进行刻画【8】：

- **pq-sm-tcr for distinct tweaks**：即后量子、单函数、多目标、针对不同 tweak 的目标碰撞抗性。该性质要求攻击者即使面对同一公共参数下的多个目标实例，也难以针对某个给定的、互不重复的 tweak 构造满足条件的目标碰撞。【8】

- **pq-sm-dspr for distinct tweaks**：即后量子、单函数、多目标、针对不同 tweak 的判定式第二原像抗性。该性质关注的是在多目标场景下，攻击者区分或构造有效第二原像的能力应当是可忽略的。【8】

这两类性质共同构成了 SPHINCS+ 中可调哈希函数安全分析的基础。通过在公共种子之外引入 tweak 参数，SPHINCS+ 能够将 WOTS+、FORS 与 hypertree 中不同层次的哈希调用统一到同一分析框架之下，从而支持模块化的安全归约证明。【8】

***

## 2.3 随机预言机模型与量子随机预言机模型

### 2.3.1 随机预言机模型（ROM）

随机预言机模型（Random Oracle Model，ROM）由 Bellare 与 Rogaway 于 1993 年提出【34】。在该模型中，哈希函数 \(\mathcal{H}\) 被理想化为一个公共可访问的随机预言机：对于每个首次出现的输入，预言机独立且均匀地返回一个固定长度的随机输出；对于重复输入，则始终返回此前给定的同一结果。

ROM 为密码方案的可证明安全分析提供了强有力的工具。在安全归约中，证明者通常可以通过“编程”随机预言机的回答，将底层困难问题实例嵌入到对手可见的交互过程中，从而构造出从破坏密码方案到求解基础困难问题的归约证明【34】。

ROM 的根本局限在于其理想化假设。现实系统中实际部署的是具体哈希函数，而非真正的随机预言机；因此，标准模型下确实存在这样的反例：某些方案在 ROM 中可证明安全，但在将预言机实例化为具体哈希函数后却不再安全【34】。尽管如此，ROM 由于能够在较强效率与较清晰证明结构之间取得平衡，仍然是现代密码学中最常用的安全证明模型之一【34】。


### 2.3.2 量子随机预言机模型（QROM）

在后量子安全分析中，传统 ROM 还不足以完整刻画量子对手的能力，因此需要引入量子随机预言机模型（Quantum Random Oracle Model，QROM）【35】。Boneh、Dagdelen、Fischlin、Lehmann、Schaffner 与 Zhandry 在 ASIACRYPT 2011 中系统讨论了这一模型【35】。与 ROM 不同，QROM 允许对手以量子叠加态形式访问随机预言机，即对手可以对输入的叠加态发起查询，并获得相应的叠加态输出，而不必退化为某一次经典查询。

这一差异使得许多经典归约技术在 QROM 中不再能够直接使用。特别是，传统 ROM 证明中常见的回溯、查询记录与条件重编程等方法，在面对量子叠加查询时会受到量子测量扰动的限制，因此必须发展专门的量子归约技术【35】。

SPHINCS+ 的安全分析正是在这一背景下展开的。其安全证明需要在 QROM 中对底层哈希相关原语进行统一建模，并借助抗量子的可调哈希安全性质来支撑整体归约【33】。此外，Barbosa 等人的形式化验证工作进一步在 EasyCrypt 证明助手中对 SPHINCS+ 的相关量子安全归约进行了机器化验证【9】。

## 2.4 SPHINCS+签名框架

SPHINCS+是一个无状态哈希基数字签名框架，由Bernstein、Hülsing、Kölbl、Niederhagen、Rijneveld与Schwabe于2019年发表【8】，并被NIST标准化为FIPS 205（SLH-DSA）【5】。其整体安全性归约至底层哈希函数的可调哈希安全属性，无需依赖任何代数困难性假设。

### 2.4.1 WOTS+：一次签名方案

WOTS+（Winternitz One-Time Signature Plus）由Hülsing于AFRICACRYPT 2013提出【36】，是SPHINCS+的基础签名原语。设安全参数为 \(n\)，Winternitz参数为 \(w\)，WOTS+私钥由 \(\ell = \ell_1 + \ell_2\) 个 \(n\) 字节随机值组成，其中：

\[
\ell_1 = \left\lceil \frac{8n}{\log_2 w} \right\rceil, \quad \ell_2 = \left\lfloor \frac{\log_2(\ell_1(w-1))}{\log_2 w} \right\rfloor + 1
\]

公钥通过对私钥链式应用哈希函数 \(w-1\) 次计算得到：

\[
\mathrm{pk}_i = \mathcal{H}^{w-1}(\mathrm{sk}_i), \quad i = 1, \dots, \ell
\]

对消息摘要 \(M\) 进行编码后，签名通过对每个私钥值应用 \(b_i\) 次哈希函数生成（\(b_i\) 由消息各分组值决定），验证者则通过补充剩余的哈希迭代将签名恢复为公钥。WOTS+的安全性在标准模型下被严格证明等价于底层哈希函数的抗第二原像性，并具有精确而紧致的安全归约【36】。由于WOTS+是一次性方案，SPHINCS+通过上层树状结构实现对WOTS+的托管与安全重用。

### 2.4.2 FORS：少次签名方案

FORS（Forest Of Random Subsets）是SPHINCS+中用于签名消息摘要前 \(ka\) 位的少次签名（Few-Time Signature，FTS）方案，是SPHINCS+区别于其前身SPHINCS的关键新组件【8】。FORS由 \(k\) 棵高度为 \(a\) 的二叉Merkle树组成，每棵树有 \(t = 2^a\) 个叶节点，叶节点值由秘密种子 \(\mathrm{SK.seed}\) 通过伪随机函数派生。

对一个 \(ka\) 位的消息进行签名时，将消息分为 \(k\) 段，每段值 \(v_i\)（\(0 \le v_i < t\)）对应第 \(i\) 棵树中揭露叶节点 \(\mathrm{sk}[i][v_i]\) 与其到根节点的认证路径（Authentication Path）。公钥为 \(k\) 棵树根节点的哈希串联值。相比SPHINCS中使用的HORST方案，FORS通过调整 \(k\) 与 \(t\) 的参数约束，可在指数级降低签名次数预算 \(q\) 时保持可证明的安全级别，从而使SPHINCS+的签名次数上限达到 \(2^{64}\)【8】。

### 2.4.3 超树（HyperTree）结构

SPHINCS+通过 \(d\) 层XMSS树（每层 \(h/d\) 高度）的层次化组合构成超树（HyperTree），总树高为 \(h\)，对应 \(2^h\) 个潜在的FORS密钥对索引【8】。

具体层次结构如下：

- **第 \(d\) 层（最顶层）**：包含一棵高度为 \(h/d\) 的XMSS树，根节点哈希即为SPHINCS+的公钥 \(\mathrm{PK}\)。
- **第 \(1\) 至 \(d-1\) 层**：每层包含若干棵高度为 \(h/d\) 的XMSS树，上层XMSS树的叶节点值等于下层对应XMSS树根节点的WOTS+签名。
- **第 \(0\) 层（最底层）**：每个叶节点对应一个FORS密钥对。

SPHINCS+完整签名由随机化值 \(R\)、FORS签名 \(\sigma_{\text{FORS}}\)、以及 \(d\) 层XMSS签名 \((\sigma_{\text{XMSS}}^{(1)}, \dots, \sigma_{\text{XMSS}}^{(d)})\) 串联组成。参数集以安全级别 \(n\)、树高 \(h\)、层数 \(d\)、FORS参数 \((k, a)\)、Winternitz参数 \(w\) 共同决定签名尺寸与性能特征。

***

## 2.5 Poseidon2零知识友好哈希函数

### 2.5.1 设计背景

传统密码学哈希函数（如SHA-256、SHAKE-256）的内部结构在表示为算术电路（R1CS、PLONK约束系统等）时产生极高的约束数量。例如，SHA-256的单次压缩在R1CS中约产生27,000至30,000个约束，导致零知识证明的证明生成开销随哈希调用次数线性增长【22】。这使得将SPHINCS+等哈希密集型方案纳入ZK证明电路在实践中极为困难，是后量子签名与零知识证明融合的核心瓶颈。

为此，学界开发了专为有限域上算术运算设计的算术化友好哈希函数（Arithmetization-Friendly Hash Function）。Poseidon由Grassi等人于2021年USENIX Security发表【23】，基于HADES（Half-And-roundS with aDd-round-key, mix-layer, Equation-based sBoxes）置换框架，在素数域 \(\mathbb{F}_p\) 上原生操作。Poseidon2由Grassi、Khovratovich与Schofnegger于AFRICACRYPT 2023进一步提出【24】，在Poseidon基础上对线性层进行重新设计，显著降低了约束密度，成为目前性能最优的算术化友好哈希函数之一。

### 2.5.2 Poseidon2 的构造

Poseidon2 是一种面向算术化约束系统优化设计的哈希原语，其内部置换延续了 HADES 设计思想，整体结构由前半段全轮、中间部分轮和后半段全轮三部分组成。设状态宽度为 \(t\)，全轮轮数为 \(R_F\)，部分轮轮数为 \(R_P\)，S 盒函数为幂映射 \(x \mapsto x^d\)，其中 \(d\) 通常取 5 或 7，且满足 \(\gcd(d,p-1)=1\)【24】。则其置换结构可表示为：先执行 \(R_F/2\) 轮全轮，再执行 \(R_P\) 轮部分轮，最后执行 \(R_F/2\) 轮全轮【24】。

Poseidon2 的核心优化体现在置换内部线性层的重新设计。与原始 Poseidon 在各轮中使用稠密 MDS 矩阵不同，Poseidon2 分别为外部轮与内部轮引入了更适于高效实现的结构化线性层，以降低矩阵乘法带来的运算与约束开销【24】。其中，外部轮使用结构化矩阵 \(M_E\)，内部轮使用“对角矩阵加低秩修正”的矩阵 \(M_I\)，从而使线性层能够在线性复杂度下实现【24】。此外，Poseidon2 在置换起始位置增加了一次额外线性层，并对内部轮常数注入方式进行了简化，以进一步改善整体实现效率【24】。

得益于上述设计，Poseidon2 在线性层相关运算中显著减少了乘法次数与电路约束数量。文献给出的结果表明，在 Plonk 等约束系统中，Poseidon2 的线性层约束数相较于 Poseidon 最多可降低约 70%，乘法次数最多可降低约 90%【24】。因此，Poseidon2 特别适合用于零知识证明场景下的哈希计算，并可按海绵（sponge）模式处理可变长度输入，也可按压缩函数（compression function）模式处理固定长度输入【24】。


### 2.5.3 安全性

Poseidon2 的安全性分析主要围绕代数攻击与经典密码分析方法展开，包括 Gröbner 基攻击、XL 类攻击、插值攻击，以及差分分析和线性分析等【24】。其参数设置目标是在保持较低算术复杂度的同时，使上述攻击在给定安全级别下的复杂度仍然足够高，从而满足单向性、抗碰撞性及置换安全性的要求【24】。

在构造层面，Poseidon2 的海绵模式与压缩函数模式均建立在其底层置换安全性的基础之上【24】。当所选参数能够抵抗已知的代数与统计分析方法时，基于该置换构造的哈希函数即可在相应模型下提供预期的安全保证【24】。因此，Poseidon2 的安全性应结合具体状态宽度、轮数配置、S 盒指数及底层有限域参数进行整体评估，而不能脱离具体实例单独讨论【24】。

当 Poseidon2 被用于替换 SPHINCS+ 中的原始哈希原语时，其安全性要求不仅限于一般意义下的抗碰撞性与单向性【24】。由于 SPHINCS+ 的安全证明依赖于底层哈希在可调哈希框架下满足相应的多目标安全性质，因此 Poseidon2 的具体实例化还需进一步验证其是否能够支撑 SPHINCS+ 所要求的可调哈希安全属性【24】。本文第三章将在具体参数设定下对这一问题作进一步分析【24】。

## 2.6 零知识证明系统

### 2.6.1 基本定义

零知识证明系统（Zero-Knowledge Proof System）的概念由Goldwasser、Micali与Rackoff于1989年发表的奠基性工作正式确立【37】。形式上，对于一个语言 \(L \in \mathrm{NP}\)（其关系为 \(\mathcal{R}_L\)），一个交互式证明系统 \((P, V)\) 是关于 \(L\) 的零知识证明，当且仅当以下三个属性同时成立：

- **完备性（Completeness）**：对任意 \((x, w) \in \mathcal{R}_L\)，诚实证明者 \(P(x, w)\) 与验证者 \(V(x)\) 交互后，验证者以压倒性概率接受。
- **可靠性（Soundness）**：对任意 \(x \notin L\) 与任意恶意证明者 \(P^*\)，验证者接受的概率为可忽略量。
- **零知识性（Zero-Knowledgeness）**：存在概率多项式时间模拟器 \(\mathcal{S}\)，对任意 \((x, w) \in \mathcal{R}_L\) 与任意验证者 \(V^*\)，\(\mathcal{S}(x)\) 生成的视图与真实交互视图在计算上不可区分。

若可靠性满足更强的**知识可靠性（Knowledge Soundness）**——存在知识提取器（Knowledge Extractor）能够从接受的证明中高效提取出有效见证 \(w\)——则该系统称为**知识的证明（Proof of Knowledge，PoK）**；若其为非交互式，则称为**非交互式零知识知识证明（NIZK PoK）**。

### 2.6.2 STARK系统

STARK（Scalable Transparent Argument of Knowledge）由Ben-Sasson、Bentov、Horesh与Riabzev于2019年CRYPTO正式发表【38】，是目前最重要的后量子零知识证明系统之一，其安全性完全基于哈希函数的抗碰撞性，不依赖任何代数困难性假设。STARK的核心技术组件如下：

**（1）算术中间表示（AIR）**：待证计算被表示为一张由满足递推约束的轨迹多项式组成的有限域表格，每一列对应计算中的一个变量，每一行对应一个时钟周期，相邻行之间由低次多项式约束关联。

**（2）FRI协议（Fast Reed-Solomon IOP of Proximity）**：STARK的核心多项式承诺与低度检验协议，由同一团队于ICALP 2018提出【39】，通过交互折叠（Folding）将低度多项式的成员测试归约为更小规模的低度检验，实现了严格线性的证明者复杂度与严格对数的验证者复杂度。STARK通过Fiat-Shamir变换将基于FRI的交互式证明转化为非交互式论证。

**（3）后量子安全性与透明性**：STARK无需可信初始化（Trusted Setup），避免了"有毒废料（Toxic Waste）"问题；其安全性完全基于哈希函数的标准密码学假设，在量子计算模型下依然安全【38】，相比基于配对的zkSNARK（如Groth16）在后量子语境下具有本质优势。STARK的主要权衡在于证明尺寸相对较大（通常为数十至数百KB），而证明生成时间与验证时间均呈准线性规模关系。

在本文所构造的盲签名方案中，STARK作为NIZK PoK的实例化选择，用于证明签名者知晓合法的SPHINCS+签名与对应承诺的随机性，是实现盲化性质的关键技术手段。

***

## 2.7 盲签名方案与Fischlin框架

### 2.7.1 盲签名的定义与安全模型

盲签名（Blind Signature）由Chaum于1982年提出【40】，作为实现不可追踪电子支付系统的密码原语。盲签名方案允许用户（请求者）获得签名者对某消息 \(m\) 的有效签名，而签名者在整个协议执行过程中无法获知消息 \(m\) 的任何信息。

形式上，一个盲签名方案 \(\Pi_{\mathrm{BS}} = (\mathrm{KeyGen}, \langle U, S \rangle, \mathrm{Verify})\) 包含三类算法：
- \(\mathrm{KeyGen}(1^\lambda) \to (\mathrm{pk}, \mathrm{sk})\)：密钥生成算法，生成签名者的公私钥对。
- \(\langle U(m, \mathrm{pk}), S(\mathrm{sk}) \rangle\)：用户与签名者之间的两方交互协议，协议结束后用户获得签名 \(\sigma\)，签名者无输出。
- \(\mathrm{Verify}(\mathrm{pk}, m, \sigma) \to \{0,1\}\)：验证算法。

盲签名方案的安全模型包含以下两项核心安全属性【29】：

- **一次多伪造不可伪造性（One-More Unforgeability）**：任意 PPT 对手即便在与签名者完成至多 \(q\) 次盲签协议交互后，也无法产生 \(q+1\) 个有效签名-消息对，即对手无法利用已有交互获得"额外"的有效签名。
- **盲化性（Blindness）**：签名者在交互结束后无法将所签署的签名与某次具体的签名协议执行实例相关联，即签名者视角下的交互记录与最终揭露的消息-签名对之间是不可区分的。

### 2.7.2 Fischlin盲签名构造框架

Fischlin于2006年CRYPTO提出了一种基于公共参考串（Common Reference String，CRS）模型的轮最优可组合盲签名通用构造【29】。该框架通过将任意数字签名方案与非交互式零知识知识证明（NIZK PoK）相结合，构造出在并发设定（Concurrent Setting）下具有可组合安全性的盲签名，无需依赖底层签名方案具有特殊代数结构，使其天然适用于SPHINCS+等哈希基签名方案。

Fischlin框架的协议流程如下：

**（1）盲化阶段**：用户选取随机性 \(r\)，以承诺方案 \(\mathrm{Com}\) 对消息 \(m\) 作出承诺 \(c = \mathrm{Com}(m; r)\)，并将承诺值 \(c\) 发送至签名者。

**（2）签名阶段**：签名者对承诺值 \(c\) 以底层签名算法生成签名 \(\sigma' = \mathrm{Sign}(\mathrm{sk}, c)\)，并将 \(\sigma'\) 返回用户。

**（3）去盲化与证明生成**：用户在收到 \(\sigma'\) 后，首先验证 \(\sigma'\) 是否为对承诺值 \(c\) 的有效底层签名；若验证失败，则中止协议。 随后，用户计算密文 \(C \leftarrow E_{pk_E}(c \| \sigma')\)，并生成非交互式零知识证明 \(\pi\)，证明其知晓见证 \((r,\omega_2,c,\sigma')\)，使得 \(c=\mathrm{Com}(m;r)\)、\(C=E_{pk_E}(c\|\sigma';\omega_2)\)，且 \(\mathrm{Verify}(pk,c,\sigma')=1\)。最终输出的签名为 \(\Sigma=(C,\pi)\)。

**（4）验证**：验证者在输入消息 \(m\)、签名 \(\Sigma=(C,\pi)\)、公钥 \(pk\) 以及系统公共参数后，验证证明 \(\pi\) 是否有效，即检查其是否证明了存在某个承诺值 \(c\) 与签名 \(\sigma'\)，满足 \(c\) 是对 \(m\) 的承诺、\(C\) 是对 \((c,\sigma')\) 的加密，且 \(\sigma'\) 是对 \(c\) 的有效签名。验证者无需显式重构 \(c\)，也不依赖从证明中提取见证；只要 \(\pi\) 验证通过，即接受该签名，否则拒绝。

该框架在随机预言机模型下具有可证明的不可伪造性与盲化性【29】：其中不可伪造性归约至底层签名方案的选择消息攻击不可伪造性（EUF-CMA），盲化性归约至承诺方案的隐藏性以及NIZK证明系统的零知识性。将Poseidon2的算术化友好性与SPHINCS+的哈希基安全性相结合，借助STARK系统高效实例化所需的NIZK PoK，是本文盲签名构造方案的核心技术路线。

***

## 参考文献（第二章新增，编号接续第一章）

【32】 Katz, J., & Lindell, Y. (2020). *Introduction to Modern Cryptography* (3rd ed.). CRC Press / Chapman & Hall.

【33】 Hülsing, A., Rijneveld, J., & Song, F. (2016). Mitigating multi-target attacks in hash-based signatures. In C. Cheng, K. Chung, G. Persiano, & B. Yang (Eds.), *Public-Key Cryptography – PKC 2016, Lecture Notes in Computer Science*, vol. 9614 (pp. 387–416). Springer. https://doi.org/10.1007/978-3-662-49384-7_15

【34】 Bellare, M., & Rogaway, P. (1993). Random oracles are practical: A paradigm for designing efficient protocols. In *Proceedings of the 1st ACM Conference on Computer and Communications Security (CCS 1993)* (pp. 62–73). ACM. https://doi.org/10.1145/168588.168596

【35】 Boneh, D., Dagdelen, Ö., Fischlin, M., Lehmann, A., Schaffner, C., & Zhandry, M. (2011). Random oracles in a quantum world. In D. H. Lee & X. Wang (Eds.), *Advances in Cryptology – ASIACRYPT 2011, Lecture Notes in Computer Science*, vol. 7073 (pp. 41–69). Springer. https://doi.org/10.1007/978-3-642-25385-0_3

【36】 Hülsing, A. (2013). W-OTS+ – Shorter signatures for hash-based signature schemes. In A. Youssef, A. Nitaj, & A. E. Hassanien (Eds.), *Progress in Cryptology – AFRICACRYPT 2013, Lecture Notes in Computer Science*, vol. 7918 (pp. 173–188). Springer. https://doi.org/10.1007/978-3-642-38553-7_10

【37】 Goldwasser, S., Micali, S., & Rackoff, C. (1989). The knowledge complexity of interactive proof systems. *SIAM Journal on Computing*, *18*(1), 186–208. https://doi.org/10.1137/0218012

【38】 Ben-Sasson, E., Bentov, I., Horesh, Y., & Riabzev, M. (2019). Scalable zero knowledge with no trusted setup. In A. Boldyreva & D. Micciancio (Eds.), *Advances in Cryptology – CRYPTO 2019, Lecture Notes in Computer Science*, vol. 11694 (pp. 701–732). Springer. https://doi.org/10.1007/978-3-030-26954-8_23

【39】 Ben-Sasson, E., Bentov, I., Horesh, Y., & Riabzev, M. (2018). Fast Reed-Solomon interactive oracle proofs of proximity. In *Proceedings of the 45th International Colloquium on Automata, Languages, and Programming (ICALP 2018), Leibniz International Proceedings in Informatics (LIPIcs)*, vol. 107 (pp. 14:1–14:17). Schloss Dagstuhl. https://doi.org/10.4230/LIPIcs.ICALP.2018.14

【40】 Chaum, D. (1983). Blind signatures for untraceable payments. In D. Chaum, R. L. Rivest, & A. T. Sherman (Eds.), *Advances in Cryptology – Crypto 1982* (pp. 199–203). Springer. https://doi.org/10.1007/978-1-4757-0602-4_18