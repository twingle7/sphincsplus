# CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures

**出处**: ePrint 2025/061
**作者**: Thibauld Feneuil, Matthieu Rivain (CryptoExperts)

## 论点
通过SmallWood证明系统和面向算术化友好置换（Anemoi/Poseidon/Rescue-Prime/Griffin）的通用编译框架，可以在极弱假设（仅安全排列）下构造SNARK友好后量子签名，签名体积9.5-15.5 KB、约束仅24K-35K，比Loquat优4-6倍。

## 背景
现有SNARK友好签名方案（如Loquat）虽在约束效率上优于MPCitH方案，但签名体积仍偏大（约46 KB），且依赖Legendre PRF等非标准单向性假设。CAPSS的目标是降低假设强度（仅依赖算术化友好排列的安全性如Anemoi）并进一步提升紧凑性，同时使其签名框架能通用支持多种排列。

## 技术路线
提出CAPSS框架（Compilation of Arithmetic-oriented Permutation into SNARK-friendly Signature）：核心是将任意算术化友好单向置换（如Anemoi、Poseidon、Rescue-Prime等）通过"多项式承诺+零知识论证"两条路径编译为签名方案。关键技术是提出SmallWood证明系统——融合Ligero、Brakedown和阈值计算（TCitH）技术的哈希基多项式承诺方案，专为算术化友好函数的低约束验证优化。框架可实例化为聚合签名和匿名凭证。

## 核心成果
1. 128位安全级签名体积9.5-15.5 KB，R1CS约束24K-35K——比Loquat小4-6倍、约束少5-8倍。
2. 聚合签名可实现亚千字节级摊还签名大小；匿名凭证展示证明小于150 KB。
3. 框架通用性极强，支持多种算术化友好排列实例化。

## 与本项目关联
**直接竞争**: CAPSS与本项目均致力于"后量子签名对ZK证明系统友好化"。CAPSS在签名紧凑性（9.5 KB vs. 本项目的~95 KB STARK证明）方面显著领先，但其系统复杂度和假设安全性需进一步验证。本项目继承SPHINCS+的标准安全性。
