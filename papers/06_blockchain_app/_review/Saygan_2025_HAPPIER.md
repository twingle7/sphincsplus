# HAPPIER: Hash-Based, Aggregatable, Practical Post-quantum Signatures Implemented Efficiently with Risc0

**出处**: LightSec 2025, LNCS 16216, pp. 3-22
**作者**: Arda Saygan, Muhammed Said Gundogan, Atakan Arslan, Mehmet Emin Gonen (TUBITAK BILGEM, Bogazici University)

## 论点
结合XMSS哈希基签名与RISC0 ZK虚拟机，可以构造实用的可聚合后量子签名方案——签名体积2-3 MB但能在标准笔记本电脑上聚合最多2^16个签名，无需数百GB内存。

## 背景
PoS区块链（如以太坊信标链）大量依赖BLS签名聚合来压缩区块空间，但BLS不抗量子。现有后量子聚合签名替代方案（如基于格的方案）签名体积小（数百KB）但聚合时需数百GB内存，不具实用性。作者寻求在"聚合器的计算可行性"和"签名体积"之间的实际权衡。

## 技术路线
以XMSS（NIST标准的哈希基签名）为基础签名，将其验证逻辑编码为RISC0 ZK虚拟机的指令迹。通过递归SNARK（RISC0的continuations机制）批量证明多个XMSS验证的正确性。引入多级聚合（multi-level aggregation）架构，允许在网络上逐步聚合签名——这是首个实现多级聚合的后量子方案。每个签名约2-3 MB（包含ZK证明），但聚合时仅需标准笔记本硬件。

## 核心成果
1. 首个实现多级聚合的后量子签名方案，支持跨网络增量聚合。
2. 聚合2^16个XMSS签名仅需标准笔记本硬件（对比格基方案需数百GB RAM）。
3. 直接适用于PoS区块链的共识签名聚合场景。

## 与本项目关联
**方法论参考**: 与本项目同属"ZK+哈希基签名"技术族。HAPPIER用RISC0递归SNARK聚合XMSS，本项目用Winterfell STARK证明SPHINCS+验证迹，两者在证明系统和签名基上不同但共享结构思路。HAPPIER的多级聚合架构对区块链部署有参考价值。
