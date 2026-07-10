# Sphinx-in-the-Head: Group Signatures from Symmetric Primitives

**出处**: ACM Transactions on Privacy and Security (TOPS), Vol. 27, No. 1, pp. 11:1-35, 2024
**作者**: Liqun Chen, Changyu Dong, Christopher J. P. Newton, Yalan Wang

## 论点
通过设计SPHINCS+的MPC友好变体F-SPHINCS+，可以利用仅对称原语（哈希函数和对称加密）构造首个支持大规模动态群组的后量子群签名方案，无需任何代数结构假设。

## 背景
现有后量子群签名大多依赖格或同源等结构化代数假设，其安全性基于尚不成熟的计算难题。对称原语（哈希函数）的安全性经过长期验证，是更保守的后量子选择。但此前基于对称原语的群签名仅支持小规模静态群组，且无法实现不可陷害性（non-frameability）。作者将MPC-in-the-Head范式与SPHINCS+签名树结构相结合以突破此限制。

## 技术路线
修改SPHINCS+的FORS签名为M-FORS（MPC友好的FORS），优化布尔电路下的零知识验证效率。M-FORS以增加少量签名体积为代价，大幅降低MPCitH NIZK中的电路复杂度。群管理采用发行人（issuer）+追踪者（tracer）分离架构，防止单方面伪造签名。安全性证明基于完全动态群签名模型（Bootle等人，JoC 2020），满足匿名性、可追踪性、不可陷害性等全部安全属性。

## 核心成果
1. 首个仅用对称原语同时支持大规模群组（最高2^60成员）、完全动态成员管理和全部安全属性的群签名。
2. F-SPHINX+的MPC友好设计思路（修改FORS结构以适应ZK电路）可直接迁移至其他哈希基签名场景。

## 与本项目关联
**方法论参考**: F-SPHINCS+与本项目均对SPHINCS+进行改造以适配ZK证明。前者用MPCitH改FORStree结构，后者用STARK改验证迹编码，技术互补性明确。M-FORS/Merkle树的分层电路优化思路可借鉴。
