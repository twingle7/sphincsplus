# Sphinx-in-the-Head: Group Signatures from Symmetric Primitives

**出处**: ACM Transactions on Privacy and Security (TOPS), Vol. 27, pp. 1-35, 2024
**作者**: Liqun Chen, Changyu Dong, Christopher J. P. Newton, Yalan Wang

## 论点
提出基于对称原语（哈希函数）的后量子群签名方案，设计F-SPHINCS+——一种SPHINCS+的MPC友好变体，首次实现支持2^60规模动态群组的后量子群签名。

## 背景
群签名允许群成员匿名签名（可追踪），在隐私保护中有重要应用。现有群签名几乎全部基于配对或RSA，不具备后量子安全性。SPHINCS+作为后量子签名标准，其FORS组件需要改造才能在MPC中高效运行。

## 技术路线
- F-SPHINCS+：修改FORS组件使其适合MPC-in-the-Head（MPCitH）范式
- MPCitH NIZK：将签名验证电路分解为多方计算协议，模拟参与方生成群签名证明
- 动态群组：支持成员加入/撤销，最大2^60成员
- 安全性基于哈希函数的抗碰撞性（ROM/QROM）
- UC安全模型下的形式化安全证明

## 核心成果
- 第一个基于对称原语的后量子群签名（仅依赖哈希函数）
- F-SPHINCS+：SPHINCS+的MPC友好变体
- 支持2^60规模动态群组
- 签名大小：约数MB（与群大小相关）

## 与本项目关联
**直接竞争**: 与本项目共享"SPHINCS+ + ZKP"的核心范式。区别在于：(1) Sphinx用MPCitH，本项目用STARK，(2) Sphinx做群签名，本项目做盲签名，(3) F-SPHINCS+的MPC友好改造与本项目的Poseidon2友好改造是两条不同的ZK优化路线。Sphinx的方法可参考用于将本项目扩展到群签名场景。
