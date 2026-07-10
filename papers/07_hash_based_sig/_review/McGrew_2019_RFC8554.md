# Leighton-Micali Hash-Based Signatures (RFC 8554)

**出处**: IETF RFC 8554, 2019 (IRTF CFRG)
**作者**: David McGrew, Michael Curcio, Scott Fluhrer

## 论点
RFC 8554 规范了 LMS/HSS 有状态哈希签名方案，为后量子时代提供了基于纯哈希函数的实用数字签名标准，无需大整数数学运算即可实现高安全等级。

## 背景
随着量子计算对 RSA/ECDSA 的威胁日益显现，需要不依赖于大整数因式分解或离散对数假设的替代签名方案。Lamport、Diffie、Winternitz 和 Merkle 在 1979 年提出的哈希签名思想，经 Leighton 和 Micali（1995 年）的改进，形成了 LMS 的基础。IRTF CFRG 推动将其标准化为 RFC，使业界获得一个经过充分审查、可互操作的后量子签名方案。

## 技术路线
LMS/HSS 由两层构成：底层是 LM-OTS 一次性签名（Winternitz 类型），上层是 Merkle 树认证结构（根为公钥，叶为 OTS 公钥）。每个树（高度 h）支持 2^h 次签名，签名者需维护状态（已使用的叶索引）。HSS（Hierarchical Signature System）通过多层 Merkle 树扩展签名容量，支持指数级增长。方案仅依赖哈希函数的抗碰撞和第二原像抵抗性，不涉及任何大整数运算，因此天然抗侧信道攻击且实现简单。

## 核心成果
- 定义了可互操作的 LMS/HSS 规范，成为后量子签名的事实标准之一
- 被 NIST SP 800-208 采纳为美国国家标准
- 提供紧凑密钥、快速签名验证、天然抗量子计算攻击等特性

## 与本项目关联
**背景知识**: RFC 8554 定义的 LMS/HSS 是与本项目使用的 SPHINCS+ 平行的有状态哈希签名方案。两者的核心组件（WOTS+ 链函数、Merkle 树、hypertree）高度相似。理解 LMS/HSS 的状态管理要求有助于对比说明 SPHINCS+（无状态）在 Fischlin 盲签名协议中的优势。
