# Hash-Based Direct Anonymous Attestation

**出处**: PQCrypto, 2023
**作者**: Liqun Chen, Changyu Dong, Nada El Kassem, Christopher J. P. Newton, Yalan Wang

## 论点
提出第一个基于对称密码原语（哈希函数）的后量子直接匿名认证(DAA)方案，支持高达2^60个群组成员，安全性在通用可组合(UC)模型下证明。

## 背景
DAA是可信计算中的关键技术，允许在不泄露用户身份的情况下证明平台状态。现有DAA标准化方案（RSA和ECC方案）在量子攻击下不安全。此前唯一的后量子DAA方案基于格密码学，本文首次探索使用哈希签名的替代路线。

## 技术路线
1. 使用SPHINCS+的轻微修改版本作为DAA凭证的底层签名方案。
2. 使用Picnic风格签名（基于MPC的NIZK证明系统）来证明凭证的持有关系。
3. 在通用可组合(UC)安全模型下证明方案的正确性、匿名性、用户可控可链接性和不可诬陷性。
4. 利用可调哈希函数（Tweakable Hash）的分离属性提供强匿名性保证。

## 核心成果
- 首个基于哈希的/对称原语的后量子DAA方案，开辟了新设计方向。
- DAA签名操作仅需约5个普通签名的工作量（假设TPM支持Picnic签名）。
- 在UC框架下提供完整的可证明安全性，涵盖DAA所有关键安全属性。

## 与本项目关联
直接竞争: 本项目使用Fischlin协议与SPHINCS+实现匿名凭证系统，与该DAA方案在目标应用（匿名认证）上高度重叠。该方案采用Picnic而非Fischlin作为ZK机制，两种技术路线的效率和安全性对比值得深入分析。
