# Post-Quantum ID-based Ring Signatures from Symmetric-Key Primitives

**出处**: ACNS 2022
**作者**: Maxime Buser, Joseph K. Liu, Ron Steinfeld, Amin Sakzad

## 论点
提出两种后量子身份基环签名：PicRS（基于Picnic/MPC-in-the-Head）和XRS（基于XMSS哈希签名）。XRS环签名仅889KB（4096用户环），远小于格基方案（335MB）。

## 背景
环签名在区块链隐私（如Monero）和举报人保护中有广泛应用。但现有后量子环签名（基于格）极其庞大。基于哈希的方案可能提供更紧凑的替代。

## 技术路线
- PicRS：基于Picnic的MPC-in-the-Head零知识证明
- XRS：基于XMSS哈希签名的环构造
- 身份基：公钥即身份标识，无需证书
- 对称原语：仅依赖哈希函数安全性

## 核心成果
- 889KB签名（4096用户环）——远小于格方案的335MB
- 仅依赖哈希函数安全性的后量子安全性
- ACNS 2022发表

## 与本项目关联
**方法论参考**: 与本项目共享"基于哈希原语+零知识证明"的核心范式。XRS证明了哈希签名在ZK环构造中的效率优势，间接支持了本项目SPHINCS++STARK的技术路线。
