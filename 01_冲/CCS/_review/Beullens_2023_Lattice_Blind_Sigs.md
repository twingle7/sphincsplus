# Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal

**出处**: ACM CCS 2023 (Copenhagen, Denmark, November 26–30, 2023)
**作者**: Ward Beullens, Vadim Lyubashevsky, Ngoc Khanh Nguyen, Gregor Seiler

## 论点
基于标准格上困难问题（Ring/Module-SIS/LWE 和 NTRU），可以构造出轮次最优（2轮）且签名尺寸显著优于此前所有方案的盲签名协议，证明了格基盲签名在效率和安全性上的实用可行性。

## 背景
盲签名是隐私保护协议的核心原语，然而此前基于标准格假设的方案签名尺寸过大（约 100 KB），实用性受限。近年有方案通过引入新假设（如 one-more-ISIS）来缩小签名，但标准假设下仍存在较大效率差距。

## 技术路线
论文采用标准 Fiat-Shamir with Aborts 范式，在随机预言机模型下构造 2 轮盲签名（理论最小轮次）。安全假设同时依赖 Module-SIS/Module-LWE 和 NTRU 的困难性。签名生成过程通过精心设计的高斯采样和拒绝采样技术控制 abort 概率，使签名尺寸压缩至约 22 KB（较此前最优方案缩短约 4 倍）。此外，论文还提出了密钥验证（keyed-verification）变体，当签名者和验证者共享密钥时签名尺寸可低至 48 字节。

## 核心成果
- **签名尺寸约 22 KB**：标准假设下最短的格基盲签名，较此前最优方案缩短 4 倍
- **轮次最优（2 轮）**：达到盲签名理论最小轮次
- **密钥验证变体（48 字节）**：特殊场景下签名尺寸极短，为专用协议设计提供新可能

## 与本项目关联
**直接竞争**: 本项目同样实现盲签名功能，但基于 SPHINCS+/Fischlin 而非格基。Beullens 等人的工作在签名尺寸上（约 22 KB）远优于本项目的 STARK 证明尺寸（约 95 KB），但其安全假设（SIS/LWE + NTRU）复杂度高于本项目仅依赖哈希函数抗碰撞性的极简假设，双方在实用性和安全简洁性之间存在权衡。
