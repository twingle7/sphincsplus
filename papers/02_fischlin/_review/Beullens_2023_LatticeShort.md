# Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal

**出处**: ACM CCS 2023, pp. 16-29
**作者**: Ward Beullens, Vadim Lyubashevsky, Ngoc Khanh Nguyen, Gregor Seiler

## 论点
提出首个轮次最优(两轮)且实用的格基盲签名，签名仅20-22 KB，基于标准Ring/Module-SIS/LWE和NTRU假设。

## 背景
格基盲签名此前要么是三轮方案(Hauck et al., CRYPTO 2020)，要么基于非标准假设或签名尺寸过大。后量子盲签名的实际部署需要同时满足紧凑的签名尺寸和标准的安全性假设。

## 技术路线
设计两轮交互协议，通过精心优化的拒绝采样和掩蔽技术实现安全盲化。协议基于标准格假设(Ring/Module-SIS/LWE和NTRU)，签名约20-22 KB，通信约60 KB。此外提出"密钥验证"变体，签名仅48字节(需签名者和验证者共享密钥)。

## 核心成果
1. 首个基于标准假设的实用轮次最优格盲签名(20-22 KB)
2. 比此前最紧凑的格盲签名(del Pino-Katsumata CRYPTO'22)短约4倍
3. 密钥验证变体签名尺寸仅48字节，展示极限压缩可能性

## 与本项目关联
直接竞争: 格基盲签名的SOTA方案之一，在签名尺寸和效率上为本项目(基于SPHINCS+和STARK)提供了重要的性能对标基准。
