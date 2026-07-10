# Round-Optimal Composable Blind Signatures in the Common Reference String Model

**出处**: CRYPTO 2006, LNCS Vol. 4117, pp. 60-77
**作者**: Marc Fischlin

## 论点
在CRS模型下构造了轮次最优（两轮）的通用可组合（UC）安全盲签名方案，这是第一个同时满足轮次最优性和UC安全性的盲签名构造。盲签名过程仅需两轮交互。

## 背景
传统盲签名（Chaum, 1983）依赖具体代数结构（RSA），且通常需要三轮交互。UC安全框架提出后，尚无方案同时达到两轮交互和UC安全性。线性加密和NIZKPoK等新工具的出现使构造成为可能。

## 技术路线
- 核心范式：Signer生成承诺c = Commit(m; r)，User计算σ = Sign(sk, c)，最终签名包含(c, σ)和NIZK证明
- 使用承诺方案替代传统盲化，避免盲化因子的复杂交互
- NIZKPoK确保σ是对c的有效签名，且c是对m的有效承诺
- CRS提供公共参数，实现非交互式零知识
- 基于一般复杂性假设（陷门置换/TDP），不依赖具体代数结构

## 核心成果
- 第一个UC安全的盲签名方案（两轮交互）
- 可并发执行（Concurrent Security）——多个盲签名会话可并行运行
- 通用构造：可基于任意签名方案+NIZKPoK+承诺方案实例化
- 为后续18年的后量子盲签名变体（格基、同源基、哈希基）提供理论框架

## 与本项目关联
**背景知识/方法论参考**: 本项目直接基于Fischlin框架实例化盲签名！我们的方案是将SPHINCS+作为底层签名方案，Poseidon2作为承诺的哈希函数，STARK作为NIZKPoK组件。理解Fischlin的范式（c = Commit(m; r) → σ = Sign(sk, c) → π = NIZKPoK）是理解本项目协议设计的核心前提。
