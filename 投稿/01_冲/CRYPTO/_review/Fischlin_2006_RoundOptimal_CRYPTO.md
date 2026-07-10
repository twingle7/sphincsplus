# Round-Optimal Composable Blind Signatures in the Common Reference String Model

**出处**: CRYPTO 2006, LNCS Vol. 4117, pp. 60-77
**作者**: Marc Fischlin

## 论点
在CRS模型下构造了第一个同时满足轮次最优（两轮）和UC安全性的盲签名方案。盲签名仅需两轮交互，且可并发执行。

## 背景
传统盲签名（Chaum 1983）依赖RSA等代数结构，通常需三轮交互。UC安全框架提出后，尚无方案同时达到两轮交互和UC安全。需要一个通用构造来打破这一限制。

## 技术路线
- 核心范式：c = Commit(m; r) → σ = Sign(sk, c) → π = NIZKPoK(σ对c有效, c对m有效)
- 用承诺方案替代传统盲化因子
- NIZKPoK确保证明的有效性
- CRS提供公共参数
- 基于一般复杂性假设（陷门置换），不依赖具体代数结构

## 核心成果
- 第一个UC安全的轮次最优盲签名
- 可并发执行——多个盲签名会话可并行
- 通用构造：可基于任意签名方案+NIZKPoK+承诺方案实例化

## 与本项目关联
**背景知识/方法论参考**: 本项目的Fischlin协议直接基于此框架。SPHINCS+作为底层签名，Poseidon2作为承诺哈希，STARK作为NIZKPoK。
