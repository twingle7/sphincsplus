# Scalable Zero Knowledge with No Trusted Setup

**出处**: CRYPTO 2019, LNCS Vol. 11694, pp. 701-732
**作者**: Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, Michael Riabzev

## 论点
提出zk-STARKs——一种无需可信设置、仅依赖抗碰撞哈希函数的零知识证明系统，验证时间为计算量的对数级别。这是第一个同时满足可扩展性、透明性（无trusted setup）和后量子安全性的ZK证明系统。

## 背景
zk-SNARKs（如Groth16）依赖可信设置（toxic waste问题）且基于非抗量子的配对假设。STARKs之前的交互式证明（IP/PCP）虽然理论优雅但实际效率低。

## 技术路线
- ALI（代数链接IOP）：将计算表示为代数约束系统（AIR），通过FRI协议证明多项式低度
- FRI（Fast Reed-Solomon IOPP）：核心创新，用对数级复杂度验证Reed-Solomon码的邻近性
- Merkle树承诺：用哈希函数（而非配对）实现多项式承诺，消除可信设置
- Fiat-Shamir变换：将IOP转为非交互式证明
- 递归组合：证明者可生成"证明的证明"，实现恒定大小验证

## 核心成果
- 第一个实用的无trusted setup ZK证明系统
- 验证时间对数级别，证明大小15-300KB
- 后量子安全（仅依赖哈希函数）
- 开源实现：Winterfell（Rust）、Stone Prover（C++）
- 被StarkWare、Polygon、RISC Zero等采用

## 与本项目关联
**方法论参考**: 本项目直接使用Winterfell STARK框架作为Fischlin协议中的NIZKPoK组件。理解AIR约束和FRI协议是理解本项目STARK层的先决条件。
