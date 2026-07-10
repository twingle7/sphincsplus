# Poseidon2: A Faster Version of the Poseidon Hash Function

**出处**: AFRICACRYPT 2023, LNCS Vol. 14064, pp. 177-203
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Markus Schofnegger

## 论点
提出Poseidon2——对原始Poseidon哈希函数的深度优化版本，通过改进线性层和双模式操作，在零知识证明电路中实现70-90%的约束减少。

## 背景
Poseidon（USENIX Security 2021）成为最广泛使用的ZK友好哈希，但其MDS矩阵在全轮次中的乘法开销仍然较高。Plonk等新型证明系统的出现对哈希函数的约束效率提出了更高要求。

## 技术路线
- 线性层优化：用更稀疏的矩阵替换全MDS矩阵，内部轮次只用对角矩阵（乘法次数减少90%）
- 双模式：海绵模式（哈希）+ 压缩函数模式（Merkle树），两种模式共享核心置换
- Goldilocks域（p=2^64-2^32+1）：64-bit友好，2^32阶单位根支持FFT
- t=12状态字，capacity=6，rate=6，RF=8，RP=22
- x^7 S-box：在Goldilocks域上是置换（gcd(7, p-1)=1）

## 核心成果
- Plonk电路中比Poseidon约束减少70%
- 外部轮次使用完整MDS，内部轮次仅用对角矩阵
- 成为SP1、RISC Zero等多个zkVM的默认哈希
- 安全性保持：Gröbner基/XL攻击分析确认RF=8, RP=22足够

## 与本项目关联
**背景知识/方法论参考**: 本项目直接使用Poseidon2作为SPHINCS+的底层哈希置换。Goldilocks域的64-bit特性使得在C中实现简单高效，同时STARK的FRI协议需要2^32阶单位根——Goldilocks恰好满足。
