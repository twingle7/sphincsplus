# Poseidon: A New Hash Function for Zero-Knowledge Proof Systems

**出处**: USENIX Security Symposium, 2021
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, Markus Schofnegger

## 论点
可以设计一种原生运行于素数域上的哈希函数，使其在零知识证明系统中相比通用哈希函数（如SHA-256）获得数十倍的性能提升。

## 背景
零知识证明系统（ZK-SNARKs、ZK-STARKs等）中的哈希计算是主要性能瓶颈之一。传统哈希函数SHA-256在设计时未考虑在算术电路中高效实现，导致证明生成时产生大量约束和计算开销。当时缺乏针对ZK友好场景专门设计的哈希函数。

## 技术路线
Poseidon采用海绵结构，其底层置换基于HADES设计策略——一种SPN网络变体。创新在于混合使用完整的S-box轮（t个S-box并行）和部分轮（仅1个S-box），大幅降低R1CS和代数执行轨迹中的约束数量。S-box使用低次幂映射（x^3或x^5），进一步减少约束。安全性分析涵盖代数攻击、差分攻击和Gröbner基攻击等场景。支持80/128/256比特安全级别。

## 核心成果
- 在PLONK和RedShift系统中比SHA-256最高快40倍
- Merkle树场景下R1CS约束数仅4,050-7,290，相比SHA-256的826,020下降两个数量级
- 被Filecoin、Polygon、Sui等主流区块链和ZK协议广泛采用

## 与本项目关联
**方法论参考**: Poseidon的设计哲学直接影响了本项目采用的Poseidon2哈希函数——本项目使用Poseidon2作为SPHINCS+的哈希后端和Fischlin协议中STARK证明的算术化基础。Poseidon系列的设计分析和安全性论证为本项目的参数选择和安全性评估提供了关键参考。
