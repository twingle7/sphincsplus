# Poseidon2: A Faster Version of the Poseidon Hash Function

**出处**: AFRICACRYPT 2023
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Markus Schofnegger

## 论点
Poseidon2 是 Poseidon 的深度优化版本，通过重新设计线性层大幅降低乘法运算和电路约束数量——线性层乘法减少约 90%，Plonk 电路约束减少约 70%。

## 背景
Poseidon 虽然显著优于传统哈希，但其线性层（基于 MDS 矩阵的矩阵-向量乘法）仍然是约束数量的主要来源。特别是全轮（full rounds）中的大矩阵乘法对电路复杂度影响显著。Grassi 等人对线性层的安全性和效率进行了系统性再分析，提出了多项关键优化。

## 技术路线
Poseidon2 的核心改进包括：(1) 用新型线性和仿射层（如带状矩阵与矩阵平方结合）替代完全 MDS 矩阵，大幅降低乘法复杂度而保持相同安全边界；(2) 优化部分轮与全轮的比例；(3) 对安全性进行更精细的形式化分析，重新评估了 Poseidon 原有安全边界（发现部分轮的原边界偏保守）。在 Goldilocks 域上，Poseidon2 的 t=12 状态（最近用于本项目）仅需 8 个全轮和 22 个部分轮，线性层仅涉及简单的域元素加法和乘法。

## 核心成果
- 线性层乘法减少约 90%，Plonk 约束减少约 70%
- 在 Goldilocks 域（2^64 - 2^32 + 1）上提供高效实现，特别适合 STARK 应用
- 维持与 Poseidon 相同的安全等级，同时显著提升实际性能

## 与本项目关联
**直接竞争/方法论参考**: Poseidon2 是本项目 SPHINCS+ 扩展的**核心依赖**——作为 Poseidon2 哈希后端的 SPHINCS+ 变体（sphincs-poseidon2-*）。本项目使用 Poseidon2 的 t=12（capacity=6, rate=6）配置进行所有哈希运算，包括 STARK 证明中的置换追踪。
