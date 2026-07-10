# Anemoi: New Design Techniques for Efficient Arithmetization-Oriented Hash Functions

**出处**: CRYPTO 2023
**作者**: Clemence Bouvier, Pierre Bariant, Jeremy Jean, Gregor Leander, Christof Beierle, and others

## 论点
Anemoi 通过创新的 Flystel S-box 设计，在 R1CS 和 Plonk 约束数量上比 Poseidon 分别提升约 2 倍和 21–35%，为算术化友好哈希提供了新的设计思路。

## 背景
Poseidon 及其变体主导了 ZK 友好哈希领域，但其 S-box（x^α, x^7 等）的设计仍存在权衡空间。Bouvier 等人寻求通过新的置换组件设计，在安全性和算术效率之间取得更优平衡。

## 技术路线
Anemoi 的核心创新是 Flystel S-box——将 Feistel 结构与扩张层结合，构造出一个在 R1CS 和 Plonkish 算术化下都高效的置换组件。Flystel 基于低次方程构造，使得在 R1CS 中每个 S-box 约束数量大幅减少。在 Plonk 设定下，Flystel 的优势来自其稀疏的约束表示——仅需 1 个门即可表示 2 个 S-box 的求值。Anemoi 支持灵活的域选择（包括 Goldilocks 域和 BLS12-381 标量域），并提供了形式化的安全分析和广泛的密码分析结果。

## 核心成果
- Flystel S-box 创新：R1CS 约束比 Poseidon 减少约 2 倍
- Plonk 约束比 Poseidon 减少 21–35%
- 提供完整的密码分析，证明在各目标安全等级下均具有充分安全边际

## 与本项目关联
**方法论参考**: Anemoi 是 Poseidon2 的直接竞争者。本项目选择 Poseidon2 作为核心哈希，但 Anemoi 的 Flystel 设计展示了减少约束的替代路径。若未来需要进一步优化 STARK 证明性能，Anemoi 的 AIR 效率可作为参考基准。
