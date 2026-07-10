# Benchmarking ZK-Friendly Hash Functions and SNARK Proving Systems for EVM-compatible Blockchains

**出处**: arXiv 2024 (arXiv:2409.01976)
**作者**: Hanze Guo, Yebo Feng, Cong Wu, Zengpeng Li, Jiahua Xu

## 论点
通过系统基准测试 3 种 SNARK 证明系统（Groth16、Plonk、Halo2）与 5 种 ZK 友好哈希（Poseidon、Poseidon2、Rescue-Prime、SHA256、Monolith）的组合，发现 Poseidon2 + Groth16 在 EVM 链上成本降低约 73%。

## 背景
ZK 友好哈希的选择对证明系统性能影响巨大，但缺乏在统一框架下对不同哈希与 SNARK 组合的横向对比。特别是在 EVM 兼容区块链的部署场景下，Gas 成本和实际执行时间是关键指标。本文首次提供了全面的系统级基准测试。

## 技术路线
论文在 EVM 兼容环境中搭建统一的基准测试框架，对 3 种 SNARK × 5 种哈希的 15 种组合进行测量。指标包括证明生成时间、验证时间、证明大小、链上验证 Gas 成本。使用 Groth16（Bn254 曲线）、Plonk（BN254）和 Halo2（Pasta 曲线）作为证明系统后端，对每个哈希在 R1CS/Plonkish 算术化下的约束数量进行精确统计。

## 核心成果
- Poseidon2 + Groth16 组合在 EVM 链上 Gas 成本最低，相比 SHA256 + Groth16 降低约 73%
- Monolith 在 Plonk/Halo2 中表现突出，但在 R1CS 中不如 Poseidon2
- Rescue-Prime 在 AIR 算术化下最优，但在非 AIR 设定下效率显著下降

## 与本项目关联
**应用场景**: 本文的基准数据为本项目选择 Poseidon2 作为哈希后端提供了量化的性能验证。论文中关于 AIR vs R1CS vs Plonk 算术化的对比分析有助于理解本项目采用 STARK（AIR 算术化）路径的选择依据。
