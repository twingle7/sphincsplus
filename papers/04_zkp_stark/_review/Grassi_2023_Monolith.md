# Monolith: Circuit-Friendly Hash Functions

**出处**: ePrint 2023/1025
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Reinhard Luftenegger, Christian Rechberger, Markus Schofnegger, Markus Skrinsky

## 论点
Monolith 是首个原生（Native）性能比肩 SHA3-256 且电路友好性优于 Poseidon2 的哈希函数——2-to-1 压缩函数在原生实现中比 Poseidon2 快 7 倍，同时保持更少的电路约束。

## 背景
ZK 友好哈希函数（如 Poseidon2）虽然在电路中效率很高，但其原生实现往往远慢于 SHA3/AES 等传统哈希。这意味着在混合场景（同时需要 ZK 证明和原生计算）中存在性能瓶颈。Monolith 的目标是同时在这两个领域达到最优。

## 技术路线
Monolith 的核心创新是"先进先出"（FIFO）S-box 和 ARX（加-旋-异或）结构的结合。S-box 基于低深度算术化友好置换，而 ARX 层提供了原生实现的高效性。Monolith 的设计吸收了 AES 指令集（AES-NI）的优化思路——利用 AES 原语加速 S-box 实现。在电路中，Monolith 的约束数量甚至低于 Poseidon2；在原生实现中，其吞吐量接近 SHA3。

## 核心成果
- 2-to-1 压缩函数原生性能比 Poseidon2 快 7 倍
- 电路约束数量低于 Poseidon2，同时保持在同等的 128 位安全等级
- 首个缩小了 ZK 友好哈希与通用哈希之间原生性能差距的设计

## 与本项目关联
**方法论参考**: Monolith 展示了 ZK 友好哈希设计的前沿——在 AIR/Plonk/R1CS 等多种算术化下兼顾性能与安全。本项目选择 Poseidon2 而非 Monolith 主要基于项目启动时间点（Monolith 较新）和 Poseidon2 在 Goldilocks 域的成熟性。
