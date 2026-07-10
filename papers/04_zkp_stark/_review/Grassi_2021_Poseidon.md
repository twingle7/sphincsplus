# Poseidon: A New Hash Function for Zero-Knowledge Proof Systems

**出处**: USENIX Security 2021
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, Markus Schofnegger

## 论点
Poseidon 是首个大规模应用的 ZK 友好哈希函数，基于 HadesSPN 设计策略，在 Plonk/R1CS 等零知识证明系统中实现比传统哈希（如 SHA3）最高 40 倍的性能提升。

## 背景
传统哈希函数（SHA-2/3、BLAKE 等）在设计时未考虑零知识证明系统的需求。在 zk-SNARK/STARK 电路中，这些哈希需要通过算术电路表示，导致巨大的约束数量和证明开销。ZK 应用（特别是区块链隐私方案）迫切需要一种在电路中高效、同时保持充分安全性的专用哈希函数。

## 技术路线
Poseidon 采用 HadesSPN 策略——结合 SPN（代换-置换网络）和 PN（置换网络）结构：外部轮次使用完整的 S-box（全轮），提供抗统计攻击的安全边界；内部轮次使用部分 S-box（仅一个 S-box 活跃），大幅减少电路约束。在 R1CS 中，Poseidon 的约束数量约为 SHA3-256 的 1/10；在 Plonk 中性能提升更为显著。参数化设计支持灵活调整安全等级和状态大小（t = 3, 5, 9, 12 等）。

## 核心成果
- 首个系统设计的 ZK 友好哈希函数，被 Zcash、Filecoin 等项目广泛采用
- 在 SNARK 电路中相比传统哈希性能提升 10–40 倍
- 提出 HadesSPN 设计策略，成为后续 ZK 友好哈希设计的范式基础

## 与本项目关联
**方法论参考**: Poseidon 的 HadesSPN 设计理念直接影响了 Poseidon2 的发展，而 Poseidon2 是本项目 SPHINCS+ 后端的核心哈希函数。理解 Poseidon 的设计取舍是理解本项目安全模型和性能指标的前提。
