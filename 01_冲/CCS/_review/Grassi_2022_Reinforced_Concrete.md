# Reinforced Concrete: A Fast Hash Function for Verifiable Computation

**出处**: ACM CCS 2022 (Los Angeles, CA, USA, November 7–11, 2022)
**作者**: Lorenzo Grassi, Dmitry Khovratovich, Reinhard Lüftenegger, Christian Rechberger, Markus Schofnegger, Roman Walch

## 论点
Reinforced Concrete 是首个在零知识证明场景和原生 x86 计算中均表现高效的通用哈希函数，填补了此前 ZK 友好哈希（如 Poseidon）在原生端性能严重不足的空白，并同时继承了传统 AES 类设计的成熟安全论证。

## 背景
零知识证明和可验证计算对算术化友好的哈希函数需求急剧增长。Poseidon、Rescue 等 ZK 友好哈希虽在约束数量上极具优势，但在原生 x86 平台上性能远逊于 SHA-256/Blake2，难以同时服务证明生成和本地验证两阶段。

## 技术路线
该函数采用海绵结构，定义域为 F_p^3 上的置换。其独特设计分为三部分：Bars（高次代数层，阻止插值与 Gröbner 基攻击）、Bricks（低次非线性层，抵抗统计攻击）、Concrete（仿射扩散层，提供充分混合）。这一分层策略在代数安全性和计算效率之间取得平衡。性能上，在通用素数域（如 BLS12-381）上比 Poseidon 快约 5 倍，在特制域上快约 16 倍；原生性能仅比 SHA-256 慢 2-9 倍，但编码为电路后门数减少约 7 倍。

## 核心成果
- **双域高效**：首次在 ZK 证明和原生执行两个场景同时实现高性能
- **安全性继承自 AES**：不依赖纯代数安全论证，安全模型更成熟
- **广泛适用性**：可替代 Poseidon、MiMC、Pedersen 等多种素数域哈希，应用于隐私币、可验证加密、递归证明等多类协议

## 与本项目关联
**背景知识**: 本项目使用 Poseidon2 作为哈希后端，Reinforced Concrete 代表同一研究前沿（ZK 友好哈希）的重要进展。其分层设计理念（高次/低次/仿射组合）对本项目 Poseidon2 实现的安全分析和参数选择具有参考价值，尤其在海绵结构构造和代数阶分析方面。
