# STARKPack: Some Amortization Techniques for FRI-based SNARKs

**出处**: ePrint 2024/661
**作者**: Albert Garreta, Hayk Hovhanissyan, Aram Jivanyan, Ignacio Manzur, Isaac Villalobos, Michal Zajac

## 论点
通过打包（Packing）和模块化分割-打包（Modular Split-and-Pack）两种摊销技术，可显著缩小 FRI-based SNARK（STARK）的证明大小并加速验证，验证时间提升约2倍，证明大小缩小约2–3倍。

## 背景
STARK 证明的典型大小在数十到数百KB之间，对于需要验证大量并行证明的应用（如 zk-Rollup、批量签名验证）来说，这段瓶颈仍然是实际部署的障碍。虽然 STARK 无需可信设置且抗量子，但其较大的证明尺寸相较于 Groth16 等 SNARK 仍存在差距。

## 技术路线
Packing 技术将多个独立 AIR 约束系统的多项式评估打包到同一棵 Merkle 树中，将所有 DEEP FRI 函数组合成一个随机化有效性函数，只需一次 FRI 低度测试即可同时验证多个实例。Modular Split-and-Pack 将大分割为小子见证，利用 Packing 并行证明每个子见证。该方法支持跨不同算术化方案的聚合，且随着打包实例数量的增加，优化效果更显著。

## 核心成果
- 打包 9 条迹线时：验证时间加速约 2.2–2.4 倍，证明大小缩小约 2.5 倍
- 支持跨 AIR + TurboPlonk 等不同算术化方案的聚合
- 提供形式化可靠性分析，量化打包过程的可靠性损失及其安全界

## 与本项目关联
**方法论参考**: 本项目当前生成单个 Fischlin STARK 证明（~95KB）。若未来需要批量验证多个签名或实现更复杂的协议组合，STARKPack 的聚合技术可直接用于压缩和加速验证。
