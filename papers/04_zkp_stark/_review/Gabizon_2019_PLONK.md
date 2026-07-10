# PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive Arguments of Knowledge

**出处**: ePrint 2019/953
**作者**: Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru

## 论点
PLONK 提出了一个兼具通用性和可更新性的通用 SNARK 构造——只需一次可信设置即可服务任意程序，且证明完全简洁，验证者仅需 2 次双线性配对。

## 背景
此前 Groth16 虽然效率极高，但每个电路都需要单独的可信设置，严重限制了实际部署的灵活性。Sonic 虽然实现了通用设置，但其验证复杂度仍不够理想。PLONK 的目标是在通用性、可更新性和验证效率三者之间取得最佳平衡。

## 技术路线
核心创新包括两个关键组件：一是基于乘法子群上拉格朗日多项式稀疏表示的新型排列论证，通过"大乘积"（grand product）技术高效实现电路的复制约束；二是使用通用可更新的结构化参考字符串（SRS），支持多方顺序参与更新，只要至少一方诚实即可保证安全性。PLONK 利用多项式恒等式而非线性测试验证电路约束，后续衍生出 Plookup、Plonky2 等大量工作。

## 核心成果
- 通用且可更新的可信设置，每个门约 9(n+a) 次 G1 指数运算
- 验证者仅需 2 次双线性配对和约 16–18 次群指数运算
- 相比 Sonic 在完全简洁验证者模式下的群指数运算减少约 7.5–20 倍

## 与本项目关联
**背景知识**: PLONK 代表了 IOP + 多项式承诺路线的 ZK 证明范式（与 STARK 的 IOP + 抗碰撞哈希路线并列）。本项目选择 STARK 路线主要基于后量子安全性需求，PLONK 作为对比路线提供了理解不同设计权衡的参考。
