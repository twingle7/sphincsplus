# ALFOMs: Quantifying the Performance/Security Tradeoff for ZK-friendly Hash Functions

**出处**: ePrint 2025/1920
**作者**: Aurelien Boeuf, Leo Perrin

## 论点
本文精确定量了 ZK 友好哈希函数的安全性与性能之间的权衡关系，发现 Griffin/Anemoi 在 R1CS 算术化下最优，而 Rescue-Prime 在 AIR 算术化下效率最高。

## 背景
ZK 友好哈希领域在过去五年经历了快速发展，涌现了 Poseidon、Poseidon2、Anemoi、Monolith、Rescue-Prime 等多种设计方案。每种方案声称在某种算术化（R1CS、Plonk、AIR）下具有优势，但缺乏统一、可量化的权衡分析框架。设计师和用户难以客观地比较不同哈希函数在给定安全约束下的实际性能。

## 技术路线
论文提出了 ALFOM（Arithmetization-Linear-Function-Oriented Metric）框架，将哈希函数的安全属性（如 S-box 代数度、差分/线性概率）和算术化性能（约束数量、乘法深度）映射到统一的安全-性能平面上。引入了"Moirai"自动分析工具，对每个哈希在不同安全等级下计算 Pareto 最优参数集。通过将安全边界形式化为可计算的代数度量，实现了对设计空间中各点的客观比较。

## 核心成果
- 提出 ALFOM 量化框架，实现 ZK 友好哈希的安全性/性能权衡的形式化度量
- 开源 Moirai 分析工具，可自动搜索给定安全目标下的最优参数配置
- Griffin 和 Anemoi 在 R1CS 中 Pareto 最优，Rescue-Prime 在 AIR 中 Pareto 最优

## 与本项目关联
**方法论参考**: ALFOM 的框架可直接用于对本项目所使用的 Poseidon2 参数（t=12, RF=8, RP=22）进行安全性/性能权衡分析。Moirai 工具提供的自动化参数搜索方法论与项目中 Poseidon2 参数选择的优化目标高度一致。
