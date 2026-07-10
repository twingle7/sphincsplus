# Rescue-Prime: a Standard Specification (SoK)

**出处**: ePrint 2020/1143
**作者**: Alan Szepieniec, Tomer Ashur, Siemen Dhooghe

## 论点
Rescue-Prime 是基于 Rescue 置换的 ZK 友好哈希函数，在 AIR（代数中间表示）算术化下效率极高，是 Winterfell STARK 框架的默认哈希函数。

## 背景
Rescue-Prime 的前身 Rescue 置换由 Aly 等人（2019）提出，其设计特别适合算术化表示——使用低次 S-box（逆向）。Szepieniec 等人将其标准化为一个具体的哈希函数规范，包括固定的参数、安全等级和域选择（主要基于 Goldilocks 域），使其可直接用于 STARK 证明系统。

## 技术路线
Rescue-Prime 采用 sponge 结构的哈希构造，底层的 Rescue 置换设计为两个方向相反的 S-box 层交换——正向使用 α 次幂，反向使用连分数（α 的逆）构造，使得整个置换在算术化（特别是 AIR）中的约束表达极为简洁。在 Winterfell 中，Rescue-Prime 的每个置换步骤仅需少量算术约束，且支持高效的域扩展和状态压缩。论文提供了每个安全等级（128, 192, 256 位）的固定参数规格。

## 核心成果
- 首个被广泛使用的 Rescue 族标准化哈希规范
- 在 AIR 算术化下效率最优之一，是 Winterfell 框架的默认哈希
- 提供完备的安全分析和固定参数推荐

## 与本项目关联
**背景知识**: 本项目使用 Poseidon2 而非 Rescue-Prime，主要因为 SPHINCS+ 的哈希需求（THF）与 Rescue-Prime 的优化目标（快速置换追踪）不完全匹配。然而 Rescue-Prime 在 Winterfell 中的 AIR 实现为本项目的 AIR 设计提供了重要参考。
