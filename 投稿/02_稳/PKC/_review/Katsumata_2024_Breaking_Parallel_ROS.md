# Breaking Parallel ROS: Implication for Isogeny and Lattice-Based Blind Signatures

**出处**: PKC, 2024
**作者**: Shuichi Katsumata, Yi-Fu Lai, Michael Reichle

## 论点
提出pROS（并行随机非齐次过定可解线性方程组）问题框架，对三个基于identificaiton protocol的三轮盲签名（CSI-Otter、Blaze+、BlindOR）实现了多项式时间的并发不可伪造性攻击。

## 背景
许多基于identification protocol的三轮盲签名仅被证明在ℓ=polylog(λ)并发下安全。Benhamouda等人(Eurocrypt 2021)展示了针对盲Schnorr的多项式时间攻击，但不适用于其他结构不同的盲签名方案。是否存在针对基于群作用（isogeny）和格密码的盲签名的高并发攻击是一个开放问题。

## 技术路线
1. 定义了称为pROS（Parallel Random inhomogeneities in an Overdetermined Solvable system of linear equations）的新中间问题。
2. 证明对pROS问题的攻击意味着对上述盲签名方案的并发不可伪造性的攻击。
3. 对各个目标方案进行参数分析，计算出实现安全破坏的具体复杂度：CSI-Otter在4-并发下约2^34哈希计算（~100%成功率），Blaze+和BlindOR约2^43哈希计算。

## 核心成果
- 对CSI-Otter、Blaze+和BlindOR三个后量子盲签名方案实现多项式时间并发攻击。
- 揭示了并行重复指数级降低identification protocol的soundness错误率，但对盲签名安全性的提升极其有限。
- pROS问题框架为评估此类盲签名方案的并发安全性提供了新的分析工具。

## 与本项目关联
方法论参考: 本文对基于identification protocol的盲签名的攻击不直接适用于本项目使用的Fischlin范式，但其安全性分析方法（特别是并行化对安全性的影响分析）对评估本协议中ZK证明的并行组合安全性具有重要参考价值。
