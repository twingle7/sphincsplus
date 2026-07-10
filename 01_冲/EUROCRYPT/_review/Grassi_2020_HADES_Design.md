# On a Generalization of Substitution-Permutation Networks: The HADES Design Strategy

**出处**: EUROCRYPT 2020
**作者**: Lorenzo Grassi, Reinhard Lüftenegger, Christian Rechberger, Dragos Rotaru, Markus Schofnegger

## 论点
提出HADES设计策略，将全S盒轮与部分S盒轮相结合，构造面向算术化场景的对称密码原语，在安全性证明与计算效率之间取得新的平衡点。

## 背景
零知识证明、安全多方计算和同态加密等应用需要原生在有限域上高效运算的密码原语，而AES等传统密码在域算术场景下效率极低。MiMC等早期方案虽实现了域友好性，但在带宽和安全性论证方面存在不足。HADES旨在填补这一空白，为算术友好的密码设计提供系统化的理论框架。

## 技术路线
论文将宽轨迹设计策略推广到部分SPN结构，其中外层采用全S盒轮（所有状态元素均经过S盒），内层采用部分S盒轮（仅少量状态元素经过S盒）。安全分析涵盖差分/线性密码分析和代数攻击，特别针对x^3等简单S盒在素数域上使用时面临的代数攻击风险。研究者进一步实例化了HADESMiMC密码方案，并给出完整的安全参数约束。

## 核心成果
- 提出HADES设计策略，将全S盒轮与部分S盒轮有机融合，形成新的SPN范式
- 建立针对差分、线性和代数攻击的安全论证框架，扩展了宽轨迹策略的适用范围
- 实例化HADESMiMC，在线带宽和吞吐量显著优于MiMC，预处理开销更低

## 与本项目关联
**方法论参考**: HADES设计策略是Poseidon哈希函数族（本项目使用的哈希后端）的核心理论基础。本项目采用的Poseidon2置换参数（t=12, RF=8, RP=22, x^7 S盒）直接继承自HADES框架的安全分析结论。
