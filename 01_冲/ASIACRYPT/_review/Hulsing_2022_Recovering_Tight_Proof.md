# Recovering the Tight Security Proof of SPHINCS+

**出处**: ASIACRYPT 2022
**作者**: Andreas Hulsing, Mikhail Kudinov

## 论点

修复SPHINCS+紧安全证明中的根本性缺陷，恢复几乎与原声明相同的安全界（仅损失因子w，通常w=16），为该签名方案的标准化提供理论基础。

## 背景

2020年，Kudinov、Kiktenko和Fedorov发现SPHINCS+的原始紧安全证明存在严重漏洞。该漏洞可追溯到方案所使用的Winternitz一次签名（WOTS）变体的安全论证。若无紧安全归约，SPHINCS+的安全声明将依赖于松散得多的界，影响参数选择的可信度。

## 技术路线

作者首先将SPHINCS+中使用的WOTS变体独立描述并命名为WOTS-TW，然后针对非自适应选择消息攻击（敌手在签名查询之后才得知公钥）证明WOTS-TW及多实例WOTS-TW的安全性。序列组合论证表明，WOTS-TW的安全性足以支撑SPHINCS+的整体紧安全证明。在更技术层面，作者引入了针对哈希函数属性的量子查询复杂度下界，并分析了SPHINCS+中使用的可调谐哈希函数的额外安全属性（如不可检测性）。

## 核心成果

- 提出WOTS-TW的独立描述和安全性分析，作为WOTS的一个新变体
- 恢复SPHINCS+的紧安全证明，仅引入w因子（通常w=16）的损失
- 给出了量子环境下针对哈希函数属性的通用攻击的查询复杂度新下界

## 与本项目关联

**直接竞争**: 本项目基于SPHINCS+构建Fischlin盲签名协议，其安全归约依赖SPHINCS+的安全性。本文修复了SPHINCS+的安全证明基础，直接确保了本项目安全声明的理论有效性。此外，WOTS-TW的分析方法也可参考用于分析本项目中的Poseidon2哈希构造。
