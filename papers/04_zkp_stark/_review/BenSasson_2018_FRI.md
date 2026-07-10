# Fast Reed-Solomon Interactive Oracle Proofs of Proximity (FRI)

**出处**: ICALP 2018
**作者**: Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, Michael Riabzev

## 论点
FRI 协议以严格线性复杂度的证明者和严格对数复杂度的验证者实现 Reed-Solomon 码的邻近性测试，是构建高效 IOP 系统和 STARK 协议的核心底层工具。

## 背景
Reed-Solomon 码在概率可检验证明（PCP）和 IOP 系统中扮演核心角色，但验证一个函数是否接近 RS 码字（即"邻近性"测试）的计算代价一直是瓶颈。早期协议的证明者复杂度虽然达到准线性，但验证者仍有额外的多项对数因子开销。FRI 的目标是将两个端都推向理论最优。

## 技术路线
FRI 的核心思想是对多项式进行递归折叠（folding）：在每一轮，将度数为 d 的多项式拆分为偶/奇两部分并组合为度数为 d/2 的新多项式，测试者只需确认折叠正确性即可。与先前方案相比，FRI 在 δ 低于唯一解码半径时仅损失可忽略的加法可靠性，从而允许 Θ(log N) 轮折叠，使查询复杂度降至 2 log N。证明者复杂度 < 6N 次运算，验证者复杂度 < 21 log N 次运算。

## 核心成果
- 证明者严格线性、验证者严格对数的 RS 邻近性测试协议
- 查询复杂度 2 log N 且可靠性损失可忽略
- FRI 成为后续 zk-STARKs、StarkWare 等工业级系统的事实标准低度测试协议

## 与本项目关联
**方法论参考**: Winterfell 框架的核心低度测试协议采用 FRI。本项目中 STARK 证明的生成和验证均依赖于 FRI 协议的高效实现，是项目技术栈的关键组成部分。
