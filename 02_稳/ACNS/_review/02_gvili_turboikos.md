# TurboIKOS: Improved Non-interactive Zero Knowledge and Post-Quantum Signatures

**出处**: ACNS 2021
**作者**: Yaron Gvili, Julie Ha, Sarah Scheffler, Mayank Varia, Ziling Yang, Xinyuan Zhang

## 论点
通过优化MPC-in-the-Head协议中Beaver三元组的通信效率，可构造通信量更低的非交互零知识证明系统。

## 背景
IKOS协议（Ishai et al., CRYPTO 2007）将MPC协议转化为ZK证明系统，是构造Picnic等后量子签名的基础。其每乘法门需4个域元素的通信开销，限制了实际效率。

## 技术路线
论文在IKOS框架内引入Beaver三元组消耗技术：基于Baum-Nof（PKC 2020）的三元组牺牲（triple sacrificing）方法，将每个乘法门的通信量从4个域元素降至2个，匹配Katz-Kolesnikov-Wang（CCS 2018）的cut-and-choose方法，同时保持较低的附加开销。协议为公开硬币、常数轮，经Fiat-Shamir转换为NIZK。给出完整实现并评估其在Picnic风格后量子签名上的性能。

## 核心成果
1. 每乘法门通信量降至2个域元素，为目前IKOS类方案中最优。
2. 基于AES电路的后量子签名实例化展示了实际效率提升。
3. 证明系统保持公开可验证性和常量轮复杂度。

## 与本项目关联
方法论参考：MPC-in-the-Head范式零知识证明是构造后量子签名的重要路径，其效率优化技术对理解ZK-STARK与Fischlin协议中的证明系统设计有参考价值。
