# Random Oracles in a Quantum World

**出处**: ASIACRYPT 2011
**作者**: Dan Boneh, Ozgur Dagdelen, Marc Fischlin, Anja Lehmann, Christian Schaffner, Mark Zhandry

## 论点
经典的随机预言机模型（ROM）安全性证明在量子敌手（可进行叠加态查询）下不再自动成立，需要引入量子随机预言机模型（QROM）重新审视安全性。

## 背景
后量子密码学的发展催生了大量抗量子方案，其中许多的安全性证明都在经典 ROM 框架下完成。但量子敌手可以对随机预言机进行量子叠加态查询，这破坏了经典 ROM 证明关键的技术假设（如编程预言机、抽取等）。论文的目标是为后量子密码方案提供一套严格的安全性证明方法论。

## 技术路线
论文首先构造了一个分离示例——一个在经典 ROM 下安全、但在 QROM 下不安全的密码方案，明确证明了经典 ROM 安全性不能直接迁移。随后引入"history-free 归约"概念：归约算法对预言机的回答仅依赖于当前查询本身，而非历史记录。证明满足 history-free 归约的方案可将安全性从经典 ROM 迁移到 QROM。论文以 GPV 签名等格基方案为例验证了这一方法的适用性。

## 核心成果
- 分离经典 ROM 和 QROM，指出 ROM 证明在量子设定下不再安全
- 提出 history-free 归约的概念和 QROM 安全性证明方法论
- 奠定 QROM 作为后量子密码方案安全性评估标准模型的基础

## 与本项目关联
**背景知识**: 本项目的 Fischlin 协议以 Marc Fischlin（本文作者之一）命名。FL 协议（Fischlin 2005）的安全性分析需要在 QROM 下重新审视。本文是理解后量子设定下随机预言机安全性证明的基础文献。
