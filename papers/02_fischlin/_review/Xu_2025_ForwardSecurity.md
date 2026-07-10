# An Efficient Anti-Quantum Blind Signature with Forward Security for Blockchain-enabled IoMT

**出处**: Computers, Materials & Continua (CMC), Vol. 82, No. 2, pp. 2293-2309, 2025
**作者**: Gang Xu, Xinyu Fan, Xiu-Bo Chen, Xin Liu, Zongpeng Li, Yanhui Mao, Kejia Zhang

## 论点
提出格基前向安全盲签名(LFSBS)方案，用于区块链赋能的医疗物联网(BIoMT)中的隐私保护。

## 背景
医疗数据在BIoMT中的传输涉及大量敏感隐私信息。现有盲签名方案面临两个关键威胁：密钥泄露风险和量子计算攻击风险。同时满足前向安全性和抗量子性尚属挑战。

## 技术路线
基于二元树结构构建密钥进化机制，保证即使未来密钥泄露，过去的数据仍保持安全。整个方案基于格上SIS问题的困难假设，抵抗量子攻击。在随机预言机模型中形式化定义并证明盲性和前向安全不可伪造性。

## 核心成果
1. 首个同时实现前向安全和抗量子安全的盲签名方案
2. 比起前方案计算开销降低22%-73%
3. 提供完整的形式化安全模型和证明，涵盖盲性和前向安全不可伪造性

## 与本项目关联
背景知识: 其前向安全密钥进化机制是盲签名安全和实用性的重要补充。本项目的Fischlin盲签名目前未考虑前向安全性，可作为未来扩展方向。
