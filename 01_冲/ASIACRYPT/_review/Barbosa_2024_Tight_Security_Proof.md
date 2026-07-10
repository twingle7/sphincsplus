# A Tight Security Proof for SPHINCS+, Formally Verified

**出处**: ASIACRYPT 2024
**作者**: Manuel Barbosa, Francois Dupressoir, Andreas Hulsing, Matthias Meijers, Pierre-Yves Strub

## 论点

使用EasyCrypt证明辅助工具为SPHINCS+（即NIST标准化中的SLH-DSA）构造了一个机器检验的紧安全归约，恢复了最初被证明有缺陷的紧安全上界。

## 背景

SPHINCS+是后量子时代最保守的签名方案，但其最初的紧安全证明于2020年被Kudinov等人发现存在漏洞。紧安全归约对于标准化参数集的置信度评估至关重要，此前虽然Hulsing和Kudinov（2022）给出了修复，但尚未经过机器验证。本工作将该修复转化为形式化验证的安全定理。

## 技术路线

作者以模块化方式重构了Hulsing-Kudinov（2022）的紧安全证明，将其编码为EasyCrypt中的可检查证明。核心挑战在于一个涉及四个游戏同时关联的复杂论证（四游戏跃迁），这是EasyCrypt此前尚未形式化的推理模式。作者为此开发了通用的形式化验证技术，并扩展了EasyCrypt中哈希函数和Merkle树的现有库，为后续哈希基密码构造的形式化验证提供了可复用构件。

## 核心成果

- 首次为SPHINCS+提供机器检验的紧安全证明，覆盖标准化参数集
- 开发了EasyCrypt中四游戏跃迁的形式化技术，填补了工具的能力空白
- 发布了改进的哈希函数库和全新的Merkle树库，降低了后续工作门槛

## 与本项目关联

**方法论参考**: 本项目使用Poseidon2+STARK构造Fischlin盲签名中的零知识证明，其安全性依赖于底层SPHINCS+的安全假设。本文验证了SPHINCS+的紧安全界，为我们的安全性声明提供了更强的基础支撑。形式化验证的方法论也可用于未来验证STARK证明系统的安全性。
