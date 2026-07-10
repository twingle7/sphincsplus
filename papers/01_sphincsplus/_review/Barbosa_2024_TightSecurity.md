# A Tight Security Proof for SPHINCS+, Formally Verified

**出处**: ASIACRYPT 2024, LNCS Vol. 15487, pp. 35-67
**作者**: Manuel Barbosa, Francois Dupressoir, Andreas Hülsing, Matthias Meijers, Pierre-Yves Strub

## 论点
SPHINCS+ 的紧致安全性归约可以通过 EasyCrypt 证明助手进行机器验证，解决了 2020 年发现的原始紧致证明中的缺陷，为标准化参数集提供了可靠的安全性基础。

## 背景
SPHINCS+ 在 2022 年被 NIST 选中标准化，但其原始紧致安全性证明由 Kudinov、Kiktenko 和 Fedorov 在 2020 年指出存在缺陷。此后 Hülsing 和 Kudinov（2022 年）提出了修正后的紧致归约，但该归约涉及复杂的多游戏混合论证，手工验证难度极大，需要形式化验证工具来建立更高置信度。

## 技术路线
论文使用 EasyCrypt 证明助手对 SPHINCS+ 的紧致安全性归约进行了机器验证。关键挑战在于归约需要同时关联四个不同的安全游戏（涉及 EUF-CMA 安全、PRF 安全、DSPR 安全和多目标哈希安全），这种四游戏同时论证此前尚未在 EasyCrypt 中完成形式化。论文为此开发了一种通用的形式化验证技术。此外，作者扩展了 EasyCrypt 中可重用的哈希密码学库，包括对 Merkle 树的完整形式化。

## 核心成果
- 首次完成对 SPHINCS+ 紧致安全性归约的机器验证形式化证明
- 确认 NIST 标准化参数集的安全性边界可靠
- 为后续基于哈希的密码方案的形式化验证提供了可复用的工具库

## 与本项目关联
**方法论参考**: 本项目的安全性分析基于与 SPHINCS+ 相同的归约框架。论文的形式化验证方法为证明 Fischlin 协议的紧致安全性提供了方法论参考——特别是当需要同时关联多个安全游戏时。本项目的 STARK 证明系统的安全性也可借鉴类似的形式化验证思路。
