# A Tight Security Proof for SPHINCS+, Formally Verified

**出处**: ASIACRYPT 2024, LNCS Vol. 15487, pp. 35-67
**作者**: Manuel Barbosa, Francois Dupressoir, Andreas Hülsing, Matthias Meijers, Pierre-Yves Strub

## 论点
使用EasyCrypt证明辅助工具对SPHINCS+进行完整的机器验证紧致安全证明——解决了原始证明中被发现的缺陷（Kudinov等, 2020），首次实现了SPHINCS+的形式化验证安全归约。

## 背景
Hülsing和Kudinov (ASIACRYPT 2022)修复了SPHINCS+原始安全证明中的紧致性缺陷，但该修复本身未经过机器验证。形式化验证可消除手工证明中的人为错误。

## 技术路线
- EasyCrypt：概率程序的形式化验证框架
- 将SPHINCS+的THF安全归约编码为EasyCrypt中的概率实验
- 四个游戏之间的紧致归约：Game 0（真实方案）→ Game 1-3（逐步理想化）→ 安全性
- WOTS-TW变体的形式化定义

## 核心成果
- 第一个经过机器验证的SPHINCS+紧致安全证明
- 修复了原始证明中的缺陷
- 为SPHINCS+标准化提供了最高级别的安全性保证

## 与本项目关联
**方法论参考**: 本项目THF安全分析可借鉴EasyCrypt形式化验证方法。如果将来需要为Poseidon2版SPHINCS+提供更严格的安全性保证，EasyCrypt验证是一条可行路径。
