# Recovering the Tight Security Proof of SPHINCS+

**出处**: ASIACRYPT 2022
**作者**: Andreas Hülsing, Mikhail Kudinov

## 论点
修复了SPHINCS+原始紧致安全证明中于2020年发现的缺陷，给出了几乎相同安全界的新紧致归约（仅损失因子w=16），并正式定义了SPHINCS+中使用的WOTS变体为WOTS-TW。

## 背景
SPHINCS+的原始安全证明声称紧致归约（安全损失仅2-3比特），但2020年发现的缺陷威胁了这一核心安全属性。鉴于SPHINCS+已被NIST标准化，修复证明至关重要。

## 技术路线
- 识别缺陷：原始证明中THF性质的多目标转换存在逻辑跳跃
- WOTS-TW：正式定义SPHINCS+中使用的WOTS+变体（与标准WOTS+略有不同）
- 新归约链：通过修正的THF→游戏跳转序列恢复紧致性
- 损失因子w=16（即log₂(16)=4比特额外安全损失）

## 核心成果
- 修复了NIST标准化方案的核心安全证明
- 紧致归约几乎完全恢复（仅4比特额外损失）
- WOTS-TW的正式规范

## 与本项目关联
**方法论参考**: WOTS-TW的正式定义直接影响本项目Poseidon2版SPHINCS+中WOTS+的正确实现。安全证明的修复方法（多目标→单目标归约）可指导THF安全分析。
