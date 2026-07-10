# Lattice-Based Universal Designated Multi-Verifiers Signature Scheme

**出处**: ISPEC 2024 (19th Information Security Practice and Experience), Wuhan
**作者**: Yanhua Zhang, Willy Susilo, Yan Chen, Fuchun Guo, Jiaming Wen

## 论点
提出基于格的通用指定多验证者签名方案（UDMVS）——签名者可以指定多个验证者，只有被指定者可以验证签名有效性。

## 背景
标准数字签名的公开可验证性在某些场景下不适用（如私密合同、医疗数据）。指定验证者签名限制验证权限，但现有方案不支持多验证者或基于非抗量子假设。

## 技术路线
- 格密码：基于LWE/SIS假设
- 通用指定：签名者可在签名时动态指定验证者集合
- 多验证者：支持任意数量的指定验证者
- 不可区分性：第三方无法判断签名是否有效

## 核心成果
- 首个基于格的多验证者签名方案
- 后量子安全性
- ISPEC 2024发表

## 与本项目关联
**应用场景参考**: 与本项目盲签名的"限制可见性"方向互补——指定验证者限制谁能验证，盲签名限制签名者能看到什么。两者可组合实现更复杂的隐私保护场景。
