# Compact Stateful Deterministic Wallet from Isogeny-Based Signature Featuring Uniquely Rerandomizable Public Keys

**出处**: CANS 2023
**作者**: Surbhi Shaw, Ratna Dutta

## 论点
基于同源密码的确定性钱包可实现后量子安全迁移，且CSI-SharK实例化下签名尺寸为目前最紧凑的后量子可重随机化签名。

## 背景
确定性钱包（deterministic wallet）是加密货币中保护用户资产的核心原语。Das等人（CCS 2019）给出了基于具有可重随机化密钥的签名方案的通用构造，但BLS/ECDSA实例化不抗量子。同源密码为后量子替代提供了可能。

## 技术路线
基于CSI-FiSh和CSI-SharK同源签名方案，设计具有唯一可重随机化公钥特性的签名方案。利用同源密码的交换性实现密钥重随机化：对公钥进行同源映射得到新公钥及对应签名转化算法。将CSI-FiSh实例化集成到确定性钱包框架中，给出钱包不可链接性和不可伪造性的形式化证明。

## 核心成果
1. CSI-SharK实例化给出目前最紧凑的后量子可重随机化签名。
2. 首个基于同源的确定性钱包，密钥尺寸紧凑。
3. 在标准模型下证明钱包的不可链接性和不可伪造性。

## 与本项目关联
背景知识：同源密码是后量子公钥密码的三大主线之一，该工作中可重随机化公钥的设计思路与SPHINCS+中FORS/WOTS+公钥派生机制有概念上的相通性。
