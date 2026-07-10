# Aggregate-Blind Signature Based on Lattices

**出处**: Advances in Mathematics of Communications (AMC), 2026
**作者**: Stuti Kumari, Meenakshi Kansal, Sumit Kumar Debnath

## 论点
提出首个格基聚合盲签名(ABS)方案，在Fischlin签名和中国剩余定理之上同时实现盲签名和签名聚合。

## 背景
聚合签名可将多个签名压缩为一个，盲签名隐藏被签消息内容。此前聚合盲签名仅基于经典假设(离散对数、CDH、大整数分解)，易受量子算法(Shor)攻击。格假设下的聚合盲签名为空白领域。

## 技术路线
方案构建在Fischlin签名框架之上，引入中国剩余定理(CRT)实现签名聚合。安全性基于SIS(Short Integer Solution)问题的困难性，可抵抗量子攻击。允许多个用户对各自消息获得盲签名，再将这些盲签名聚合为单一短签名。

## 核心成果
1. 首个抗量子安全的格基聚合盲签名方案
2. 将聚合签名与盲签名两种功能首次在格基础上结合
3. 安全性基于标准SIS假设，可在随机预言机模型下证明

## 与本项目关联
背景知识: 聚合盲签名为Fischlin框架的功能扩展提供了新思路。本项目暂不涉及聚合功能，但作为未来方向有潜在参考价值。
