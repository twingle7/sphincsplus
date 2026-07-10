# Practical Round-Optimal Blind Signatures in the ROM from Standard Assumptions

**出处**: ASIACRYPT 2023, LNCS Vol. 14439, pp. 383-417
**作者**: Shuichi Katsumata, Michael Reichle, Yusuke Sakai

## 论点
提出Fischlin通用盲签名构造的高度优化变体，逐步弱化所需基础模块。在标准配对假设（CDH/DDH/SXDH）下构造两个方案——方案一签名+通信约750字节，方案二签名仅96字节。

## 背景
Fischlin（CRYPTO 2006）的通用构造需要PKE+在线可提取NIZK两个强假设。Katsumata等通过逐步替代将这些假设弱化为承诺方案+重绕可提取NIZK。

## 技术路线
- 模块弱化：PKE→承诺方案，在线可提取NIZK→重绕可提取NIZK
- 方案一（CDH）：签名+通信≈750字节
- 方案二（SXDH）：签名仅96字节，是目前最小的盲签名之一
- 随机预言机模型下的安全证明

## 核心成果
- 96字节签名——盲签名大小的新纪录
- 仅依赖标准配对假设（非量子安全）
- Fischlin框架的最优效率实例化

## 与本项目关联
**方法论参考**: 证明了Fischlin框架可以高度优化。虽然Katsumata方案基于配对（非后量子），但其模块弱化思路可借鉴——本项目用STARK替代NIZK也是模块替换的一种形式。96字节的目标为本项目的证明大小优化提供了参照。
