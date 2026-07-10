# Practical Round-Optimal Blind Signatures in the ROM from Standard Assumptions

**出处**: ASIACRYPT 2023, ePrint 2023/1447
**作者**: Shuichi Katsumata, Michael Reichle, Yusuke Sakai

## 论点
在随机预言机模型(ROM)下，基于标准配对假设构造高度实用的轮次最优盲签名，逐步弱化Fischlin通用构造所需的基础模块。

## 背景
区块链和隐私认证令牌等新兴应用推动了盲签名的实践需求。Fischlin框架虽具通用性，但构造出的方案效率不足。此前轮次最优方案在签名尺寸和通信开销上均未满足实际部署要求。

## 技术路线
提出两种构造路线：(1) Fischlin框架的高度优化变体，系统地弱化每个底层模块，签名447字节、通信303字节，总和首次低于1KB；(2) 从可随机化签名方案的半通用构造，签名仅96字节。两者均基于非对称配对群的标准假设(CDH/DDH/SXDH)，并依赖对分叉引理的细粒度非黑盒分析。

## 核心成果
1. Fischlin框架的首个实用级实例化，签名+通信不到1KB
2. 基于可随机化签名的最优签名尺寸(96B)，通信仅2.2KB
3. 为非黑盒分叉引理分析提供了全新的技术工具

## 与本项目关联
方法论参考: 展示了Fischlin框架在经典安全假设下的高效实例化路径，其优化策略(弱化基础模块)对后量子Fischlin实例化有重要借鉴意义。
