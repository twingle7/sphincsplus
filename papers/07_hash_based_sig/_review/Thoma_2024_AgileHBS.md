# Agile Acceleration of Stateful Hash-based Signatures in Hardware

**出处**: ACM Transactions on Embedded Computing Systems (TECS), Vol. 23, No. 2, Article 29, 2024
**作者**: Jan Philipp Thoma, Darius Hartlief, Tim Güneysu

## 论点
首个同时支持 LMS 和 XMSS 的敏捷（agile）硬件加速器，通过利用两种方案的架构相似性，以仅增加 20% LUT 的面积开销实现了方案可切换能力。

## 背景
NIST SP 800-208 同时批准了 LMS/HSS 和 XMSS/XMSS^MT 两种有状态哈希签名方案。在实际部署中，设备可能需要同时支持两种方案以满足不同的应用需求或合规要求。然而已有硬件实现通常仅支持其中一种。LMS 和 XMSS 虽然共享类似的多层 Merkle 树架构和基于 Winternitz 的 OTS，但在链函数构造、随机化方式等方面存在差异，增加了统一硬件设计的难度。

## 技术路线
论文的核心方法是"敏捷设计"——通过分析 LMS 和 XMSS 的共性（Merkle 树结构、OTS 验证、哈希调用模式）和差异（链函数的不同、address 格式的不同），设计了一种可配置的硬件架构。通过一个简单的配置信号即可在两种方案间切换。设计支持可扩展的哈希核心数量，允许针对不同应用场景在面积和吞吐量之间权衡。基于 Xilinx Artix-7 FPGA（NIST 推荐的 PQC 评估平台）进行了实现和评估。

## 核心成果
- 首个同时支持 LMS 和 XMSS 的敏捷硬件加速器
- 相比单一 XMSS 实现，面积仅增加 20% LUT 和 3% 触发器
- 支持哈希核心数量和加速器模块的可配置扩展

## 与本项目关联
**方法论参考**: Thoma 等人在处理两种相似方案的统一硬件设计时采用的"共性提取-差异参数化"方法，可迁移到本项目的多方案支持场景中。例如，本项目同时支持多种 SPHINCS+ 参数集（不同安全等级、不同哈希后端），敏捷加速器的设计理念有利于构建统一的硬件加速方案。
