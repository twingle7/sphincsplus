# Lattice-based blockchain platform for IoT: Privacy-enhanced application with lattice-based blind signatures

**出处**: Computer Standards & Interfaces, Vol. 96, Article 104077, 2025
**作者**: Bora Bugra Sezer, Sedat Akleylek

## 论点
将基于MLWE（模学习带误差）的格基盲签名集成到物联网区块链平台中，结合多层级结构、STARK零知识证明和Kyber/Dilithium后量子原语，可以实现设备层级的匿名认证和量子安全数据交换。

## 背景
物联网设备数量激增，区块链提供的去中心化信任机制与设备隐私需求之间存在张力。现有盲签名方案大多基于经典安全假设，面临量子计算威胁。同时，物联网设备的资源受限特性要求密码方案在安全性与效率之间取得平衡。作者提出将后量子盲签名直接嵌入区块链平台架构。

## 技术路线
基于MLWE问题构造新型格基盲签名，将其整合到具备多层结构（MLS）的物联网区块链框架中。使用Kyber提供安全随机性以增强盲化过程抗量子能力，以Dilithium确保数据完整性和不可否认性，并引入STARK协议实现零知识验证而不暴露设备身份。附加阈值逻辑时钟（TLC）和基于事件的智能合约（EBSC）以降低通信开销。采用电化学传感器数据作为评估案例。

## 核心成果
1. 提出首个集成了MLWE盲签名的完整后量子物联网区块链平台框架，覆盖设备注册、匿名认证和数据交换全流程。
2. 通过多层架构和事件驱动智能合约优化了IoT场景下的通信效率。

## 与本项目关联
**背景知识**: 展示了后量子盲签名+STARK验证在物联网区块链中的系统集成方案，与本项目的"Fischlin协议+STARK"技术栈在架构层面具有平行参考价值。
