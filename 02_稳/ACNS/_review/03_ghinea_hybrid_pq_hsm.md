# Hybrid Post-Quantum Signatures in Hardware Security Keys

**出处**: ACNS 2023（Best Workshop Paper Award）
**作者**: Diana Ghinea, Fabian Kaczmarczyck, Jennifer Pullman, Julien Cretin, Stefan Kölbl, Rafael Misoczki, Jean-Michel Picod, Luca Invernizzi, Elie Bursztein

## 论点
ECDSA与Dilithium的混合签名方案可在当前硬件安全密钥上实际部署，兼顾经典安全与后量子安全。

## 背景
量子计算对当前广泛使用的RSA/ECDSA构成威胁，但纯后量子迁移需要长时间过渡。混合签名（hybrid signature）提供增量迁移路径：即使一个组件被攻破，另一个仍保证安全性。硬件安全密钥（如FIDO U2F）资源受限，部署后量子签名面临存储和计算瓶颈。

## 技术路线
设计ECDSA+Dilithium混合签名方案，确保签名不可由任一组分单独伪造。在nRF52840开发板上实现，将其集成到Google的OpenSK开源安全密钥固件中。评估包括签名生成时间、RAM占用、固件体积等关键指标，分析混合方案在资源受限设备上的可行性。

## 核心成果
1. 首个在真实硬件安全密钥上实现并验证的ECDSA+Dilithium混合签名。
2. 开源发布实现代码（OpenSK hybrid-pqc版本）。
3. 获ACNS 2023最佳研讨会论文奖，表明该工作对后量子密码迁移路径的重要工程参考价值。

## 与本项目关联
背景知识：后量子签名的工程化部署（尤其是混合模式）是本项目Fischlin最终协议实际落地的重要参考，SPHINCS+作为NIST标准化方案同样面临与现有PKI体系的融合挑战。
