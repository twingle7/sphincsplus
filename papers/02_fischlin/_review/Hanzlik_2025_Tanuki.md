# Tanuki: New Frameworks for Blind Signatures from Post-Quantum Group Actions

**出处**: ASIACRYPT 2025, ePrint 2025/1100
**作者**: Lucjan Hanzlik, Yi-Fu Lai, Marzio Mula, Eugenio Paracucchi, Daniel Slamanig, Gang Tang

## 论点
提出四个基于密码学群作用的盲签名新框架，首次在不需要交换性的群作用下实现并发安全的盲签名。

## 背景
后量子盲签名多数依赖Fischlin框架和格假设，基于sigma协议的盲化技术在格之外的假设中仍然稀疏。EC'24和PKC'24的攻击揭示了并发安全这一长期未解决的挑战。CSIDH和LESS等群作用假设需要全新的协议设计范式。

## 技术路线
设计四个渐近增强的框架，在交互性需求(从交互式单次到标准逆问题)和签名/密钥尺寸之间提供灵活权衡。最终框架实现多项式并发会话下的安全性——证明是对群作用新型假设(GAIP及其变体)的规约。CSIDH实例~4.5 KB，LESS实例~64.7 KB。

## 核心成果
1. 首批从同源(CSIDH)和编码(LESS)实现可证明并发安全的盲签名
2. 四个框架覆盖从弱假设到强假设的完整频谱
3. 引发后续工作Wombat(EUROCRYPT 2026)，在标准群作用逆假设下进一步优化签名尺寸

## 与本项目关联
背景知识: Tanuki的群作用路线与本项目基于哈希/对称密码的盲签名路线正交，但其并发安全分析方法和安全定义为本项目提供重要参考。
