# Post Quantum-Resistant Blind Signature Scheme for Consumer IoT Security

**出处**: IEEE Transactions on Consumer Electronics, Vol. 71, No. 2, pp. 4949-4958, 2025
**作者**: Mohammed E. Seno, Janjhyam Venkata Naga Ramesh, Aadam Quraishi, Azzah A. Alghamdi, K. D. V. Prasad, Divya Nimma, Yelisela Rajesh, Uguloy Berdieva, Mukesh Soni

## 论点
基于NIST后量子标准化算法CRYSTALS-Dilithium，构造适用于消费电子IoT(CIoT)环境的抗量子盲签名方案。

## 背景
传统盲签名方案基于RSA或椭圆曲线，易受量子计算攻击。消费电子IoT设备面临计算资源受限和量子威胁的双重压力，急需抗量子轻量级盲签名方案。

## 技术路线
将CRYSTALS-Dilithium签名算法扩展为盲签名方案：设计盲化协议使得用户可对Hash值进行盲化，签名者使用Dilithium对盲化消息签名，用户去盲后恢复标准Dilithium签名。安全性依赖于Dilithium所依赖的Module-LWE和Module-SIS困难问题。

## 核心成果
1. 首个基于NIST标准Dilithium的盲签名方案
2. 面向消费电子IoT的应用场景，关注资源受限设备的计算可行性
3. 填补了传统盲签名向后量子过渡过程中的工程应用空白

## 与本项目关联
背景知识: 同为后量子盲签名方案，但基于Dilithium(格)而非SPHINCS+(哈希)。其IoT应用场景和性能评估方法对本项目的应用落地有参考意义。
