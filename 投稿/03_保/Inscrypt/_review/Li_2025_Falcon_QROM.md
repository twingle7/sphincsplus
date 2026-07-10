# Tighter Security Proof of Falcon+ in the Quantum Random Oracle Model

**出处**: Inscrypt, 2025
**作者**: Jiacheng Li, Haodong Jiang, Hong Wang, Qianheng Duan

## 论点
在量子随机预言机模型(QROM)下为Falcon+方案提供更紧的安全性证明，将区分优势从朴素组合的4q^2ε改进为qε。

## 背景
Falcon是NIST已标准化的基于NTRU格的数字签名方案，遵循GPV（Gentry-Peikert-Vaikuntanathan）全域哈希框架但使用Renyi散度替代统计距离。Gajland等人提出了改进变体Falcon+并给出了经典安全证明，但其量子安全性（QROM中的安全性）此前是未解决的问题。

## 技术路线
1. 首先展示了朴素组合现有技术（量子预言机差异评估、自适应重编程和Pinsker不等式）会带来4q^2ε的大归约损失。
2. 深入分析Falcon+中量子预言机的分布特性，利用这些特性显著改进了区分优势。
3. 证明区分优势从O(q^2ε)降低到O(qε)，实现了在QROM下更紧的安全归约。
4. 该紧化技术不限于Falcon特定，可为其他GPV类签名方案提供通用的紧化方法。

## 核心成果
- 首次给出Falcon+在量子随机预言机模型下的严格安全证明。
- 将归约损失从O(q^2ε)改进到O(qε)，显著缩小了理论安全边界与实际攻击之间的差距。
- QROM紧化方法论对于其他哈希签名方案（如SPHINCS+）的量子分析也具参考价值。

## 与本项目关联
方法论参考: 本项目中的Fischlin协议在QROM中也有安全性论证需求。该文在QROM中紧化安全证明的方法论（特别是利用预言机分布特性）为本项目的QROM安全性分析提供了可借鉴的技术路径。
