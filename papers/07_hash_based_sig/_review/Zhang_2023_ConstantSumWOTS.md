# Revisiting the Constant-Sum Winternitz One-Time Signature with Applications to SPHINCS+ and XMSS

**出处**: CRYPTO 2023, Part V, pp. 455-483
**作者**: Kaiyi Zhang, Hongrui Cui, Yu Yu（上海交通大学）

## 论点
常量和 WOTS+（constant-sum WOTS+）不仅是 Winternitz 框架下尺寸最优的一次性签名设计，在所有基于树的 OTS 设计中也是尺寸最优的；同时指出了此前被认为最优的 DAG 方案中存在安全缺陷。

## 背景
WOTS+ 是 SPHINCS+、XMSS、LMS 等 NIST 标准化哈希签名方案的核心构建块，其效率直接影响整个方案的性能。Bos 和 Chaum（Crypto 1992）提出了常量和编码的 Winternitz 变体，但其最优性（是否在所有基于树的 OTS 设计中不可改进）以及其与 Asiacrypt 1996 中 DAG 方案的比较，长期以来没有定论。

## 技术路线
论文从理论最优性和实际性能两个角度进行了分析。理论上，证明了常量和 WOTS+ 在基于树的 OTS 设计类中达到尺寸最优——给出了下界并构造了匹配上界的方案。同时发现了 Asiacrypt 1996 所谓的"DAG 最优 OTS"存在安全性缺陷（密钥不可区分性问题），使得常量和 WOTS+ 成为目前已知最尺寸高效的 OTS。实际方面，将常量和 WOTS+ 集成到 SPHINCS+ 和 XMSS 中，在签名时间和签名尺寸上均观察到改进。

## 核心成果
- 证明常量和 WOTS+ 在所有基于树的 OTS 设计中尺寸最优
- 发现此前认为最优的 DAG OTS（Asiacrypt 1996）中的安全缺陷
- 集成到 SPHINCS+ 和 XMSS 后，签名尺寸和签名时间均有改进

## 与本项目关联
**直接竞争**: 常量和 WOTS+ 的尺寸最优性结论意味着 SPHINCS+ 的 WOTS+ 组件在当前 OTS 框架下已无进一步优化的理论空间。本项目的 STARK 证明需处理最优尺寸的 WOTS+ 链，其证明效率受限于此最优性。论文对 SPHINCS+ 的改进可直接影响本项目 Fischlin 协议中的签名性能。
