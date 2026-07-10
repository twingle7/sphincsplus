# Blinding Post-Quantum Hash-and-Sign Signatures

**出处**: IEEE Symposium on Security and Privacy (S&P), 2026
**作者**: Charles Bouillaguet, Thibauld Feneuil, Jules Maire, Matthieu Rivain, Julia Sauvage, Damien Vergnaud

## 论点
Fischlin框架可推广至任意后量子哈希签名方案，通过"承诺-追加-证明"系统实现轮数最优的盲签名，且安全性仅依赖底层方案的不可伪造性和随机谕言模型。

## 背景
后量子盲签名是隐私保护应用（如电子投票、匿名凭证）的关键组件。此前仅存在基于格的后量子盲签名方案（如22 KB），且缺乏通用构造框架能够将任意后量子哈希签名转换为盲签名。

## 技术路线
论文引入"承诺-追加-证明"（CAP）系统作为核心理论工具，它是承诺-证明系统的推广，支持可更新的承诺。基于MPC-in-the-Head技术给出高效的CAP实例化，再将CAP嵌入Fischlin框架中，以O(1)轮实现盲签名。具体构造了UOV（不平衡油醋）和Wave（编码密码学）的盲签名版本，分别代表了多变量和基于编码的后量子签名方向。

## 核心成果
- 首个将Fischlin盲签名框架系统推广至后量子哈希签名的通用方法
- 盲UOV签名尺寸仅3.8-11 KB，显著优于此前最优的22 KB格基方案
- 安全性证明规范，仅依赖底层签名的标准不可伪造性和ROM假设

## 与本项目关联
**方法论参考**: 本研究同样基于Fischlin框架构建SPHINCS+的盲签名协议。该论文提供的CAP系统和通用构造方法论直接可参考，但其实例化基于UOV/Wave，而本项目的实例化基于SPHINCS+（哈希签名），在底层签名机制和证明策略上具有互补性。
