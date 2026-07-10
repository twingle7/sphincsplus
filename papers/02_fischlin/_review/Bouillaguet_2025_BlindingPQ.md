# Blinding Post-Quantum Hash-and-Sign Signatures

**出处**: IEEE S&P 2026 (接收), ePrint 2025/895
**作者**: Charles Bouillaguet, Thibauld Feneuil, Jules Maire, Matthieu Rivain, Julia Sauvage, Damien Vergnaud

## 论点
提出"承诺-追加-证明"(CAP)系统，将Fischlin框架推广至任意后量子哈希-签名方案，构造首批多元密码和编码密码盲签名。

## 背景
现有后量子盲签名多基于格或同源假设，多元密码和编码密码领域的盲签名尚属空白。Fischlin框架的已有实例化无法直接推广至非代数结构的哈希-签名方案。

## 技术路线
引入CAP系统，该系统的承诺可在追加证据后更新，再执行证明——这一推广解决了此前Fischlin变体无法适用于任意哈希-签名方案的技术障碍。基于最近MPC-in-the-Head技术实现高效CAP系统。将框架应用于UOV(多元)和Wave(编码)签名方案。

## 核心成果
1. 首批多元密码盲签名(UOV，3.8-11 KB)和编码密码盲签名(Wave)
2. 盲UOV签名显著优于此前最紧凑的格盲签名(22 KB)
3. 方案满足设计上的盲性，仅依赖底层签名安全性和ROM即实现单次不可伪造性

## 与本项目关联
直接竞争: 与本项目同属后量子Fischlin框架实例化。CAP系统技术与本项目采用的STARK + Poseidon2技术路线形成重要对照——两者均为从经典Fischlin到后量子设置的桥接。
