# Blinding Post-Quantum Hash-and-Sign Signatures

**出处**: IEEE S&P 2026 (accepted), IACR ePrint 2025/895
**作者**: Charles Bouillaguet, Thibauld Feneuil, Jules Maire, Matthieu Rivain, Julia Sauvage, Damien Vergnaud

## 论点
提出"承诺-追加-证明"（CAP）系统，将Fischlin轮次最优盲签名框架推广到任意后量子hash-and-sign签名方案。构造了首个来自多元密码（UOV）和编码密码（Wave）的实用盲签名。

## 背景
Fischlin框架理论上支持任意签名方案，但实际实例化需要高效的NIZKPoK。此前后量子盲签名集中于格密码。多元密码和编码密码此前被认为不适用于盲签名构造。

## 技术路线
- CAP系统：Commit（承诺消息）→ Append（追加公开数据）→ Prove（NIZKPoK证明签名有效）
- 使用MPC-in-the-Head技术实现NIZKPoK：将签名验证电路分解为MPC协议
- UOV实例化：签名3.8-11KB
- Wave实例化：基于编码假设，签名大小与UOV相当
- 证明大小比格基方案更小
- 安全性归约到MQ问题（多元）和编码解码问题（Wave）

## 核心成果
- 首个多元密码盲签名（UOV: 3.8-11KB）——目前最小的后量子盲签名之一
- 首个编码密码盲签名（Wave）
- 将Fischlin框架的后量子实例化空间从格扩展到多元和编码
- 发表在IEEE S&P 2026（安全领域最高级别会议之一）

## 与本项目关联
**直接竞争**: 与本项目共享Fischlin框架的推广目标——都是将Fischlin应用于非格后量子签名。区别在于底层签名类型不同（多元/编码 vs 哈希签名/SPHINCS+）和NIZKPoK技术不同（MPCitH vs STARK）。UOV的3.8KB签名远小于SPHINCS+，但UOV的公钥（~100KB）远大于SPHINCS+。
