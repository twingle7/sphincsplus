# CSI-IBBS: Identity-Based Blind Signature using CSIDH

**出处**: arXiv:2509.06127, 2025
**作者**: Soumya Bhoumik, Sarbari Mitra, Rohit Raj Sharma, Kuldeep Namdeo

## 论点
利用CSIDH(交换超奇异同源Diffie-Hellman)框架，提出首个基于同源的身份基盲签名方案。

## 背景
身份基密码学消除了证书管理的开销。Katsumata等首次给出基于同源的盲签名协议(类Schnorr盲签名)。将身份基密码与盲签名在同源假设下结合，可同时获得身份基的可扩展性和盲签名的隐私性。

## 技术路线
基于CSIDH框架，将盲签名与诚实零知识验证者协议结合。利用CSIDH的抗量子特性(超奇异同源)，安全性基于群作用逆问题(GAIP)及其多目标变体(MT-GAIP)。在标准模型下证明安全。签名约9 KB(128位安全)/37 KB(256位安全)。

## 核心成果
1. 首个基于CSIDH的身份基盲签名方案
2. 在标准模型(非ROM)下可证明安全
3. 展示了同源假设在后量子盲签名中的实际可行性

## 与本项目关联
背景知识: 同源盲签名是本项目哈希盲签名的正交技术路线。身份基特性可为本项目未来支持更灵活密钥管理提供思路。
