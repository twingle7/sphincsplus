# Practical Round-Optimal Blind Signatures in the ROM from Standard Assumptions

**出处**: ASIACRYPT 2023
**作者**: Shuichi Katsumata, Michael Reichle, Yusuke Sakai

## 论点

在随机预言机模型下，基于标准配对群假设构造两种实用的轮数最优盲签名方案，首次实现标准假设下签名+通信总大小低于1KB。

## 背景

轮数最优盲签名（两轮）的理论构造早已存在，但要么依赖非标准假设，要么效率极低无法实用。Fischlin（CRYPTO 2006）的通用构造虽然优雅，但效率远不能满足实际需求。如何在标准假设下获得真正可部署的短盲签名是该领域的开放问题。

## 技术路线

文章提出两种构造方案。第一种是对Fischlin通用构造的高度优化变体：用承诺方案+重绕可提取NIZK替代原构造中的PKE+在线可提取NIZK，通过Fiat-Shamir启发式大幅提升效率。第二种是半通用构造：利用具有all-but-one归约能力的随机化签名方案（Boneh-Boyen签名）结合Bulletproofs NIZK，首次在ROM中证明Bulletproofs的在线可提取性。两种构造均依赖对分叉引理的细粒度非黑盒分析。

## 核心成果

- 构造一：签名447B，通信303B，总大小约750B——首个标准假设下低于1KB的盲签名
- 构造二：签名仅96B（2个群元素），通信2.2KB，将此前同类方案的通信开销降低约100倍
- 证明了Bulletproofs在ROM中的在线可提取性，具有独立的理论意义

## 与本项目关联

**直接竞争**: 本项目同样构造Fischlin范式的盲签名协议，但采用后量子安全的SPHINCS+签名+Poseidon2哈希+STARK零知识证明。本文的构造基于配对群（非后量子安全），效率指标（签名96-447B）可作为本项目性能优化的参照基准。本项目的后量子安全性是区别于本文的核心优势。
