# The SPHINCS+ Signature Framework

**出处**: ACM CCS 2019, pp. 2129-2146
**作者**: Daniel J. Bernstein, Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, Peter Schwabe

## 论点
提出SPHINCS+——一个无状态哈希签名框架，引入FORS（随机子集森林）作为新的少次签名方案，统一了哈希签名的安全分析。

## 背景
SPHINCS（2015）是首个实用无状态哈希签名，但签名大小达41KB。后量子密码标准化进程中，NIST需要更高效的无状态哈希签名方案。同时，已有方案的安全分析缺乏统一框架。

## 技术路线
- FORS：k个Merkle树的森林，每棵树有t=2^a个叶节点，大幅提升签名效率
- THF（可调哈希函数）抽象：将WOTS+、FORS、XMSS统一为THF调用
- Hypertree：d层XMSS树，底层用FORS签名消息摘要
- "simple"和"robust"两种THF实例化模式
- 安全证明完全基于THF的四个性质（SM-TCR/SM-DSPR/SM-PRE/SM-UD）

## 核心成果
- 成为NIST后量子签名标准FIPS 205（SLH-DSA）的基础方案
- 签名大小从7.8KB到49.8KB（6个参数集×2种模式）
- 紧致安全归约：8n-bit经典安全性

## 与本项目关联
**背景知识/方法论参考**: 本项目直接基于SPHINCS+框架，替换其SHA-256/SHAKE-256为Poseidon2，保持THF语义不变。理解FORS/WOTS+/Hypertree结构是理解本项目的先决条件。
