# The SPHINCS+ Signature Framework

**出处**: ACM CCS 2019, pp. 2129-2146
**作者**: Daniel J. Bernstein, Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, Peter Schwabe

## 论点
提出SPHINCS+——无状态哈希签名框架，引入FORS（随机子集森林）和THF（可调哈希函数）抽象，统一了哈希签名的安全分析。

## 背景
SPHINCS（2015）是首个实用无状态哈希签名，但签名41KB。NIST后量子标准化需要更高效的方案。此前缺乏统一的THF安全框架。

## 技术路线
- FORS：k个Merkle树森林，每树t=2^a叶节点
- THF抽象：统一WOTS+/FORS/XMSS为THF调用，四个性质（SM-TCR/DSPR/PRE/UD）
- Hypertree：d层XMSS树，底层FORS
- simple/robust两种THF实例化

## 核心成果
- 成为NIST FIPS 205（SLH-DSA）基础
- 签名7.8-49.8KB
- 紧致安全归约：8n-bit经典安全

## 与本项目关联
**背景知识/方法论参考**: 本项目直接基于SPHINCS+框架，用Poseidon2替换SHA-256，保持THF语义不变。
