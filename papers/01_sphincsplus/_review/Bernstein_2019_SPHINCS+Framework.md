# The SPHINCS+ Signature Framework

**出处**: ACM CCS 2019, pp. 2129-2146
**作者**: Daniel J. Bernstein, Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, Peter Schwabe

## 论点
SPHINCS+ 框架统一了无状态哈希签名设计，通过 FORS 少次签名方案和可调哈希函数抽象，在速度、签名尺寸和安全性三个维度上同时超越此前所有基于哈希的签名方案。

## 背景
此前基于哈希的签名方案面临两大挑战：SPHINCS (Eurocrypt 2015) 使用的 HORST 方案效率有限，且安全性分析依赖于特定哈希函数属性。NIST PQC 标准化要求方案具有可证明安全性和高性能。SPHINCS+ 需要解决签名尺寸过大和安全性边界不清晰的核心问题。

## 技术路线
论文引入三项核心创新：第一，FORS（Forest Of Random Subsets）取代 HORST 作为少次签名方案，通过随机子集森林结构降低签名尺寸；第二，可调哈希函数抽象层，将哈希调用与具体后端解耦，支持统一的、模块化的安全性归约；第三，基于此抽象层给出了紧致的安全归约，证明安全性基于可调哈希函数的决策性第二原像抵抗（DSPR）等性质。框架支持简单（simple）和鲁棒（robust）两种可调哈希实例化方式。

## 核心成果
- FORS 方案显著减少了签名尺寸，使 SPHINCS+ 在 NIST PQC 第二轮中成为最高效的哈希签名方案
- 可调哈希抽象成为后续 XMSS、LMS 等方案安全性分析的统一框架
- 论文方案最终入选 NIST 标准化，成为 FIPS 205 (SLH-DSA) 的技术基础

## 与本项目关联
**方法论参考**: 本项目完整继承了 SPHINCS+ 框架，包括 FORS、WOTS+、hypertree 和可调哈希架构。Poseidon2 哈希后端通过可调哈希接口（hash_poseidon2_adapter.[ch]）集成，严格遵循论文定义的可调哈希原则。
