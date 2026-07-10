# SPHINCS+ -- Submission to the NIST Post-Quantum Project, v.3.1

**出处**: NIST PQC Round 3 提交书, 2022
**作者**: Jean-Philippe Aumasson, Daniel J. Bernstein, Ward Beullens, Christoph Dobraunig, Maria Eichlseder, Scott Fluhrer, Stefan-Lukas Gazdag, Panos Kampanakis, Stefan Kölbl, Tanja Lange, Martin M. Lauridsen, Florian Mendel, Ruben Niederhagen, Christian Rechberger, Joost Rijneveld, Peter Schwabe, Bas Westerbaan（18位提交者，主提交人 Andreas Hülsing）

## 论点
SPHINCS+ 是 NIST 后量子密码标准化项目中最终入选的无状态哈希签名方案，其 v3.1 规范定义了基于 SHA-2 和 SHAKE256 的完整参数集，为后续标准化为 FIPS 205 (SLH-DSA) 奠定基础。

## 背景
NIST 于 2016 年启动后量子密码标准化项目，SPHINCS+ 作为唯一的基于哈希的签名候选方案进入第三轮。与其他候选方案（如基于格的 CRYSTALS-Dilithium）不同，SPHINCS+ 的安全性仅依赖于底层哈希函数的抗（第二）原像攻击强度，是最保守的安全假设。

## 技术路线
SPHINCS+ 采用 SPHINCS+ 框架（CCS 2019）定义的多层架构：WOTS+ 作为一次性签名构建块、FORS 作为少次签名方案、XMSS 多树（hypertree）实现大规模签名能力，并通过可调哈希抽象统一安全分析。v3.1 版本包含 12 个官方参数集，涵盖 NIST 安全等级 1/3/5 的"快"和"小"两种变体。

## 核心成果
- 最终入选 NIST 后量子标准化，成为唯一被选中的基于哈希的签名方案
- 提供 12 个参数集，覆盖 SHA-2 和 SHAKE256 两种哈希后端
- 签名尺寸范围从 7,856 字节（128s）到 49,856 字节（256f）

## 与本项目关联
**方法论参考**: 本项目选用 SPHINCS+ 作为底层签名方案，在其上构建 Fischlin 盲签名协议。v3.1 的参数选择直接指导了开发参数集（如 sphincs-poseidon2-192s）的设计和安全性分析。
