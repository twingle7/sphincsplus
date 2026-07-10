# Spinel: A Post-Quantum Signature Scheme Based on SL_n(F_p) Hashing

**出处**: ePrint 2026/221
**作者**: Asmaa Cherkaoui, Faraz Heravi, Delaram Kahrobaei, Siamak F. Shahandashti

## 论点
将Tillich-Zemor代数码哈希嵌入SPHINCS+框架——仅替换底层哈希原语而保留WOTS+/FORS/hypertree架构——可以构造基于非交换群难题的后量子签名方案。

## 背景
SPHINCS+的模块化设计使其哈希原语可替换性成为重要特性。此前已有Streebog（Kiktenko 2020）、Haraka等人替换案例。作者探索了另一条路径：基于SL_n(F_p)群的Tillich-Zemor代数码哈希，其安全性基于群中的扩张图导航问题——该问题被认为对量子计算有强抵抗性。

## 技术路线
将SPHINCS+的标准哈希函数替换为SL_n(F_p)代数码哈希（512比特摘要），保持静态哈希树、WOTS+一次性签名、FORS几次签名和hypertree元数据结构不变。通过安全退化建模（security degradation modeling）指导参数选择，使用NIST统计测试套件的全部15类测试验证代数码哈希的统计随机性。在512比特摘要级别实现了可行性基准测试。

## 核心成果
1. 通过NIST全部15类统计测试，验证了SL_n(F_p)代数码哈希作为密码原语的可靠性。
2. 在SPHINCS+框架中成功替换哈希原语，证明SPHINCS+在不同代数哈希族之间的可移植性。

## 与本项目关联
**方法论参考**: 与本项目共享"SPHINCS+哈希原语替换"的核心方法论，高度平行。本项目用Poseidon2替换SHA-2以支持Goldilocks域上的STARK，Spinel用SL_n代数码哈希替换SHA-2以引入基于群难题的新安全假设。
