# Loquat: A SNARK-Friendly Post-quantum Signature Based on the Legendre PRF with Applications in Ring and Aggregate Signatures

**出处**: CRYPTO 2024, Part I, LNCS 14920, pp. 3-38
**作者**: Xinyu Zhang, Ron Steinfeld, Muhammed F. Esgin, Joseph K. Liu, Dongxi Liu, Sushmita Ruj

## 论点
基于Legendre伪随机函数（PRF）可以构造SNARK友好的后量子签名方案，其R1CS验证约束比SPHINCS+减少3-9倍，并能高效支持环签名和聚合签名。

## 背景
使后量子签名对零知识证明系统友好是近年来的研究热点。MPC-in-the-Head类方案签名较大（数百KB），而SPHINCS+虽签名小但在SNARK中验证效率低（约130万约束）。作者尝试在"较弱的数论假设+对称原语"与"SNARK友好性"之间找到新的设计点。

## 技术路线
签名方案基于Legendre PRF的单向性构造一对多的陷门函数，验证电路设计使其自然适应R1CS算术化。引入代数哈希替代随机谕言以降低约束数。环签名通过Camenisch-Standard方法扩展，聚合签名则结合Aurora和Fractal两种SNARK递归组合方案。技术核心在于将Legendre符号计算编码为低阶多项式约束。

## 核心成果
1. 签名约46 KB，验证R1CS约束约148K——比SPHINCS+少3-9倍，比MPCitH方案少7-175倍。
2. 32个签名的聚合证明适用Fractal递归后可实现恒定145 KB的聚合签名体积。
3. 基于身份的环签名（ID-based）将签名体积从1.9 MB降至0.9 MB。

## 与本项目关联
**直接竞争**: 与本项目同属"SNARK/ZK友好的后量子签名"研究前沿。Loquat以Legendre PRF+代数哈希为技术路径，本项目以SPHINCS++STARK为路径，两者在约束效率上竞争（Loquat约束更少，本项目完全避免电路重写）。
