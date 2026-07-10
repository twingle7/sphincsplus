# SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost

**出处**: IEEE Symposium on Security and Privacy (S&P), 2023
**作者**: Andreas Hulsing, Mikhail A. Kudinov, Eyal Ronen, Eylon Yogev

## 论点
SPHINCS+的签名尺寸可以通过结构优化大幅压缩，而几乎不增加计算开销和安全性损失。

## 背景
SPHINCS+作为NIST标准化的无状态哈希签名方案，其核心瓶颈在于签名尺寸过大（约8-49 KB），限制了实际部署场景。此前针对签名压缩的尝试通常以显著增加签名时间或密钥尺寸为代价。

## 技术路线
论文提出SPHINCS+C，核心创新在于将FORS（森林随机子集）中的索引选择与WOTS+一次性签名密钥的生成进行联合优化，利用Merkle树的交叉认证机制消除冗余信息。通过引入"树内压缩"技术，将原本需要显式存储的认证路径信息嵌入到已有结构之中。方案保持与SPHINCS+相同的密钥生成和验证算法接口，仅修改签名生成逻辑，实现了向后兼容的压缩方案。安全性证明基于SPHINCS+原有的安全模型，无需额外假设。

## 核心成果
- 在不改变底层安全假设的前提下，将SPHINCS+签名尺寸压缩约25-30%
- 额外计算开销可忽略不计（仅约1-3%的签名时间增加）
- 保持了与标准SPHINCS+完全相同的密钥结构和验证接口

## 与本项目关联
**直接竞争**: SPHINCS+C与本项目都致力于优化SPHINCS+框架，但方向不同——SPHINCS+C压缩签名尺寸，本项目引入Poseidon2后端和Fischlin盲签名协议扩展功能。二者的优化策略正交，可考虑组合使用。
