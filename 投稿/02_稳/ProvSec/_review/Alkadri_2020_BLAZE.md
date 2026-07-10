# BLAZE: Practical Lattice-Based Blind Signatures for Privacy-Preserving Applications

**出处**: FC, 2020
**作者**: Nabil Alkeilani Alkadri, Rachid El Bansarkhani, Johannes Buchmann

## 论点
提出BLAZE——实用的格基盲签名方案，签名大小6.6KB（~128比特安全），签名生成时间18ms，达到与Dilithium等标准格基签名方案相当的性能水平。

## 背景
格基盲签名是后量子环境下替代RSA盲签名的关键候选。此前格基盲签名的效率瓶颈在于签名尺寸过大（通常超过20KB）和签名生成的计算开销过高，限制了其在实际隐私保护应用中的部署。

## 技术路线
1. 基于格困难假设构造盲签名协议，优化签名过程中拒绝采样（rejection sampling）的效率。
2. 通过精心设计的协议参数和密钥结构，将签名大小压缩到6.6KB，比此前最佳方案小2.7倍。
3. 密钥生成和验证速度与NIST后量子签名候选Dilithium相当。

## 核心成果
- 签名大小仅6.6KB，为当时最小的格基盲签名方案。
- 签名生成仅需18ms，达到实际可用水平。
- 适用于匿名凭证和电子投票等需要盲签名的隐私保护应用场景。

## 与本项目关联
直接竞争: BLAZE与本项目均面向后量子盲签名的实际部署。BLAZE的签名大小（6.6KB）和速度（18ms）优于本项目当前状态，但其基于格密码学，依赖的困难假设与哈希签名不同。BLAZE+（后续工作）后被Katsumata等人的pROS攻击影响，安全性不完全确定。
