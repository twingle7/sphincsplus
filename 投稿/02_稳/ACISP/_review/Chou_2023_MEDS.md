# Take Your MEDS: Digital Signatures from Matrix Code Equivalence

**出处**: AFRICACRYPT, 2023
**作者**: Tung Chou, Ruben Niederhagen, Edoardo Persichetti, Tovohery Hajatiana Randrianarisoa, Krijn Reijnders, Simona Samardjiska, Monika Trimoska

## 论点
利用矩阵码等价(MCE)问题构造数字签名方案MEDS，在NIST Category 1安全级别实现最小2.8KB公钥和约6.5KB签名，并随后提交至NIST额外数字签名标准化流程。

## 背景
基于同构问题的签名方案是后量子签名的重要分支（如基于MQ问题的方案）。MCE作为一种更具一般性的编码等价问题，相比之前的向量码等价问题可以提供更小的数据尺寸，但此前未在签名方案中得到充分探索。

## 技术路线
1. 将MCE问题的群作用性质用于构造零知识交互协议，再通过Fiat-Shamir变换转为数字签名。
2. 对MCE问题的安全性进行深入分析：研究来自前人的碰撞攻击，并独立开发两种新攻击——基于minors的MinRank建模代数攻击，以及适用于矩阵码的Leon算法变体。
3. 实现参考C语言实现，并提供多个安全级别和签名/公钥尺寸的配置选项。

## 核心成果
- 构造MEDS签名方案，公钥最小2.8KB（NIST Cat 1），签名约18KB到6.5KB。
- 提出两种针对MCE问题的新攻击方法，完善了MCE问题的安全性理解。
- MEDS被提交至NIST额外数字签名标准化流程（Round 1），表明业界认可。

## 与本项目关联
背景知识: MEDS与本项目的SPHINCS+签名同属后量子签名候选，但基于完全不同的困难假设（编码等价 vs. 哈希函数）。MEDS的群作用构造思路与格基方案的可扩展性值得对比，SPHINCS+的简洁假设优势仍是本项目的关键差异点。
