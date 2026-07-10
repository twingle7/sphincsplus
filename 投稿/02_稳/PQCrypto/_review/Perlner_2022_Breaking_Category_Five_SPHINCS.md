# Breaking Category Five SPHINCS+ with SHA-256

**出处**: PQCrypto, 2022
**作者**: Ray Perlner, John Kelsey, David Cooper

## 论点
对SHA-256实例化的SPHINCS+高安全参数集实现了完整的伪造攻击，将受影响的Category Five参数集的实际经典安全性降低约40比特。

## 背景
SPHINCS+是无状态哈希签名方案，被NIST选入后量子密码标准化。其SHA-256实例化的Category Five参数集声称提供256比特经典安全性。Perlner等人将Sydney Antonov在NIST PQC邮件列表上的观察转化为完整的密钥伪造攻击。

## 技术路线
1. 利用SHA-256的Merkle-Damgard结构在SPHINCS+中缺乏"不同函数多目标第二原像抵抗(DM-SPR)"属性。
2. 将这一观察应用于SPHINCS+中的WOTS+一次性签名公钥，构造一个可以签名极有限哈希值的新的一次性密钥。
3. 通过该密钥构造原始超树的轻微修改版本，使得可以签名任意消息，生成的签名通过验证。

## 核心成果
- 在Category Five级别SPHINCS+ SHA-256上完成首次完整签名伪造攻击。
- 证明SHA-256的Merkle-Damgard结构是根本弱点的来源。
- 该攻击不影响SHAKE或其他哈希后端的SPHINCS+实例化。

## 与本项目关联
背景知识: SPHINCS+的安全分析直接关联本项目的签名方案底层安全假设，此类攻击方法论有助于评估Fischlin协议中SPHINCS+的安全性边界。
