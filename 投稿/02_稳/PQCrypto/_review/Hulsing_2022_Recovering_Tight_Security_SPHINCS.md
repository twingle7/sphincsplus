# Recovering the Tight Security Proof of SPHINCS+

**出处**: PQCrypto / ASIACRYPT, 2022
**作者**: Andreas Hulsing, Mikhail Kudinov

## 论点
为SPHINCS+提供修正后的紧安全性证明，修复了Kudinov等人(2020)发现的原始紧安全性证明中的漏洞，仅损失Winternitz参数w（通常为16）的因子。

## 背景
SPHINCS+的紧安全性证明是其在NIST标准化过程中被选中的关键优势之一。2020年Kudinov、Kiktenko和Fedorov发现SPHINCS+中WOTS+组件的紧安全性证明存在缺陷。这一发现可能影响对该方案整体安全性保证的信任。

## 技术路线
1. 明确定义WOTS-TW——SPHINCS+中使用的WOTS变体的独立数学描述。
2. 在非自适应选择消息攻击（adversary仅在查询签名后才获得公钥）下证明WOTS-TW和其多实例版本的安全性。
3. 证明该安全性足以恢复SPHINCS+的紧安全性归约，边界几乎与原始声称一致。
4. 结合对可调哈希函数的额外分析，引入哈希函数通用攻击的量子查询复杂度下界。

## 核心成果
- 修复了SPHINCS+紧安全性证明中的关键漏洞，重新建立了该方案的强安全性保证。
- 证明了WOTS-TW在更弱攻击模型下的安全性足以支撑整体方案的紧归约。
- 为可调哈希函数的安全性属性提供了额外分析，对更广泛的哈希构造领域有参考价值。

## 与本项目关联
方法论参考: 本项目使用SPHINCS+作为底层签名方案，其安全性证明的紧性直接关系到Fischlin协议中盲签名的可证明安全性框架设计，修复后的证明为本项目的安全性论证提供了可靠支撑。
