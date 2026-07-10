# Hash-Based Blind Signatures: First Steps

**出处**: IACR ePrint 2025/2097
**作者**: Javier Herranz, Hugo Louiso

## 论点
提出首个安全性仅依赖哈希函数抗碰撞性的盲签名方案——将Fischlin通用盲签名构造进行哈希实例化，基于MPC-in-the-Head技术实现NIZKPoK。

## 背景
现有后量子盲签名几乎全部基于格密码（SIS/LWE假设）、同源（CSIDH/CSI-FiSh）或多元二次方程（MQ）。这些方案依赖的数学假设不如哈希函数的抗碰撞性保守。目前尚无仅依赖哈希函数安全性的盲签名方案。

## 技术路线
- Fischlin框架实例化：底层签名用基于哈希的签名方案
- NIZKPoK用MPC-in-the-Head（MPCitH）技术实现：将签名验证电路分解为MPC协议，模拟MPC参与方生成证明
- 承诺方案用哈希承诺（随机oracle实例化）
- 安全性仅依赖哈希函数的抗碰撞性（ROM下）
- 提供C语言实现和基准测试

## 核心成果
- 第一个仅依赖哈希函数安全性的盲签名方案
- 无格/同源/多元假设——安全性假设最保守
- C实现验证了可行性（含运行时间和内存基准）
- 签名/密钥大小比格基方案大，但安全性更保守

## 与本项目关联
**直接竞争**: 这是与本项目方向最接近的独立工作！同样基于Fischlin框架+哈希签名，区别在于：(1) 本方案用STARK替代MPCitH作NIZKPoK，(2) 本方案用Poseidon2替换通用哈希以提升ZK效率，(3) 本方案实现了全内生AIR的完全ZK证明而非仅MPC模拟。
