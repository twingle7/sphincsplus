# Quantum-Resistant Signatures for Bitcoin: A STARK Experiment (OP_STARK_VERIFY)

**出处**: DelvingBitcoin 论坛技术提案，2025
**作者**: AbdelStark 等（Bitcoin 社区）

## 论点
在Bitcoin Tapscript中引入原生STARK证明验证操作码OP_STARK_VERIFY，可实现后量子签名聚合和零知识隐私功能，为Bitcoin提供不依赖OP_CAT或自定义算术操作码的后量子迁移路径。

## 背景
Bitcoin的ECDSA签名算法面临量子计算威胁，且其UTXO模型无原生智能合约能力，限制了后量子密码的部署。此前社区尝试（如OP_CAT+CTV组合）复杂度高且安全论证不完整。同时，Bitcoin PoS转型讨论中对签名聚合的需求日益增长，而BLS聚合签名不抗量子。AbdelStark的实验性提案选择了STARK路径。

## 技术路线
提案在Tapscript中新增OP_STARK_VERIFY操作码，以内置函数形式验证有限大小的STARK证明。采用Stone STARK验证器（Starkware的生产级形式化验证实现），通过verifier_id命名空间支持未来证明系统扩展。证明大小约100 KB（压缩），链上验证约数十毫秒。相关实验（s2morrow项目）验证了STARK对Falcon和SPHINCS+签名的批处理聚合能力。

## 核心成果
1. 提出Bitcoin L1原生STARK验证的完整操作码设计，覆盖批量后量子签名聚合和隐私交易场景。
2. 实验验证了STARK+SPHINCS+组合在Bitcoin脚本约束下的可行性，证明约100 KB，验证在毫秒级。

## 与本项目关联
**应用场景**: 直接验证了本项目"STARK+SPHINCS+"技术栈在Bitcoin区块链生态中的应用可行性，是潜在的目标部署场景。
