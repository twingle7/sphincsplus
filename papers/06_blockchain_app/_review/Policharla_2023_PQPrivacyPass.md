# Post-Quantum Privacy Pass via Post-Quantum Anonymous Credentials

**出处**: ePrint 2023/414 (Real World Crypto 2023)
**作者**: Guru-Vamsi Policharla, Bas Westerbaan, Armando Faz-Hernandez, Christopher A. Wood (Cloudflare, UC Berkeley)

## 论点
通过精心优化的通用零知识证明，后量子匿名凭证方案可以获得与专用后量子盲签名方案竞争力相当的性能，从而为Privacy Pass协议提供实用的后量子隐私令牌替代方案。

## 背景
Cloudflare的Privacy Pass让用户在验证身份后获得不可关联令牌，用于后续匿名访问。目前已在TLS 1.3中部署但依赖经典安全假设。面对量子威胁，需要在不依赖非合谋假设的前提下，构造支持速率限制的后量子匿名令牌系统。作者选择使用STARK通用零知识证明路径而非设计专用盲签名。

## 技术路线
构造zkDilithium——一种将Dilithium2（ML-DSA）签名验证转化为STARK友好算术电路的编码方案。电路优化包括：将Dilithium的数论变换（NTT）兼容于STARK的算术化约束、通过批量Merkle树证明压缩公开输入、以及对矩张采样进行范围证明优化。令牌协议支持速率限制变体，通过绑定公钥实现每用户速率控制而不依赖合谋假设。

## 核心成果
1. 令牌体积85-175 KB，生成时间0.3-5秒（115比特证明安全），验证时间20-30毫秒。
2. 首次展示了通用ZK后量子匿名凭证的生产级可行性——在同一硬件上与格基专用盲签名方案性能相当。

## 与本项目关联
**方法论参考**: 与本项目采用相同的"通用ZKP + 后量子签名"范式（STARK + Dilithium对本项目的STARK + SPHINCS+），但构建目标不同（Privacy Pass令牌 vs. Fischlin盲签名），在电路编码和STARK优化方面有直接参考价值。
