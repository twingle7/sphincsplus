# Full L1 On-Chain ZK-STARK+PQC Verification on Solana: A Measurement Study

**出处**: ePrint 2025/1741
**作者**: Jotaro Yano

## 论点
在Solana L1的交易预算内（1.4M CU），完全可以在链上同时验证STARK证明和SPHINCS+后量子签名——STARK验证约1.10M CU，SPHINCS+验证约0.50M CU，总计算量在限制范围内。

## 背景
区块链要在后量子时代保持安全，必须在L1层支持后量子签名验证。但通用零知识证明（特别是STARK）的链上验证计算开销极高，此前尚未有对主流高性能L1的完整测量。Solana以其高吞吐和严苛的计算预算（每笔交易1.4M CU）成为最具挑战性的测试平台。

## 技术路线
适配Winterfell 0.12 STARK验证器至Solana的SBF（Solana BPF）运行时。关键工程优化包括：（1）为SHA-256哈希使用专用hashv系统调用路径以减少哈希开销；（2）在FRI关键热点中抑制内联以满足SBF栈限制；（3）自定义bump分配器与请求堆帧同步；（4）≤900字节分块上传+滚动哈希链实现固定工作量拒绝。验证分两阶段：先验证SPHINCS+签名，再验证绑定到SHA256(cipher)的STARK证明。

## 核心成果
1. SPHINCS+验证约5.01e5 CU，STARK验证约1.10e6 CU——均在1.4M CU预算内。
2. 验证成本对证明字节数大致线性扩展，分块上传机制确保可预测Gas消耗。
3. 首次实证了STARK+SPHINCS+完整验证管道在主流L1区块链上的端到端可行性。

## 与本项目关联
**应用场景**: 直接验证了本项目的技术栈（STARK+SPHINCS+）在Solana区块链上部署的可行性，为Fischlin协议的Show/Verify步骤上链提供了工程参考数据和优化方向。
