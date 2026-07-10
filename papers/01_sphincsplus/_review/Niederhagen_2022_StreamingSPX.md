# Streaming SPHINCS+ for Embedded Devices Using the Example of TPMs

**出处**: AFRICACRYPT 2022, LNCS Vol. 13503, pp. 269-291
**作者**: Ruben Niederhagen, Johannes Roth, Julian Wälde

## 论点
通过流式（streaming）输入/输出技术，SPHINCS+ 可以在内存极度受限的嵌入式设备（如 TPM）上运行，峰值内存仅需 2.55 KB，而无需存储完整签名。

## 背景
SPHINCS+ 被 NIST 选为后量子签名标准，但其签名尺寸较大（7-50 KB），远超过典型 TPM 和嵌入式设备的可用内存（通常只有几 KB）。传统实现需要在签名生成或验证完成前将整个签名或签名过程中的中间状态存储在内存中，这在嵌入式环境中不可行。

## 技术路线
论文提出两阶段流式方法：签名生成时使用流式输出（streaming-out），边生成边输出签名分量，避免在内存中缓存完整签名；验证时使用流式输入（streaming-in），边接收边验证，同样避免完整存储。论文基于 ARM Cortex-M4 平台实现了完整的 SPHINCS+ 流式签名和验证，并提出了将流式扩展集成到 TPM 规范的方案。实现利用了 SPHINCS+ 的签名可分解性——WOTS+ 链和 FORS 树的叶子可以独立生成和验证。

## 核心成果
- 峰值内存仅需 2.55 KB（支持所有参数集），适用于最严格的嵌入式场景
- 流式方法几乎不引入性能开销
- 为 SPHINCS+ 在 TPM 和物联网设备中的实际部署铺平了道路

## 与本项目关联
**应用场景**: 本项目的 Fischlin 盲签名协议如果部署在嵌入式环境中（如 TPM 作为 Issuer），可借鉴流式方法降低 Issuer 侧的内存需求。特别地，Poseidon2 哈希后端的高效性可与流式方法结合，进一步降低嵌入式部署的硬件门槛。
