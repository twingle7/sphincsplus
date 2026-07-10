# SPHINCSLET: An Area-Efficient Accelerator for the Full SPHINCS+ Digital Signature Algorithm

**出处**: ACM Transactions on Embedded Computing Systems (TECS), Vol. 24, Issue 5, 2025
**作者**: Sanjay Deshpande, Yongseok Lee, Cansu Karakuzu, Jakub Szefer, Yunheung Paek

## 论点
SPHINCSLET 是首个完全符合 SLH-DSA 标准的紧凑硬件加速器，在 FPGA 上实现了 4.7 倍面积缩减和 2-5 倍签名速度提升，使 SPHINCS+ 的硬件部署成为可行。

## 背景
SPHINCS+ 被 NIST 标准化为 SLH-DSA（FIPS 205），但纯软件实现在性能上有限，而现有硬件实现或面积过大、或仅支持部分功能。随着后量子密码迁移的推进，需要一种面积高效、完全标准兼容的硬件加速方案，适用于资源受限的嵌入式场景。

## 技术路线
论文设计了 SPHINCSLET 架构，其核心在于参数化设计和平衡的面积-性能折中。SHA-2 变体通过精心设计的哈希核心复用和流水线调度，在仅需要 6,000-15,000 LUTs 的 FPGA 面积下实现完整的签名、验证和密钥生成功能。SHAKE256 变体基于 AMD Artix-7 FPGA，面积控制在 10,800 LUTs 内。架构支持所有 NIST 安全等级，且无需更换硬件即可切换参数集。加速器采用模块化设计，覆盖整个 SPHINCS+ 算法流程而非仅部分组件。

## 核心成果
- 相比高性能设计面积减少 4.7 倍
- SHA-2 变体签名生成速度比协处理器设计快 2-4 倍，为目前最快的 SHA-2 SLH-DSA 实现
- 首个支持完整 SLH-DSA 功能（密钥生成、签名、验证）的紧凑型加速器

## 与本项目关联
**应用场景**: 本项目的 Fischlin 盲签名协议若需硬件加速（如作为硬件安全模块中的 Issuer），SPHINCSLET 的架构设计提供了重要参考。特别是其参数化设计理念可迁移到 Poseidon2 后端的硬件加速中，为本项目的签名过程提供硬件加速支持。
