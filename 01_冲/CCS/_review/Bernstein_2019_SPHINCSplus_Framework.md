# The SPHINCS+ Signature Framework

**出处**: ACM CCS 2019 (London, UK, November 11–15, 2019)
**作者**: Daniel J. Bernstein, Andreas Hülsing, Stefan Kölbl, Ruben Niederhagen, Joost Rijneveld, Peter Schwabe

## 论点
SPHINCS+ 提出一种无状态、基于哈希的数字签名框架，通过全新的可调哈希抽象和 FORS 少次签名方案，在安全性、签名速度和签名大小上全面超越此前所有基于哈希的签名方案，并成为 NIST PQC 标准化项目的最终入选方案。

## 背景
后量子密码标准化进程中，基于哈希的签名方案因仅依赖哈希函数的抗碰撞性而具备极强安全假设优势，但先前方案（如原始 SPHINCS-256）的签名尺寸和速度尚不理想。同时，原有安全证明中存在统计性假设的漏洞，亟需严格归约。

## 技术路线
论文引入 FORS（Forest Of Random Subsets）取代 HORST 作为少次签名组件，降低签名尺寸并提升效率。核心创新是可调哈希函数（Tweakable Hash Functions）抽象层，将哈希基的安全性归约与树节点计算方式解耦，从而在不同哈希后端之间实现统一安全分析。基于该抽象，论文给出 SPHINCS+ 的紧致安全归约，并衍生出 Decisional Second-Preimage Resistance (DSPR) 框架。实现层面针对多种哈希后端进行优化，提供完整的参数集选择。

## 核心成果
- **FORS 方案**：新的少次签名机制，比 HORST 更紧凑高效
- **可调哈希抽象**：统一了不同哈希后端的安全分析，实现紧致归约
- **完整的参数化框架**：支持 SHA-256、SHAKE、Haraka 等多后端，覆盖 128/192/256 安全级别

## 与本项目关联
**方法论参考**: SPHINCS+ 是本项目的底层签名原语。论文中的可调哈希抽象设计直接影响了本项目在 Poseidon2 后端下的哈希适配层架构，FORS/WOTS+ 组合方案也是本项目中 Fischlin 协议所验证的核心签名结构。
