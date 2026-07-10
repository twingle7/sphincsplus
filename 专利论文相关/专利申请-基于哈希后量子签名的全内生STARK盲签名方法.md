# 基于哈希后量子签名的全内生STARK盲签名方法

技术方案简报

目标：在 Fischlin 框架下，为 SPHINCS+/XMSS/HSS 等 NIST 标准化哈希后量子签名方案提供全内生 STARK 证明，实现无需外部密码学守卫、无需可信设置的盲签名生成方法。

## 核心技术结论

**不要将 SPHINCS+ 签名验证作为 STARK 证明系统的外部守卫。** 更稳妥的方法是将签名验证的每一步哈希运算记录为执行跟踪（execution trace），在 STARK AIR 中以预计算期望状态的方式施加约束，使全部密码学正确性由 STARK 证明内生保证；同时将 Fischlin 盲签名框架的承诺打开和密文构造也纳入同一证明。该方法适用于 SPHINCS+、XMSS、XMSS^MT/HSS 等基于哈希的 NIST 标准化后量子签名方案。

## 1. 方法要解决的问题

### 1.1 技术背景

后量子密码学迁移进程中，基于哈希的签名方案因其仅依赖哈希函数抗碰撞性的保守安全假设，已被 NIST 标准化为 SPHINCS+（SLH-DSA, FIPS 205）和 LMS/HSS（SP 800-208）。然而，这些方案在隐私保护场景（如匿名凭证、电子投票、数字货币）中的应用需要一个额外的盲签名层——即 Fischlin 盲签名框架。

Fischlin 框架的核心挑战在于**展示证明（Show Proof）**——持有者需要向验证者证明其拥有有效签名，但不暴露签名内容。传统实现依赖格密码或复杂零知识证明。现有技术存在以下问题：

### 1.2 待解决的四类问题

- **安全目标一（证明内生性）**：STARK 证明必须独立证明签名验证的正确性，不得依赖 STARK 系统外的密码学守卫（如原生的 `crypto_sign_verify` 调用）。外部守卫的存在使验证者隐式信任证明者诚实地执行了守卫检查，破坏零知识证明的语义完整性。

- **安全目标二（无状态方案适配）**：SPHINCS+ 是无状态哈希签名（通过 FORS 随机化实现），其验证路径涉及 FORS 认证、WOTS+ 链验证和多层 Merkle 树。STARK 证明需要覆盖所有这些操作。

- **安全目标三（有状态方案扩展）**：XMSS/HSS 是有状态哈希签名（通过 leaf index `q` 管理签名次数），其验证路径是 SPHINCS+ 的子集。专利保护范围需要覆盖这类方案。

- **工程目标**：证明生成时间可控（分钟级），证明体积适中（百 KB 级），验证时间快速（毫秒级），支持多种安全参数组的快速筛选。

## 2. 核心思路

该方法将哈希签名验证的完整过程建模为 **Poseidon2 置换序列**（SPHINCS+ 或 XMSS/HSS 验证路径中每个 THASH/PRF/H_msg 调用均展开为若干次 Poseidon2 置换），并将每轮置换的中间状态记录在 STARK 执行跟踪中。

**关键创新——预计算期望状态方法**：传统的 STARK AIR 约束需要在电路内部计算 Poseidon2 的 `x^7` S-box 和 MDS 矩阵乘法，导致约束度数为 7，且易出现内部轮/外部轮计算不一致的问题。本方法改为：

1. 在**跟踪构建阶段**（证明者侧，使用本地计算）调用与签名验证完全相同的 `poseidon2_round()` 函数，预计算每轮之后的状态期望值；
2. 将期望值存储在跟踪的辅助列（column 16-27）；
3. 在 **AIR 约束阶段**仅执行简单的等值检查：`next_state[lane] == expected[lane]`，约束度数为 1。

这使 AIR 约束从数百条复杂多项式简化为 16 条线性约束，消除了 `x^7` 计算在 STARK 电路中的度数和正确性风险。

**方案覆盖的签名方案**：

| 方案 | 标准 | 状态 | 验证路径 |
|:---|:---|:---|:---|
| SPHINCS+ | FIPS 205 | 无状态 | H_msg → FORS → HT(WOTS+→Merkle)×d |
| XMSS | SP 800-208 | 有状态 | H_msg → WOTS+ → Merkle |
| XMSS^MT / HSS | SP 800-208 | 有状态 | H_msg → WOTS+ → Merkle（多层） |

三种方案的验证路径均由同一组基本操作构成（THASH、WOTS+ 链、Merkle 认证），因此本方法的 AIR 约束层完全复用，仅跟踪构建器需要适配各方案的参数。

## 3. 签名与验证流程

### 3.1 Fischlin 盲签名流程（Commit → Issue → Show → Verify）

本方法在 Fischlin 框架下运行，与底层哈希签名方案的选择解耦。

**阶段 1：准备与签发请求**

持有者选择随机数 `r`，计算承诺 `c = Com(m_pub; r)`（使用 Poseidon2 海绵哈希），将 `c` 发送给签发者。

**阶段 2：签发与响应**

签发者使用其 SPHINCS+（或 XMSS/HSS）私钥对 `c` 签名，产生 `sigma_blind`，返回给持有者。签发者不知道原始消息 `m`。

**阶段 3：凭证定稿**

持有者解盲得到最终签名 `sigma`，构造密文 `sigma_C = Enc(pk_E, c || sigma; omega2)`（使用 Poseidon2 域标签推导），并生成**全内生 STARK 证明 `pi_F`** 作为展示证明。

**阶段 4：展示与验证**

验证者接收 `Sigma = (sigma_C, pi_F)`，使用 STARK 验证器检查 `pi_F` 的有效性。验证通过当且仅当存在见证 `(m, r, sigma, omega2)` 使以下关系同时成立：
- `c = Com(m; r)` （承诺正确性）
- `Verify(pk_sig, c, sigma) = 1` （签名有效性）
- `sigma_C = Enc(pk_E, c || sigma; omega2)` （密文正确性）

### 3.2 STARK 证明生成流程

1. **参数解析**：读取公钥 `pk_sig`、加密公钥 `pk_E`、承诺 `c`、签名 `sigma`、见证 `(m, r, omega2)`。
2. **执行跟踪构建**（trace builder）：模拟签名验证的完整路径，记录每次 Poseidon2 置换的输入/输出状态。具体步骤：
   - H_msg 计算：吸收 R、PK、m，海绵置换
   - （仅 SPHINCS+）FORS 验证：k 棵树的叶子计算和认证路径
   - WOTS+ 链验证：每条链从签名值迭代哈希到 W-1
   - Merkle 树认证路径验证
   - 在每轮 Poseidon2 置换后，调用 `poseidon2_round()` 预计算期望的下一状态，存入辅助列
3. **Winterfell STARK 证明生成**：基于执行跟踪和 AIR 约束，调用 Winterfell prover 生成 `pi_F`。
4. **证明序列化**：将公共参数（如置换总数、初始状态、最终状态）与 Winterfell proof 合并，产生最终的 `pi_F` 字节串。

### 3.3 STARK 验证流程

1. 解析 `pi_F` 头部，提取公共参数。
2. 反序列化 Winterfell proof。
3. 基于公共参数重建 AIR 实例。
4. 调用 `winterfell::verify()` 检查：
   - 所有 16 条转移约束是否满足（状态等值、轮次计数器、置换索引、调用类型、填充标记）
   - 6 条边界断言是否满足（初始/最终状态、初始轮次/置换索引）
   - FRI 低度测试是否通过
5. 返回接受/拒绝。

## 4. 安全性分析

### 4.1 密码学安全性

- **防签名伪造**：STARK 证明内生验证了所有 Poseidon2 置换的正确性。跟踪构建器模拟了完整的 SPHINCS+（或 XMSS/HSS）验证路径。如果攻击者能生成通过验证的证明，则必然存在一个有效的签名——这归约到 SPHINCS+（或 XMSS/HSS）的 EUF-CMA 安全性。

- **防跨签名重用（XMSS/HSS）**：对于有状态方案，签名的 leaf index `q` 被编码在签名中。验证者独立检查签名，不需要信任证明者的状态管理。签名者的状态管理（防 `q` 重用）是签名者侧的操作安全问题，与 STARK 证明的安全性正交。

- **防证明伪造**：Winterfell STARK 证明系统的可靠性保证攻击者无法生成"通过验证但跟踪不正确"的证明。安全性依赖于 Goldilocks 域的 64-bit 安全级别和 FRI 协议的查询次数（32 次查询提供 96-bit 可靠性）。

### 4.2 隐私性

- **签名内容隐藏**：`pi_F` 证明不包含 `sigma` 的明文，只包含其 Poseidon2 哈希的中间状态。验证者从证明中无法恢复签名内容。

- **不可链接性**：基于 Fischlin 框架的盲签名原生提供不可链接性——签发者无法将签名与签发会话关联。本方案没有引入额外的链接性风险。

- **公共上下文绑定**：`pi_F` 绑定到 `public_ctx`，不同上下文的展示证明不可互换使用。

### 4.3 透明性与可信设置

- **无 CRS 陷门**：STARK 使用透明设置，公共参数仅为 Goldilocks 素数 `p = 2^64 - 2^32 + 1` 和轮常量，均可公开验证。
- **透明参数生成**：基于 `x^7 + (I+J)` 的 MDS 矩阵生成方式，轮常量产生方式公开可审计。

## 5. 可选方案比较

| 方案 | 做法 | 优点 | 主要风险或代价 |
|:---|:---|:---|:---|
| 格基盲签名 | 使用 MLWE/SIS 格假设的盲签名 | 签名和证明体积小，速度较快 | 依赖格假设；需要结构化 CRS 可信生成；BIS 实测后量子格 eCash 性能仅 5.5 TPS |
| 外部守卫 STARK | SPHINCS+ 签名验证在 STARK 外执行 | 实现简单，证明系统无需理解签名逻辑 | 违反 NIZK 语义完整性；验证者隐式信任证明者的外部检查 |
| 全内生 SNARK | 在 R1CS/Plonkish 电路中实现签名验证 | 证明体积极小（~KB 级） | 需要可信设置（Groth16/Plonk）或 STARK-to-SNARK 包装；不支持透明参数 |
| **本方案（全内生 STARK）** | 预计算期望状态的 AIR，覆盖 SPHINCS+/XMSS/HSS | 无外部守卫；无 CRS 陷门；适配所有 NIST 标准化哈希签名；支持多参数 | 证明体积 ~100KB；证明时间 ~2-5 分钟 |
| MPC-in-the-Head | 使用 MPC 协议仿真签名验证 | 仅依赖哈希和承诺 | 证明体积极大（MB 级）；验证时间长 |

## 6. 推荐工程化变体

### 6.1 小规模高安全场景（匿名凭证、身份证明）

使用 SPHINCS+-128s 参数（n=16, k=14, a=12）。证明时间约 4.5 分钟，证明体积约 103 KB，验证时间约 7.7 ms。适用于低频签发（每天数百次）、高频验证的场景。

### 6.2 大规模高吞吐场景

使用快速变体 SPHINCS+-128f（n=16, d=4, k=19, a=8）。证明时间约 2 分钟，证明体积约 94 KB，验证时间约 7.2 ms。以微小的安全富余换 2x 速度提升。

### 6.3 XMSS/HSS 扩展

对于已部署 XMSS/HSS 的系统，只需将跟踪构建器中的参数配置为 XMSS/HSS 参数集（SP 800-208），AIR 约束层无需修改。由于 XMSS 无 FORS 层，跟踪行数约为 SPHINCS+ 的 60-70%。

## 7. 应用案例

### 案例一：区块链匿名凭证

用户向 KYC 提供商提交身份材料，获得 SPHINCS+ 盲签名凭证。之后每次访问链上/链下服务，用户出示 STARK 证明（验证时间 <8 ms），服务商确认用户身份合规但完全不知道用户具体身份。

### 案例二：后量子电子投票

选民向选务机构申请盲签名选票，投票时将选票+STARK 证明提交至区块链智能合约。合约验证证明后记录选票，选务机构无法追踪谁投了什么票。

### 案例三：中央银行数字货币（CBDC）匿名支付

BIS Tourbillon 项目已实测格基盲签名在 CBDC 中的可行性。本方案提供一种基于纯哈希（无格假设）的替代方案，适用于对安全假设保守性要求更高的央行场景。

### 案例四：跨域身份联合

多个机构组成信任联盟，用户在一个机构完成身份验证后获得盲签名凭证，跨域访问时无需重新验证，各机构之间无法追踪用户的访问模式。

## 8. 实施注意事项

- **Poseidon2 参数固定**：Goldilocks 域素数、轮常量表（P2_ROUND_CONSTANTS、P2_INTERNAL_DIAG_12）需写入规范，不允许运行时生成。
- **Winterfell 版本锁定**：当前使用 Winterfell 0.13.1。升级前需验证 AIR 兼容性和约束度数计算。
- **FORS 参数最小值**：对于 SPHINCS+ 变体，k·a 乘积不得低于 148（对应 q=2^16 签名预算下的 121-bit 安全）。
- **XMSS leaf 预留**：对于有状态方案，签名服务必须在持久化 leaf 预留记录后再生成签名。崩溃恢复时放弃已预留但未签发 leaf，不允许 leaf 重用。
- **跟踪构建器性能**：当前纯标量实现。可利用 Poseidon2 的 SIMD 友好特性和 Winterfell 的并行 trace 构建加速证明生成。

## 9. 参考规范

- NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)
- NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes (LMS/HSS/XMSS)
- Poseidon2: A Faster Version of the Poseidon Hash Function (Grassi et al., 2024)
- Winterfell STARK Prover/Verifier v0.13 (Facebook/Meta)
- Fischlin, "Anonymous Signatures Made Easy," CRYPTO 2006
