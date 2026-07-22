# 交付物 #3: Fischlin 框架变体研究

## 1. Fischlin 盲签名框架的演化谱系

盲签名的研究可追溯到 Chaum (1982)，但这里聚焦于 Marc Fischlin 于 2006 年在 CRYPTO 提出的特定框架及其后续演化 — 该框架的独特之处在于：它是**通用的**、**轮数最优的**、且在 ROM 下具有组合安全性。

### 1.1 Fischlin 原始框架 (CRYPTO 2006)

**论文:** M. Fischlin, "Round-Optimal Composable Blind Signatures in the Common Reference String Model," CRYPTO 2006.

**核心机制:** Fischlin 提出了一个两轮盲签名协议，基于以下组件：
1. 一个承诺方案 (Commit)
2. 一个标准签名方案 (Sign/Verify)
3. 一个非交互零知识证明系统 (NIZK) 用于证明格式正确的 statement

**协议流程 (2 轮):**
```
User (消息 m, 随机数 r)                    Signer (sk, pk)
──────────────────────                    ─────────────────
c = Commit(m; r)
Send: c
                                            σ_blind = Sign(sk, c)
                          Receive: σ_blind ←
// ⚠️ 注意：Fischlin 框架中不存在数学上的"去盲"操作
// sigma_blind 被原封保留为凭证的一部分。解释见下方安全性分析。
π = NIZK.Prove{我知道 (m, r) 使得
    Verify(pk, c, σ_blind)=1 ∧ c = Commit(m; r)}
最终凭证: Σ = (c, σ_blind, π)
```

**⚠️ 关键澄清：Fischlin 框架没有"去盲"操作。** 与 RSA 盲签名不同（`σ = σ_blind · r⁻¹ mod N` 将签名从盲化消息转化为对原始消息的有效签名），Fischlin 框架中 Signer 签名的是**承诺值 c**，用户将 `σ_blind` 原样保留。Verifier 检查：(1) `σ_blind` 是对 c 的有效签名，(2) π 证明 c 是某 (m, r) 的承诺。Blindness 完全来自承诺方案的 hiding 性质，而非签名的代数变换。**对 SPHINCS+ 等哈希基签名——它们没有代数同态结构，无法做传统"去盲"——Fischlin 框架的承诺范式是唯一可行的方法。**

**安全性分析:**
- **Blindness:** 承诺方案 c = Commit(m; r) 的 hiding 性质保证 Signer 不能从 c 中恢复 m。即使 Signer 事后看到 (c, σ_blind, π) 也无法链接到签发会话（π 是零知识的）
- **One-more unforgeability (OMUF):** 即使敌手询问了 ℓ 次签名谕言机，也不能产生 ℓ+1 个有效凭证。归约到：(1) 底层签名方案的 EUF-CMA 安全性，(2) NIZK 的 soundness，(3) 承诺方案的计算 binding

**局限性:**
- 依赖 CRS (Common Reference String) 模型（需要可信设置来生成 NIZK 参数）
- NIZK 的具体效率取决于底层签名方案的验证电路复杂度
- 原始论文未给出后量子实例化；Fuchsbauer 2015 的格基标准模型实例化同样没有"去盲"操作

### 1.2 Fuchsbauer-Hanser-Slamanig 标准模型变体 (CRYPTO 2015)

**论文:** G. Fuchsbauer, C. Hanser, D. Slamanig, "Practical Round-Optimal Blind Signatures in the Standard Model," CRYPTO 2015.

**关键改进:**
1. **消除 ROM 依赖:** 使用 Structure-Preserving Signatures (SPS) + Groth-Sahai NIZK 证明系统，在 DLIN 假设下实现标准模型安全。这是第一个**不需要 ROM 的轮数最优盲签名**。
2. **引入 Fischlin 框架的形式化:** 将 Fischlin 的直观构造提升为正式的安全性框架，定义了关键的安全实验和归约路径。
3. **实用性考虑:** 尽管标准模型安全理论上更优，但 SPS + Groth-Sahai 的具体效率远不如 ROM 方案——签名和证明尺寸大、验证慢。

**与本项目的关系:** ⭐⭐ 该文是理解 Fischlin 框架安全性归约的关键参考文献，但**不适用于本项目**——SPHINCS+ 的整个安全分析都在 ROM 中。我们不需要（也无法）追求标准模型安全，因为哈希函数本质上是 RO 实例化。Dietz et al. [ePrint 2026] 甚至证明了标准模型下无法实现轮数最优的 Pairing-Free 盲签名——这进一步确认了 ROM 方案在哈希基场景中的必要性。

### 1.3 del Pino-Katsumata 格基 Trapdoor 变体 (CRYPTO 2022)

**论文:** R. del Pino, S. Katsumata, "A New Framework for More Efficient Round-Optimal Lattice-Based (Partially) Blind Signature via Trapdoor Sampling," CRYPTO 2022.

**关键创新:**
1. **Trapdoor 抽样替代 NIZK:** 不直接使用通用 NIZK，而是在格设置中利用 Trapdoor 抽样技术实现 Fischlin 框架。这大幅降低了证明复杂度——从通用 NIZK 的 circuit-based 到代数结构的 native 操作。
2. **首次支持半盲签名:** 在 Fischlin 框架中自然地嵌入了半盲签名（Partially Blind Signature）支持。半盲签名的公开 info 被绑定在签名的 Trapdoor 抽样中。
3. **基于 Module-SIS/LWE:** 假设与 CRYSTALS-Dilithium 属于同一族。

**安全性:** OMUF 归约到 Module-SIS 和 Module-LWE，ROM 模型。

**与本项目的关系:** ⭐⭐⭐⭐ 该文展示了如何将 Fischlin 框架**适配特定代数结构**（格 Trapdoor），从而提高效率。这恰是本项目的策略——利用 Poseidon2 的 Goldilocks 域结构和 STARK 的 AIR 约束系统来**为哈希基方案量身定制**Fischlin 实例化。

### 1.4 Beullens-Lyubashevsky-Nguyen-Seiler 优化变体 (CCS 2023)

**论文:** W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler, "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal," CCS 2023.

**关键改进:**
1. **签名尺寸缩减至 20 KB:** 通过 (1) 在 NTRU 环上的更紧凑的参数选择，(2) 移除 Trapdoor 抽样中的冗余元素，(3) 在不损失安全性的前提下合并证明组件。
2. **更加模块化的安全归约:** 将 OMUF 归约分解为多个中间步骤，使归约更清晰，便于审计。
3. **Keyed-Verification 变体:** 提出只需要共享 Key 的轻量级盲签名（signature 仅 48 bytes），适用于 Signer 和 Verifier 合作场景。

**与本项目的关系:** ⭐⭐⭐ 该文是目前格基 Fischlin 方案中效率最优的，是我们效能对比的**黄金基线** (golden baseline)。我们应引用该文作为 "the current state-of-the-art in lattice-based Fischlin blind signatures"。

### 1.5 Bouillaguet 通用 Hash-and-Sign 编译器 (IEEE S&P 2026) ★ 本项目直接使用的变体

**论文:** C. Bouillaguet, T. Feneuil, J. Maire, M. Rivain, J. Sauvage, D. Vergnaud, "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026.

**这是本项目的理论基础。** 详细分析如下：

**核心贡献:**
1. **通用性:** 编译器适用于**任何**满足以下条件的 Hash-and-Sign 签名方案 Σ：
   - (i) Σ 在 ROM 中满足 EUF-CMA 安全
   - (ii) Σ 的签名算法可以表示为 `σ = Sign(sk, H(m))`，其中 H 是 RO
   - (iii) H 的输出在某个代数域 G 中（例如：H: {0,1}* → G）

2. **SPHINCS+ 的适配:** SPHINCS+ 满足上述条件：(i) SPHINCS+ 在 ROM 中 EUF-CMA 安全（规范 Theorem 1-2），(ii) 签名即对 H_msg(m) 的 WOTS/FORS/HT 操作，(iii) Poseidon2 的输出在 Goldilocks 域中。

3. **编译器工作方式（注意：不存在数学"去盲"操作）:**
   ```
   输入: Hash-and-Sign 方案 Σ = (Σ.KeyGen, Σ.Sign, Σ.Verify)
   输出: Fischlin 盲签名方案 BS = (BS.KeyGen, BS.Sign, BS.User, BS.Verify)

   承诺阶段:  User 抽样 r ← {0,1}^λ, 计算 c = H(m, r)   // H 是另一个 RO
   签发阶段:  Signer 计算 σ_blind = Σ.Sign(sk, c)
   凭证最终化: User 验证 Σ.Verify(pk, c, σ_blind) = 1
              User 保存 credential = (c, σ_blind, m, r) // 签名原封不动!
   Show阶段:  User 生成 π = NIZK.Prove{∃(m,r): c = H(m,r) ∧ Verify(pk, c, σ_blind) = 1}
   最终出示:  Σ = (c, σ_blind, π)
   ```
   
   **关键点：** 对于 Hash-and-Sign 签名的编译器，`σ_blind` 在整个流程中**不发生任何变换**。底层签名（如 SPHINCS+）的代数结构不支持去除盲化因子——因为压根就没有盲化因子可去——`c = H(m, r)` 是对消息的承诺（而非消息的代数盲化），签发 `σ_blind = Σ.Sign(sk, c)` 后，此签名永久绑定在承诺值 `c` 上。**凭证 = (c, σ_blind, π)，验证者检查的是"π 是否有效" + "σ_blind 是否是对 c 的有效签名"——从不检查签名是否对 m 有效，也无需检查。**

3. **为什么"无去盲"是正确的 — SPHINCS+ 的特殊性:**
   
   对于 SPHINCS+ 这样的哈希基 Hash-and-Sign 方案，不存在任何代数同态结构能支持 `σ = Unblind(σ_blind, r)` 这样的操作。但这**不影响 Fischlin 框架的正确性**——因为 Fischlin/Bouillaguet 框架**从不需要去盲**。凭证 `(c, σ_blind, π)` 中，`σ_blind` 是对承诺值 `c` 的有效签名，π 证明 `c` 是某 (m, r) 的承诺。Verifier 检查的是这两条，**从不检查签名是否对原始消息 m 有效**。

   这与 RSA 盲签名有本质区别: RSA 中 `σ_blind = (m·r^e)^d = m^d·r (mod N)` → `σ = σ_blind/r = m^d`，最终得到的是对 m 的标准签名。Fischlin 中最终凭证包含的是对 c 的签名 + 对 c 的零知识打开证明 —— 从不产生对 m 的标准签名。

4. **安全性归约:**
   ```
   BS.OMUF ≤ Σ.EUF-CMA + H.Collision-Resistance + Commit.Binding
   ```
   归约将攻击盲签名方案的敌手 A_BS 转换为攻击底层签名方案的敌手 A_Σ，转换损失为 poly(λ)。

**本项目的差异 (Delta from Bouillaguet):**

| 维度 | Bouillaguet | 本项目 |
|------|-----------|--------|
| 证明系统 | MPC-in-the-Head (线性 proof size) | **STARK (对数 proof size)** |
| 哈希函数 | 原生方案哈希 (SHA2/SHAKE) | **Poseidon2 (Goldilocks 域原生)** |
| SPHINCS+ 实例化 | 理论提及，未实现 | **完整的代码实现 + benchmark** |
| 半盲签名 | 未讨论 | 通过 public_ctx 绑定支持 |
| 安全参数 | 通用框架 | **128-bit 具体参数 (n=16, h=63, d=7, k=10, a=12)** |

## 2. Fischlin 框架的变体分类总结

### 2.1 按证明系统分类

| 变体 | 证明系统 | Proof Size | 后量子? | 代表性工作 |
|------|---------|-----------|---------|----------|
| 原始 Fischlin 2006 | 通用 NIZK (CRS) | Circuit-dependent | 否 | Fischlin '06 |
| Fuchsbauer 2015 | Groth-Sahai NIZK | O(\|C\|) group elements | 否 (DLIN) | FHS '15 |
| 格基 Trapdoor | Lattice Trapdoor | O(λ) lattice elements | 是 (SIS/LWE) | dP-K '22, Beullens '23 |
| MPC-in-the-Head | ZKBoo/ZKB++ | O(\|C\|) hash openings | 是 (Hash) | Bouillaguet '26, Herranz '25 |
| **STARK (本项目)** | **Winterfell AIR** | **O(log\|C\|) field elements** | **是 (Hash)** | **本项目** |

### 2.2 按安全模型分类

| 安全模型 | ROM | Standard Model | 本项目适用? |
|---------|-----|----------------|------------|
| Fischlin 2006 | ✅ | ❌ | ✅ ROM 可接受 |
| FHS 2015 | ❌ | ✅ (DLIN) | ❌ 标准模型对哈希基不可行 |
| dP-K 2022 | ✅ | ❌ | ✅ 同类 ROM |
| Bouillaguet 2026 | ✅ | ❌ | ✅ 直接使用 |
| Dietz 2026 | ⚠️ 证明不可能 | ⚠️ | 确认 ROM 必要 |

### 2.3 本项目使用的具体 Fischlin 配置

```
┌─────────────────────────────────────────────────────────┐
│ Fischlin 框架层次                                        │
├─────────────────────────────────────────────────────────┤
│ 顶层: Bouillaguet 通用编译器 (IEEE S&P 2026)             │
│    │                                                    │
│    ├── 底层签名: SPHINCS+ (NIST FIPS 205)                │
│    │     └── THF: Poseidon2 (Goldilocks, t=12)          │
│    │           ├── 安全性: ROM 下 SM-TCR/DSPR/PRE/UD     │
│    │           └── 参数: n=16, h=63, d=7, k=10, a=12    │
│    │                                                    │
│    ├── 零知识证明: STARK (Winterfell)                    │
│    │     ├── AIR: 53 约束, 23,861 行 × 64 列             │
│    │     ├── 域: Goldilocks prime (co-design with hash)  │
│    │     └── 安全性: ~108-bit conjectured (blowup=16)    │
│    │                                                     │
│    └── 安全归约:                                         │
│          OMUF ← EUF-CMA ← THF ← Poseidon2               │
│                 (Bouillaguet)  (SPHINCS+)  (ROM)        │
└─────────────────────────────────────────────────────────┘
```

## 3. 为什么选择 Bouillaguet 编译器而非其他变体

| 评估维度 | Bouillaguet | dP-K (格基) | FHS (标准模型) | 评价 |
|---------|-----------|-----------|---------------|------|
| 底层假设多样性 | ✅ 任意 H&S | ❌ 仅格 | ❌ 仅 DLIN + SPS | Bouillaguet 最灵活 |
| 哈希基支持 | ✅ 原生 | ❌ | ❌ | 决定性因素 |
| 实现复杂度 | 中等 (编译) | 高 (Trapdoor) | 最高 (Groth-Sahai) | 工程可行 |
| 证明系统可替换 | ✅ 是 | ❌ 绑定 Trapdoor | ❌ 绑定 Groth-Sahai | 允许 STARK |
| 标准化路径 | ✅ SPHINCS+ → NIST FIPS 205 | ✅ Dilithium → NIST FIPS 204 | ❌ 无 NIST 标准 | SPHINCS+ 更保守 |
| Proof Size | O(log\|C\|) (STARK) | O(\|C\|) | O(\|C\|) | STARK 渐近更优 |

## 4. 总结

Fischlin 框架经过近 20 年的演化，从 CRS 依赖的通用 NIZK 构造发展为可以在 ROM 中灵活实例化的模块化编译器。Bouillaguet et al. [S&P 2026] 的通用 Hash-and-Sign 编译器代表了这一演化的最新状态——它将 Fischlin 框架**完全解耦**为三个独立组件（底层签名、承诺方案、零知识证明），允许每个组件独立选择和优化。

本项目正是利用这种模块性做出了以下选择：
- **最保守的底层签名:** SPHINCS+ (仅假设哈希函数安全性)
- **最保守的零知识证明:** STARK (仅假设哈希函数安全性，无 Trusted Setup)
- **共设计的哈希函数:** Poseidon2 (在 SPHINCS+ 验证和 STARK AIR 中复用同一个域)

这一选择的哲学是：**后量子安全性不需要在效率和保守性之间 trade-off，通过哈希-证明共设计可以实现两者兼得。**

---

## 参考文献

- [Fischlin 2006] M. Fischlin, "Round-Optimal Composable Blind Signatures in the Common Reference String Model," CRYPTO 2006. [DOI: 10.1007/11818175_4](https://doi.org/10.1007/11818175_4)
- [Fuchsbauer et al. 2015] G. Fuchsbauer, C. Hanser, D. Slamanig, "Practical Round-Optimal Blind Signatures in the Standard Model," CRYPTO 2015. [DOI: 10.1007/978-3-662-48000-7_34](https://doi.org/10.1007/978-3-662-48000-7_34)
- [del Pino-Katsumata 2022] R. del Pino, S. Katsumata, "A New Framework for More Efficient Round-Optimal Lattice-Based (Partially) Blind Signature via Trapdoor Sampling," CRYPTO 2022. [DOI: 10.1007/978-3-031-15979-4_11](https://doi.org/10.1007/978-3-031-15979-4_11)
- [Beullens et al. 2023] W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler, "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal," CCS 2023. [DOI: 10.1145/3576915.3616613](https://doi.org/10.1145/3576915.3616613)
- [Bouillaguet et al. 2026] C. Bouillaguet, T. Feneuil, J. Maire, M. Rivain, J. Sauvage, D. Vergnaud, "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. [DOI: 10.1109/SP63933.2026.00032](https://doi.org/10.1109/SP63933.2026.00032)
- [Dietz et al. 2026] M. Dietz, J. Kastner, S. Tessaro, "On the Impossibility of Round-Optimal Pairing-Free Blind Signatures in the ROM," IACR [ePrint 2026/090](https://eprint.iacr.org/2026/090).
- [Herranz-Louiso 2025] J. Herranz, H. Louiso, "Hash-Based Blind Signatures: First Steps," IACR [[ePrint 2025/209](https://eprint.iacr.org/2025/209)7](https://eprint.iacr.org/2025/2097).
- [Kastner et al. 2024] J. Kastner, K. Nguyen, M. Reichle, "Pairing-Free Blind Signatures from Standard Assumptions in the ROM," CRYPTO 2024. [DOI: 10.1007/978-3-031-68376-3_7](https://doi.org/10.1007/978-3-031-68376-3_7)
- [Bernstein et al. 2019] D. J. Bernstein et al., "The SPHINCS+ Signature Framework," CCS 2019. [DOI: 10.1145/3319535.3363229](https://doi.org/10.1145/3319535.3363229)
- [Grassi et al. 2023] L. Grassi, D. Khovratovich, M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon Hash Function," AFRICACRYPT 2023. [DOI: 10.1007/978-3-031-37679-5_8](https://doi.org/10.1007/978-3-031-37679-5_8)
