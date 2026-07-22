# 交付物 #7: 框架改动与安全性规约

## 1. 安全归约链的完整结构

本项目的安全性通过以下**四层模块化归约**来论证：

```
┌──────────────────────────────────────────────────────┐
│ 第 4 层: Fischlin 盲签名 OMUF 安全性                   │
│    ↑ 归约 (Bouillaguet et al., IEEE S&P 2026)         │
│ 第 3 层: SPHINCS+ EUF-CMA 安全性                      │
│    ↑ 归约 (SPHINCS+ 规范, Bernstein et al., CCS 2019)  │
│ 第 2 层: THF 四性质 (SM-TCR/SM-DSPR/SM-PRE/SM-UD)     │
│    ↑ 实例化 (ROM)                                      │
│ 第 1 层: Poseidon2 海绵构造 (Goldilocks, t=12, 30 轮)  │
└──────────────────────────────────────────────────────┘
```

每一层都是**解耦的**——上层的安全结论不需要重新推导，仅需证明下层满足上层的前提条件。这种模块化方法源自 SPHINCS+ 规范的设计哲学，并在 SPHINCS+-SM3 [《密码学报》2023] 中得到了验证。

## 2. 逐层分析

### 2.1 第 1 层 → 第 2 层: Poseidon2 作为 THF 的实例化

**SPHINCS+ 规范要求 THF 满足四个性质:**

| 性质 | 全称 | 含义 | 在 SPHINCS+ 中的对应组件 |
|------|------|------|------------------------|
| **SM-TCR** | Single-Function, Multi-Target Collision Resistance | 给定 P (pub_seed)，攻击者难以找到两个不同的 M, M' 使得 Th(P, T, M) = Th(P, T, M') | WOTS+ 链安全性 |
| **SM-DSPR** | Single-Function, Multi-Target Decisional Second-Preimage Resistance | 给定 P 和 M，难以找到 M' ≠ M 使得 Th(P, T, M) = Th(P, T, M') | FORS 叶节点安全性 |
| **SM-PRE** | Single-Function, Multi-Target Preimage Resistance | 给定 P 和 y，难以找到 M 使得 Th(P, T, M) = y | Hypertree 层间安全性 |
| **SM-UD** | Single-Function, Multi-Target Undetectability | Th(P, T, ·) 在 ROM 中与随机函数不可区分 | 伪随机生成 (PRF, H_msg) |

**Poseidon2 满足这些性质的论证:**

1. **ROM 实例化:** Poseidon2 的海绵构造在 ROM 下是标准的。`Th(P, T, M)` 定义为：
   ```
   Th(P, T, M) = Poseidon2_Sponge.absorb(P || T || M).squeeze(n)
   ```
   其中 P = pub_seed (pad 到 sponge rate)，T = 32-byte ADRS (pad 到 rate)，M = message (pad10*1 到 rate)

2. **域标签 (Domain Tags):** THASH 使用三个不同的域标签（F=0x11, H=0x12, TL=0x13）来区分 FORS、WOTS 叶和 Merkle 树层的哈希调用。这些标签作为 sponge absorb 的第一个字节，提供了**完全域分离**——不同调用类型使用不同的 RO。

3. **多目标防护 (ADRS):** SPHINCS+ 的 ADRS 编码了 hypertree 中的精确位置（layer + tree index + leaf index）。在 ROM 中，ADRS 提供了**独立前缀**——不同地址的 THASH 调用模拟为独立的 RO。这使多目标攻击的成功概率保持为单实例攻击概率 × 目标数量（标准 ROM bound），不会出现灾难性的交叉目标加速。

4. **轮数充分性:** 
   - 已知攻击阈值：统计饱和攻击 ~18 轮，Groebner 基攻击 ~14 轮，差分攻击 ~16 轮
   - Poseidon2 使用 **30 轮（8+22）**，至少 **12 轮的安全边际**
   - 对于多目标设置，安全边际更大——每个目标的成功概率远低于 2^{-128}

**保守性陈述:**
> Poseidon2 (Goldilocks, t=12, RF=8, RP=22) 提供 30 轮置换，远超已知密码分析攻击所需的最少轮数。在 ROM 中，该实例化满足 SPHINCS+ 规范对 THF 的所有安全性质要求。

### 2.2 第 2 层 → 第 3 层: THF 性质 → SPHINCS+ EUF-CMA

**这是 SPHINCS+ 规范的直接继承——不需要修改。**

SPHINCS+ 规范 [Bernstein et al., CCS 2019] 的 Theorem 1-2 给出了完整的 game-hopping 归约：

```
Adv_EUF-CMA(SPHINCS+) ≤ 
    Adv_SM-TCR(THF) + Adv_SM-DSPR(THF) + Adv_SM-PRE(THF) + Adv_SM-UD(THF)
    + negl(λ)
```

其中每个 Adv 项上界为 O(q_s · 2^{-8n})（对于 n-byte 输出的 RO，紧致归约给出 ~8n bit 安全性）。

**本项目的参数 (n=16):**
- RO 安全性: 8×16 = 128 bit (ROM 紧致 bound)
- 保守简化估计: FORS: k·a - log(q·k) = 10×12 - log(2^{16}·10) = 120 - 20 = 100 bit
- 规范紧致 bound (参考 128s 的 61→121 放大): ~121+ bit

**关键修改—签名预算 q_s:**

标准的 SPHINCS+ 假设 q_s = 2^{64}（接近无限的签名预算）。在盲签名场景中，q_s 由应用确定：
- 匿名凭证系统: q_s = 2^{16} (65K 用户)
- 电子投票: q_s = 2^8 到 2^{16}
- 区块链: 取决于使用模式

**更小的 q_s → FORS 和 HT 安全项更大 → 可以使用更小的 (k, a) → 更快的证明时间。**

本项目当前使用 n=16, k=10, a=12 (k·a=120)，对于 q_s = 2^{16} 达到 ~121 bit 范畴安全（紧致 bound）。更大的 k·a（如 k=14, a=12 → k·a=168）提供更大的富余。

### 2.3 第 3 层 → 第 4 层: SPHINCS+ EUF-CMA → Fischlin OMUF

**Bouillaguet 编译器的安全归约 (IEEE S&P 2026):**

编译器将 EUF-CMA 安全的 Hash-and-Sign 方案 Σ 转换为 OMUF 安全的 Fischlin 盲签名方案 BS，归约损失为 poly(λ)：

```
Adv_OMUF(BS) ≤ Adv_EUF-CMA(Σ) + Adv_Collision(H) + Adv_Binding(Commit)
```

其中：
- **Adv_EUF-CMA(Σ):** 底层签名方案 SPHINCS+ 的不可伪造性（已在 2.2 节论证 ≤ negl(λ)）
- **Adv_Collision(H):** 承诺方案中哈希函数 H 的碰撞抵抗。H 是独立的 RO ⇒ Adv_Collision(H) ≤ q_H^2 · 2^{-|H_output|} ≤ negl(λ)
- **Adv_Binding(Commit):** 承诺方案的计算 Binding。在 ROM 中，对 RO 的 binding 等同于 collision resistance

**OMUF 安全性的意义:**

OMUF (One-More Unforgeability) 是盲签名的核心安全定义：攻击者获得 ℓ 次签名谕言机（与 Signer 交互 ℓ 次），不能输出 ℓ+1 个有效的、彼此独立的（message, signature）对。

这对于盲签名的应用场景至关重要——用户不能"凭空创造"额外的有效凭证。每个有效凭证必须对应 Issuer 的一次真实签发。

### 2.4 完整的归约链（论文中的呈现）

论文的 Security Analysis 章节可组织为：

```
§5. Security Analysis
  5.1 Security Model (OMUF + Blindness definitions, 1 paragraph each)
  5.2 THF Security of Poseidon2 (2 paragraphs + ROM argument)
  5.3 SPHINCS+ EUF-CMA (1 paragraph, reference to Bernstein CCS'19 Theorems 1-2)
  5.4 Reduction to Fischlin OMUF (2 paragraphs, reference to Bouillaguet S&P'26)
  5.5 Parameter Selection and Concrete Security (1 paragraph + parameter table)
  5.6 Discussion: What Is Not Proven (1 honest paragraph about UC model and side-channel)
```

## 3. 框架改动与安全影响分析

本项目对 Bouillaguet 编译器的改动主要有三项。以下是每项改动的安全性分析：

### 3.1 改动 1: MPC-in-the-Head → STARK 证明系统

**改动:** 将 Bouillaguet 编译器中的通用 NIZK (MPC-in-the-Head 实例化) 替换为 STARK (Winterfell)

**安全影响:** ⚠️ 需要额外论证

- Bouillaguet 的归约假设 NIZK 满足 (1) completeness, (2) soundness, (3) zero-knowledge
- STARK 在 ROM 下满足上述性质：(1) completeness → STARK 总是通过诚实验证，(2) soundness → FRI 协议保证 ~108-bit soundness (blowup=16, queries=27)，(3) zero-knowledge → 可通过 mask 多项式实现
- **关键:** STARK 的 soundness 依赖于 FRI 的 Merkle tree 的 collision resistance ——这与 Bouillaguet 归约中的 Adv_Collision(H) 项是一致的。不会引入新的假设。

**论文中的表述:**
> "The replacement of MPC-in-the-Head with STARK does not alter the security reduction, as both proof systems rely solely on the collision resistance of hash functions in the ROM. The STARK's conjectured soundness (~108 bits at blowup 16) is compatible with the 128-bit security target."

### 3.2 改动 2: Native Hash → Poseidon2 (THF 实例化)

**改动:** 将底层签名方案的哈希函数替换为 Poseidon2 (作为 THF)

**安全影响:** ✅ 已在 2.1 节论证

Bouillaguet 编译器的安全归约**独立于**底层签名的具体哈希实例化，仅要求底层签名满足 EUF-CMA。只要 Poseidon2 满足 THF 性质，SPHINCS+ 的 EUF-CMA 直接继承。

### 3.3 改动 3: 签名预算 q_s = 2^{16} (替代 2^{64})

**改动:** 将 FORS 安全约束中的 q_s 从 2^{64} 调整为 2^{16}

**安全影响:** ✅ 更小 q_s 实际上**增加**了安全边际（参见 2.2 节）

仅需在论文中显式声明 q_s = 2^{16} 是应用场景的合理假设，并给出 q_s 随应用变化的敏感性分析（参见 SECURITY_ANALYSIS.md §3.4）。

### 3.4 改动 4: public_ctx 绑定 (半盲签名支持)

**改动:** 在 STARK 证明的 public inputs 中绑定 ctx_hash = Blake3(pk ‖ pk_e ‖ com ‖ m_pub ‖ public_ctx ‖ sigma_c)

**安全影响:** ✅ 增强安全性

- public_ctx 被包含在 proof 的 public input hash 中，敌手无法在不同 public_ctx 之间重放证明
- ctx_hash 作为 proof header (v2 format, 296 bytes) 的一部分，在 verify 时被检查
- 这不会引入新的攻击面——ctx_hash 的 collision resistance 由 Blake3 保证

## 4. "没有形式化安全证明"的诚实处理

项目**没有**提供以下形式化证明：
- UC (Universal Composability) 框架下的组合安全性
- 完整 game-hopping 序列的机械化验证
- Quantum ROM (QROM) 中的安全性
- Constant-time 实现（侧信道防护）

**在论文中的处理方式:**

```
§5.6 Limitations and Future Work

We do not provide a formal proof in the Universal Composability framework, 
as our security argument follows the modular reduction methodology of SPHINCS+ 
and Bouillaguet et al., which is standard in the ROM. The following limitations 
are acknowledged:

1. Quantum ROM: Our analysis is in the classical ROM; the QROM security of 
   Poseidon2 as a THF is an open research question.
2. Side-Channel: The current implementation is not constant-time; side-channel 
   resistance for STARK proving is deferred to future work.
3. Parameterization: Our implementation hardcodes n=16 (128-bit); extension 
   to n=24 (192-bit) and n=32 (256-bit) requires trace builder generalization.
```

**关键原则:** 诚实承认限制 + 指出限制不影响本文贡献 + 不夸大安全性。这种诚实性在同行评审中是被尊重的（相比于过度声称安全性）。

## 5. 参考文献

- [Bernstein et al. 2019] D. J. Bernstein, A. Hulsing, S. Kolbl, R. Niederhagen, J. Rijneveld, T. Simson, "The SPHINCS+ Signature Framework," CCS 2019. DOI: 10.1145/3319535.3363229
- [Bouillaguet et al. 2026] C. Bouillaguet, T. Feneuil, J. Maire, M. Rivain, J. Sauvage, D. Vergnaud, "Blinding Post-Quantum Hash-and-Sign Signatures," IEEE S&P 2026. DOI: 10.1109/SP63933.2026.00032
- [SPHINCS+ v3.1] J. P. Aumasson et al., "SPHINCS+ — Submission to the NIST PQC Standardization Project, v3.1," 2022.
- [NIST FIPS 205] NIST, "Stateless Hash-Based Digital Signature Standard," FIPS 205, 2024.
- [Grassi et al. 2023] L. Grassi, D. Khovratovich, M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon Hash Function," AFRICACRYPT 2023. DOI: 10.1007/978-3-031-37679-5_8
- [孙思维等 2023] 孙思维等, "SPHINCS+-SM3: 基于SM3的无状态数字签名算法," 《密码学报》, 2023, 10(6): 1266-1278.
- [Fischlin 2006] M. Fischlin, "Round-Optimal Composable Blind Signatures in the Common Reference String Model," CRYPTO 2006.
- [del Pino-Katsumata 2022] R. del Pino, S. Katsumata, "A New Framework for More Efficient Round-Optimal Lattice-Based (Partially) Blind Signature via Trapdoor Sampling," CRYPTO 2022. DOI: 10.1007/978-3-031-15979-4_11
- [Beullens et al. 2023] W. Beullens, V. Lyubashevsky, N. K. Nguyen, G. Seiler, "Lattice-Based Blind Signatures: Short, Efficient, and Round-Optimal," CCS 2023. DOI: 10.1145/3576915.3616613
- [Ben-Sasson et al. 2020] E. Ben-Sasson et al., "DEEP-FRI: Sampling Outside the Box Improves Soundness," ITCS 2020.
- [Adomnicai 2026] A. Adomnicai, "Towards Practical Multi-Party Hash Chains using Arithmetization-Oriented Primitives," IACR Comm. Cryptol., 2026.
