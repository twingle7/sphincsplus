# 交付物 #5: 技术难点挖掘 — 从工程实现中提取学术贡献

## 1. 概述

本项目的核心是**工程实现**而非算法设计。在论文中，技术贡献需要通过详细阐述工程中解决的非平凡问题来体现。以下是 5 个可以写入论文的技术难点，每个均有具体的代码级解决方案和设计决策。

## 2. 技术难点逐一分析

### 2.1 Full-AIR 约束设计：53 条约束覆盖完整 SPHINCS+ 验证

**问题描述:**
STARK 的 AIR (Algebraic Intermediate Representation) 需要将**完整的** SPHINCS+ 验证计算表示为多项式约束。SPHINCS+ 验证包含 2,091 次 Poseidon2 置换（128-bit 参数），每次置换有 12 个状态 lane、8 个全轮和 22 个部分轮。直接约束每个字节操作会产生 >500K 约束，导致证明时间不可接受。

**难点:**
- 如何将 SPHINCS+ 的**复杂控制流**（FORS 树、WOTS 链、Merkle 路径验证）转化为多项式等式约束？
- 如何设计约束使得 proof size 和 prove time 落在实用范围（<100 KB, <1 min）？
- 如何在约束数量与安全性覆盖之间取得平衡？

**解决方案: Pre-computed Expected Next State (PENS) 方法**

本项目的核心设计决策是：**不在 AIR 中重新实现整个 SPHINCS+ 验证逻辑，而是在 trace building 阶段预先计算所有 Poseidon2 置换的期望输出，AIR 仅检查 trace 中的实际下一状态 (columns 28-39) 是否等于 pre-computed 期望值 (columns 16-27)。**

这 53 条约束分为 8 类：

| 约束类别 | 数量 | 约束内容 |
|---------|------|---------|
| Core Permutation | 16 | rate lanes (cols 0-5) 的 x^7 S-box + MDS + RC；capacity lanes (cols 6-11) 的 x^7 S-box |
| Internal round | 4 | 部分轮: lane 0 的 x^7 S-box + RC，capacity lanes 恒等 |
| Round Counter | 2 | RC 递增 (0..29)，在 permutation 边界重置为 0 |
| Perm Index | 2 | perm_idx 在 permutation 内恒定，在边界递增 |
| Call Type | 2 | call_type 在 permutation 内不变 |
| Sponge Continuity | 6 | carries_from_prev/carries_to_next 标志 + init_state (cols 12-15) 与输出状态 (cols 28-39) 的连续性 |
| THASH Absorb Binding | 8 | absorb[0] = domain+pub_seed (Lagrange selector 在 THASH 第一行检查), absorb[1] = pub_seed_hi, absorb[2..5] = expected addr bytes |
| pk_root Assertion | 1 | 在 root_row 的边界断言: trace 中的 Merkle root = pk_root (public input) |
| Padding + Copies | 12 | pad flag, copies 约束 |
| **总计** | **53** | |

**创新性:** PENS 方法将 SPHINCS+ 的完整验证语义编码在 trace 数据中，AIR 仅验证**一致性**（consistency）而非**正确性**（correctness）。这类似于 zkVM 中"执行一次，验证一致"的理念——trace builder 担任"prover"，AIR 约束担任"verifier"。这种设计大幅减少了约束数量（从 >500K 到 53），使证明时间从数小时降至 37 秒。

**论文中的表述:**
> "We adopt a pre-computed expected next state (PENS) methodology: the trace builder executes SPHINCS+ verification once and records every intermediate state, while the AIR constraints check that these states are consistent with the Poseidon2 round function, sponge continuity, and input binding. This reduces the AIR from ~500K constraints in a native circuit to 53 constraints, making STARK proving practical at 37 seconds."

### 2.2 Sponge State Continuity: 跨 Permutation Block 状态传递

**问题描述:**
Poseidon2 使用海绵结构，消息通过多次 `poseidon2_inc_absorb` → `poseidon2_inc_squeeze` 调用进行吸收和挤出。在 trace 中，不同的 permutation 必须保持 sponge 状态的连续性：前一个 permutation 的输出状态必须等于下一个 permutation 的输入状态。

在 C 代码中，这由 `poseidon2_t` 状态对象管理——`poseidon2_inc_absorb` 向内部状态 buffer 写数据，`poseidon2_inc_squeeze` 执行 permutation 并输出。但在 trace 的 2D 矩阵表示中，每个 permutation 被展开为 30 行（每行是一个 round），没有显式的 sponge 状态对象。

**难点:**
- 如何将面向对象的状态管理（C 中的 `poseidon2_t`）映射到二维 trace 矩阵？
- 相邻 permutation 不在连续的 trace 行中（中间可能有几千行属于其他 permutation），如何表达"输出 = 下一个 permutation 的输入"的约束？
- 当 sponge 在一次吸收中吸收多个元素时（如吸收 5 个 addr 字节），如何追踪部分状态？

**解决方案: 标志位 + Init_State Columns**

在 trace 中引入了：
1. **carries_from_prev** (column 39): 如果为 1，表示当前行开始一个新的 permutation，且其输入 sponge 状态应来自上一个 permutation 的输出
2. **carries_to_next** (column 40): 如果为 1，表示当前 permutation 的输出 sponge 状态将被下一个 permutation 继承
3. **init_state** (columns 41-52): 存储当前 permutation 的初始 sponge 状态（在吸收任何消息之前）

AIR 约束：
```
如果 carries_from_prev[i] = 1，则
  init_state[i] = 上一个 permutation 最终行的最终 sponge 状态
  （通过 columns 39-52 的 permutation 状态输出 + carries_to_next 标记来索引）
```

**实现细节 (trace_builder.rs):**
```rust
// For each hash operation (THASH_F, THASH_H, THASH_TL):
// 1. Record carries_from_prev = true at row 0 of the operation
// 2. Populate init_state columns from previous_perm_state
// 3. Execute all absorptions and squeezes
// 4. Set carries_to_next = true in the final row
// 5. Update previous_perm_state = final_sponge_state
```

**挑战的具体性:** 这个问题的解决需要 trace builder 从 C 代码的 `poseidon2_t` 状态中提取完整的 sponge 状态快照，并在 trace 中插入跨越数千行的连续性约束。在典型的 AIR 设计中（例如 Fibonacci 序列），连续性约束仅涉及相邻行。跨非连续行的绑定是本项目的一个设计特色。

### 2.3 THASH Absorb Binding: 将 Domain + Pub_Seed + ADRS 绑定到 Trace

**问题描述:**
SPHINCS+ 使用 THASH (Tweakable Hash) 来防止多目标攻击。THASH 的每次调用都绑定了：
- domain_tag: 1 字节（区分 FORS、WOTS、Merkle 层：F=0x11, H=0x12, TL=0x13）
- pub_seed: 32 字节的公共种子（PK.seed）
- addr: 32 字节的 ADRS（编码当前计算在 hypertree/FORS 树中的精确位置）

这些值在 SPHINCS+ C 实现中是**隐式绑定**的——它们通过 THASH 的参数传递，在哈希内部被 absorb。但在 trace 中，这些值需要被**显式约束**——否则敌手可以在 proof 生成时替换 pub_seed 或 addr，生成一个对相同 pk_root 但不同公钥有效的"假证明"。

**难点:**
- absorb 操作跨越多个 trace 行（address 在 3 个 absorb 行中加载），如何逐行约束？
- domain_tag 和 pub_seed 是每个 THASH 调用**共有的**，但 addr 是**每个 THASH 调用特有的**（取决于在 hypertree 中的位置）。如何区分"每行的共享约束"与"每行的特有约束"？

**解决方案: Lagrange Selector + Pre-computed Expected Absorb**

这 8 条约束 (constraints 45-52) 是本项目 AIR 中最精细的部分：

1. **absorb[0] (row 0 of each THASH permutation):** 
   ```
   如果 Lagrange_selector[row] == 1 (当前行是 THASH 的第一次吸收):
     absorb[0] = domain_tag || pub_seed[0..7]
   ```
   domain_tag 从 call_type 派生（F=0x11, H=0x12, TL=0x13），pub_seed 来自 public input

2. **absorb[1] (row 1):**
   ```
   如果这是 THASH 的第一个 permutation:
     absorb[1] = pub_seed[8..15]
   ```

3. **absorb[2..5] (rows 2-5):**
   ```
   对每个 absorb:
     实际 trace 中的 absorb 值 = pre-computed expected addr 字节
   ```
   expected addr 字节由 trace builder 根据 SPHINCS+ 验证逻辑预先计算

**安全性论证:**
- domain_tag 绑定：防止跨 THASH 类型的伪造（不能用 FORS hash 的结果来伪造 WOTS 签名）
- pub_seed 绑定：防止跨公钥的伪造（不能将 pk_1 的证明用于 pk_2，因为 pub_seed 不同）
- addr 绑定：防止跨位置的伪造（不能将一个 Merkle 路径节点的 hash 重放为另一个节点）

**论文中的表述:**
> "Constraints 45-52 enforce THASH absorb binding: absorb values at each permutation boundary are checked against domain tag, public seed, and address bytes derived from the SPHINCS+ verification walk. This prevents an adversary from reusing a valid trace for one public key to generate a proof for a different public key — a subtle binding gap that naive AIR designs miss."

### 2.4 pk_root Boundary Assertion: 将 Merkle Root 绑定到 Public Key

**问题描述:**
SPHINCS+ 验证的核心检查是：计算出的 Merkle root 必须等于公钥（pk_root）。在 AIR 中，这需要一个**边界断言**（boundary constraint）——仅在 trace 的特定行（root_row）检查该约束。

**难点:**
- pk_root 在 SPHINCS+ C 验证中被计算为最后一个 Merkle 路径验证的输出。在 trace 中，"最后一行"不一定对应 SPHINCS+ 语义中的"pk_root 计算完成"，因为 padding 行占据了 trace 末尾
- 如何确定 root_row 的位置？如果 trace 参数改变（例如不同的 n/h/d），该位置会漂移

**解决方案:**
Trace builder 在构建 trace 时标记 root_row 索引。AIR 使用 Winterfell 的 boundary constraint 原语：
```rust
builder.assert_last(flag_root, pk_root_column - public_pk_root);
```
或更精确地：
```rust
// 在 trace 中标记 root_row 行
// 在该行的 boundary constraint:
assert(trace[root_row][root_col] == public_inputs.pk_root)
```

**效果:** 这确保了：即使所有 2,091 个 Poseidon2 置换都正确执行，如果最终的 root 不等于 pk，证明仍然会失败。这是防止"结构正确的计算但错误的结果"的关键防线。

### 2.5 Poseidon2 作为 THF 的安全论证：模块化 ROM 归约

这个技术难点更偏**理论**而非代码，但对审稿来说至关重要。

**问题:**
SPHINCS+ 规范的安全性证明（Theorem 1-2）**解耦了** THF 的安全性（SM-TCR/SM-DSPR/SM-PRE/SM-UD）与 SPHINCS+ 的 EUF-CMA 安全性。替换哈希函数时，只需验证新哈希函数满足上述四个 THF 性质。

**难点:**
- Poseidon2 的设计文档没有显式分析 SM-TCR/SM-DSPR/SM-PRE/SM-UD 性质
- 这些性质是**多目标**（multi-target）变体——涉及攻击者对多个 key 的并行攻击能力
- 如何论证 Poseidon2 (Goldilocks, 30 轮) 足够强大以在 ROM 中提供这些性质？

**解决方案: 模块化继承 + 保守估计**

参考 SPHINCS+-SM3 [《密码学报》2023] 的方法论：

1. **不重新推导安全界** — 直接引用 SPHINCS+ 规范的 Theorem 1-2
2. **论证 Poseidon2 在 ROM 中满足 THF 性质** — 通过以下论点：
   - Poseidon2 的海绵构造是经典的 ROM 实例化 → SM-TCR/DSPR/PRE/UD 在 ROM 下自动成立
   - THASH 的域标签 (domain tag) 提供域分离 → 防止跨 THASH 类型的多目标攻击
   - ADRS 提供地址隔离 → 防止跨 hypertree 位置的多目标攻击
   - Poseidon2 的 30 轮远超已知攻击（统计饱和攻击 ~18 轮，Groebner ~14 轮）→ 提供充分单实例安全性
3. **参数选择** 遵循 SPHINCS+ 规范的方法论，仅将签名预算 q_s 从 2^64 调整为 2^16（盲签名场景）
4. **给出保守安全估计** — FORS: k·a - log(q·k) ≥ 128 bit（q=2^16），HT: 8n - log(q) - log(d) ≥ 128 bit

**论文中的表述 (重要——避免过度声明):**
> ✅ "Based on the modular THF security framework of SPHINCS+ [Bernstein CCS'19], Poseidon2's sponge construction in the random oracle model satisfies the required SM-TCR, SM-DSPR, SM-PRE, and SM-UD properties. The domain tags and ADRS encoding provide the necessary domain separation for multi-target security."
>
> ❌ "We prove that Poseidon2 achieves 128-bit security in the UC model."

## 3. 技术难点总览表

| 难点 | 类别 | 难度 | 创新度 | 论文中的位置 |
|------|------|------|--------|-----------|
| Full-AIR PENS 方法 | 约束设计 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | § Design |
| Sponge Continuity | 数据流 | ⭐⭐⭐⭐ | ⭐⭐⭐ | § Trace Building |
| THASH Absorb Binding | 安全性 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | § Security |
| pk_root Boundary Assertion | 安全性 | ⭐⭐⭐ | ⭐⭐⭐ | § Design |
| THF 安全论证 | 理论 | ⭐⭐⭐⭐ | ⭐⭐⭐ | § Security Analysis |

## 4. 论文中如何呈现这些难点

### 建议的"Technical Challenges and Design Decisions"章节结构:

```
§3. Design Challenges and Solutions
  3.1 The PENS Methodology: Why Not a Native Circuit? (2-3 paragraphs)
  3.2 Sponge State Continuity Across Permutation Blocks (2 paragraphs + diagram)
  3.3 THASH Absorb Binding: Securing the Input Dataflow (3 paragraphs + constraint table)
  3.4 Boundary Constraints: Merkle Root, Padding, and Call Type Sequencing (2 paragraphs)
```

每个子节应遵循"问题 → 为什么困难 → 我们的解决方案 → 方案的安全性/正确性论证"的结构。

## 5. 总结

本项目的技术贡献不在于发明新密码学原语，而在于**解决将一个复杂协议（SPHINCS+ Fischlin）映射到 STARK AIR 的过程中出现的一系列非平凡工程问题**。这些问题在文献中未被充分讨论——大多数 AIR 论文处理的是简化示例（Fibonacci、Merkle 路径），而本项目需要处理 2,091 个 permutation 的完整验证流程。

审稿人应该认识到：**第一个完整实现的价值不在于代码行了多少，而在于它是"方案可行"的唯一证据。** 在 Bouillaguet 仅给出理论框架、Herranz 仅给出问题定义的背景下，本项目的 53-constraint AIR + 23,861-row trace + 37s prove time 构成了一个 concrete existence proof。

---

*本项目实现的源文件:*
- `ref/stark-rs/src/air_engine.rs` — Full-AIR definition (53 constraints)
- `ref/stark-rs/src/trace_builder.rs` — SPHINCS+ verification walk + trace builder
- `ref/stark/ffi.c` — C FFI layer
- `ref/CURRENT_STATUS.md` — Architecture documentation
- `ref/SECURITY_ANALYSIS.md` — THF security framework analysis
