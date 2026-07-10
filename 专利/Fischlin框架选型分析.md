# Fischlin 框架选型分析：原始方案 vs 最新变体

> 分析日期：2026年7月10日
> 当前使用：Fischlin 2006 (CRYPTO) + SPHINCS+ + Poseidon2 + STARK

---

## 一、当前方案的技术定位

我们的方案在Fischlin框架中的角色映射：

```
Fischlin 2006 通用构造:
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ 承诺方案      │    │ 签名方案      │    │ NIZKPoK      │
│ Commit(m;r)  │    │ Sign(sk, c)  │    │ π: 证明       │
│              │    │              │    │ 签名有效+     │
│              │    │              │    │ 承诺正确      │
└──────────────┘    └──────────────┘    └──────────────┘
     Poseidon2         SPHINCS+           Winterfell STARK
     (哈希承诺)        (后量子签名)        (全内生AIR)
```

**安全性假设**：仅依赖 (1) Poseidon2的抗碰撞性 (2) SPHINCS+的THF安全性 (3) STARK的可靠性

---

## 二、最新Fischlin变体对比

### 变体1: Katsumata et al. (ASIACRYPT 2023)
**"Practical Round-Optimal Blind Signatures in ROM from Standard Assumptions"**

| 维度 | 分析 |
|------|------|
| 核心改进 | 弱化NIZK要求：在线可提取→重绕可提取；PKE→承诺方案 |
| 效率 | 方案二签名仅96字节（目前最小盲签名） |
| 安全性 | 基于配对假设(CDH/DDH/SXDH) — **不抗量子** |
| 适用性 | ❌ 不适合我们——依赖配对，非后量子 |

**结论：不适用。** 效率惊人但安全性假设与我们不同——他们用配对实现紧凑性，我们用哈希实现抗量子性。这是安全模型层面的根本分歧。

---

### 变体2: Bouillaguet et al. (IEEE S&P 2026)
**"Blinding Post-Quantum Hash-and-Sign Signatures" — CAP系统**

| 维度 | 分析 |
|------|------|
| 核心改进 | CAP(Commit-Append-Prove)泛化Fischlin，专为后量子hash-and-sign设计 |
| NIZK | MPC-in-the-Head (MPCitH)，不依赖STARK/SNARK |
| 效率 | UOV盲签名3.8-11KB；Wave盲签名 |
| 安全性 | MQ问题(多元) / 编码解码(编码) — 抗量子但非哈希 |
| 适用性 | ⚠️ 部分适用——CAP的泛化思路可借鉴，但底层签名不同 |

**关键差异**：CAP将Fischlin泛化为三个模块：
1. **Commit**：同Fischlin，承诺消息
2. **Append**：追加公开数据（如公钥、上下文）——这是Fischlin没有的显式步骤
3. **Prove**：MPCitH NIZK证明"hash-and-sign验证通过"

我们的方案可以映射到CAP：
- Commit = Poseidon2承诺 (同Fischlin)
- Append = 追加pk_E, m_pub, public_ctx (我们已有Statement-Bound模式)
- Prove = STARK证明 (我们使用STARK替代CAP的MPCitH)

---

### 变体3: Herranz & Louiso (ePrint 2025/2097)
**"Hash-Based Blind Signatures: First Steps" — 纯哈希盲签名**

| 维度 | 分析 |
|------|------|
| 核心改进 | 首个**仅依赖哈希抗碰撞性**的盲签名——安全性假设最保守 |
| NIZK | MPC-in-the-Head |
| 效率 | 签名较大（哈希+MPCitH的开销），但安全性最保守 |
| 安全性 | 仅哈希碰撞抗性 (ROM)，无格/同源/多元假设 |
| 适用性 | ⚠️ 与本项目目标最接近，但技术路线不同 |

**这是与本项目方向最接近的独立工作！** 区别在于：
- Herranz用MPCitH作NIZK → 我们**用STARK作NIZK**
- Herranz用通用哈希(如SHA-256) → 我们**用Poseidon2(ZK友好哈希)**

这个区别正是我们的核心创新：**ZK友好哈希(Poseidon2)使得在STARK电路中的证明效率极高**（仅16约束），而Herranz方案用SHA-256在MPCitH电路中代价很高。

---

### 变体4: Tanuki (ASIACRYPT 2025)
**"New Frameworks for Blind Signatures from Post-Quantum Group Actions"**

| 维度 | 分析 |
|------|------|
| 核心改进 | 四个基于群作用的盲签名新框架，首次实现并发安全 |
| NIZK | Sigma协议+FS变换 |
| 效率 | CSIDH实例3.9KB; LESS实例56KB |
| 安全性 | 群作用(GAIP/CSI) — 抗量子但非哈希 |
| 适用性 | ❌ 不适合——基于群作用假设，与我们基于哈希的技术路线不同 |

---

## 三、结论：保持Fischlin 2006 + STARK是正确的

### 为什么不需要切换变体？

**1. 安全假设的保守性是我们方案的核心优势**

| 方案 | 安全假设 | 抗量子 | 假设保守性 |
|------|---------|--------|-----------|
| Katsumata 2023 | 配对(CDH/DDH) | ❌ | 弱 |
| Bouillaguet CAP | MQ/编码 | ✅ | 中 |
| Tanuki 2025 | 群作用(GAIP) | ✅ | 中 |
| Herranz 2025 | **仅哈希碰撞** | ✅ | **最强** |
| **我们的方案** | **仅哈希碰撞** | ✅ | **最强** |

我们和Herranz共享最保守的安全性假设。但我们在效率上有优势（STARK的16约束 vs MPCitH的电路门数）。

**2. Fischlin 2006的"强假设"已被我们的实例化自然满足**

Fischlin 2006要求：
- PKE（公钥加密）— 我们用Poseidon2的密码学海绵实现密钥封装
- 在线可提取NIZK — STARK天然支持知识提取（Knowledge Soundness）

换句话说，2006年Fischlin提出的"强假设"在2026年已经有了实用的后量子实例化。我们不需要弱化假设的变体，因为我们的实例化已经用更强的原语自然地满足了假设。

**3. CAP的"Append"步骤我们已在Statement-Bound模式中实现**

CAP引入的Append阶段（追加公共声明）与我们的Statement-Bound模式功能等价。这不是新功能——是Fischlin 2006中就已隐含存在（CRS本身就是公共参数）。CAP只是将它显式化，我们在Statement-Bound模式中也做了同样的事情。

**4. 我们的创新恰恰在于用STARK替代MPCitH**

Herranz 2025和CAP 2025都使用MPC-in-the-Head作为NIZK。我们的差异化和创新在于：
- **STARK的16约束AIR** vs MPCitH的电路门 → 证明更简洁
- **Poseidon2在STARK中的效率** vs SHA-256在MPCitH中的低效 → 这是我们的核心创新
- 如果切换到MPCitH，我们的Poseidon2优化将失去上下文

---

## 四、建议在论文中如何表述

### 推荐框架定位

```
"我们采用Fischlin (CRYPTO 2006)的通用盲签名框架，并基于
 SPHINCS+ (FIPS 205) 和 Poseidon2 (AFRICACRYPT 2023)
 进行了后量子实例化。

 具体的协议采用了CAP (IEEE S&P 2026) 的Commit-Append-Prove
 语义来显式化公共声明的绑定过程。

 在NIZKPoK组件上，我们使用Winterfell STARK 替代主流的
 MPC-in-the-Head方法 (cf. Herranz-Louiso 2025, Bouillaguet
 et al. 2026)，利用Poseidon2的AIR友好性将约束减少至16个，
 显著优于基于SHA-256的MPCitH电路。"
```

这一定位的好处：
- 承认了最新工作（CAP、Herranz）的存在
- 说明了我们的差异化（STARK > MPCitH）
- 没有声称我们"改进了Fischlin"——框架是一样，实例化不同

### 论文中可以引用的对比

| 对比维度 | Herranz 2025 (哈希盲签名) | Bouillaguet 2026 (CAP) | **本方案** |
|----------|--------------------------|----------------------|-----------|
| 底层签名 | 通用哈希签名 | UOV/Wave | **SPHINCS+** (标准化) |
| NIZK技术 | MPCitH | MPCitH | **STARK (全内生AIR)** |
| NIZK约束数 | ~数万门电路 | ~数万门电路 | **16个AIR约束** |
| 安全性假设 | 仅哈希碰撞 | MQ/编码 | **仅哈希碰撞** |
| 证明大小 | ~MB级 | ~KB级(签名小但证明另算) | **~95KB** |
| ZK友好哈希 | 无(SHA-256) | 无(专用结构) | **Poseidon2** |

---

## 五、最终建议

**✅ 保持当前Fischlin 2006 + SPHINCS+ + Poseidon2 + STARK的方案不变。**

理由总结：
1. **安全假设最保守**（仅哈希碰撞）——与Herranz 2025持平，优于所有其他变体
2. **STARK差异化**——所有最新变体都用MPCitH，我们用STARK和全内生AIR，这是独一无二的
3. **Poseidon2使STARK高效**——16约束 AIR是MPCitH无法达到的
4. **Fischlin 2006的假设已被后量子实例化满足**——不需要弱化
5. **CAP的语义可直接引用但不需要改变协议**——Statement-Bound模式已等价实现

论文中建议同时引用Fischlin 2006（框架来源）和CAP 2026（语义对齐），以展示对最新文献的覆盖，同时突出STARK替代MPCitH的创新点。
