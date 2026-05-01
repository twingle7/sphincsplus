# 第四章：基于 Fischlin 框架的盲签名方案设计与实现总结

## 1. 文档目的

本文档用于整理论文第四章所需材料，主题为“基于 Fischlin 框架的盲签名方案设计与实现”。本文档主要回答四类问题：

1. Fischlin 框架在本课题中的协议语义是什么；
2. 本仓库如何将其落地到 `Poseidon2 + SPHINCS+-like + STARK` 的工程实现中；
3. 当前仓库已经完成了哪些可稳定声明的成果；
4. 哪些内容必须保守表述为“工程原型”“部分约束增强”或“未来工作”。

本文档内容以仓库 `ref/` 目录中的代码、测试与总结文档为准，因此强调的是“实际实现口径”和“最终可声明成果”，而不是脱离仓库上下文的抽象理论终态。

## 2. Fischlin 框架的抽象语义

### 2.1 核心思想

Fischlin 盲签框架的核心思路可以概括为：

- 用户先对消息做承诺；
- 签发者对承诺值签名；
- 用户再构造一个证明，说明“我知道一个消息及其随机性，使该承诺可以打开到该消息，并且这个承诺上存在一个有效签名”；
- 验证者不需要看到内部签名本体，只需要验证最终展示对象是否满足该存在性关系。

若进一步按标准化抽象理解，其目标语言可以概括为：

```text
L = {
  (m, C, pk_E, pk_sig) :
  存在 (r, omega2, c, sigma')
  使得
    c = Com(m; r),
    C = Enc(pk_E, c || sigma'; omega2),
    Verify(pk_sig, c, sigma') = 1
}
```

这也是本仓库后续 strict public-statement 路径试图逼近的最终公开语句语义。

### 2.2 本课题采用 Fischlin 框架的原因

本课题选择 Fischlin 框架，主要有三个原因：

1. **与“签署承诺，再证明可打开”这一思路天然匹配**
   - 本仓库底层签名本体来自 `SPHINCS+-like` 结构，适合先对承诺 `com` 签名，再围绕 `com` 组织后续展示证明。

2. **适合把签发与展示拆开**
   - 签发阶段只需要 Issuer 对承诺签名；
   - 展示阶段由 Holder 单独完成证明生成，更适合结合零知识证明系统。

3. **与 STARK 增强路线兼容**
   - 该框架天然会引入一个“公开语句/私有见证”的存在性证明问题；
   - 这使得仓库可以把后续工作聚焦到 `ShowProve/ShowVerify` 的证明接口和 strict STARK 路径上。

因此，本课题并不是把 Fischlin 当作纯理论背景引用，而是把它作为整个盲签原型系统的协议组织方式。

## 3. 本仓库中的方案定位

### 3.1 方案整体结构

本仓库实现的盲签方案，可以概括为：

- 底层签发原语：`Poseidon2` 替换底层哈希后的 `SPHINCS+-like` 签名；
- 盲签协议框架：采用 Fischlin 风格的“承诺签发 + 展示证明”结构；
- 展示验证增强：在 `ShowProve/ShowVerify` 阶段接入最终展示证明对象与 strict STARK 路径。

因此，本方案不是“传统 RSA/椭圆曲线盲签”的直接移植，而是：

```text
Poseidon2-SPHINCS+-like + Fischlin 框架 + STARK 增强验证
```

### 3.2 为什么文中更适合使用 `SPHINCS+-like`

从仓库实现看，本课题虽然继承了 SPHINCS+ 的整体签名结构，但底层哈希已经替换为 Poseidon2，并且展示/证明链路也加入了仓库特定的 `sigma_C`、展示证明对象、strict public-statement 等机制。因此，更稳妥的论文口径是：

- `SPHINCS+-like`
- `基于 Fischlin 框架的后量子盲签原型系统`

而不宜直接表述为：

- “标准 SPHINCS+ 盲签完整实现”
- “标准 Fischlin 盲签等价实现”

因为仓库中的实现目标是“可运行原型 + 可验证增强”，而不是对标准文献构造做逐字节、逐关系的完全等价复刻。

## 4. 角色、对象与接口设计

### 4.1 三方角色

本仓库中的协议角色与 `fischlin-blind-sign-spec-v1.md`、`fischlin-technical-spec` 系列文档一致，可以分为三方：

- `Issuer`：签发者，持有签发私钥 `sk_sig`；
- `Holder`：持证者，负责生成请求、接收盲签结果、完成去盲与展示证明；
- `Verifier`：验证者，只验证最终展示对象，不接触内部签名 `sigma_com`。

这种三方划分在测试用例 `poseidon2_roles_interaction.c` 中也有非常清楚的工程映射。

### 4.2 关键对象

结合 `show_poseidon2_v1.h`、`protocol_poseidon2_v1.h` 和相关测试，当前仓库中的关键对象可整理如下。

#### 1. 承诺请求对象

```text
com = Commit(m; r)
```

其中：

- `m` 为消息；
- `r` 为承诺随机性；
- `com` 为提交给签发者的承诺值。

### 4.3 内部凭证对象

Holder 侧内部私有凭证在代码中对应 `spx_p2_cred_v1_internal`，其内容包括：

- `m`
- `r`
- `omega2`
- `com`
- `sigma_com`
- `trace`

对应结构见 `show_poseidon2_v1.h`：

```c
typedef struct
{
    uint8_t m[SPX_BYTES];
    size_t mlen;
    uint8_t r[SPX_BYTES];
    size_t rlen;
    uint8_t omega2[SPX_N];
    size_t omega2_len;
    uint8_t com[SPX_N];
    uint8_t sigma_com[SPX_BYTES];
    spx_p2_trace trace;
} spx_p2_cred_v1_internal;
```

这表明当前 strict 路径并不是只依赖 `sigma_com`，而是要求 Holder 侧保留完整见证材料，以支持后续的 public-statement 绑定与 STARK 证明生成。

### 4.4 外部展示对象

当前对外展示对象对应 `spx_p2_show_v1`，其关键字段为：

- `sigma_C`
- `com`
- `m_pub`
- 展示证明字段
- `public_ctx`

对应结构为：

```c
typedef struct
{
    uint8_t sigma_C[SPX_P2_SIGMA_C_MAX_BYTES];
    size_t sigma_C_len;
    uint8_t com[SPX_N];
    uint8_t m_pub[SPX_BYTES];
    size_t m_pub_len;
    uint8_t pi_f[SPX_P2_SHOW_PI_F_MAX_BYTES];
    size_t pi_f_len;
    uint8_t public_ctx[SPX_P2_PUBLIC_CTX_MAX];
    size_t public_ctx_len;
} spx_p2_show_v1;
```

这里需要特别注意三点：

1. 外部对象中没有 `sigma_com` 明文字段；
2. 结构体中的 `pi_f` 字段在语义上表示最终展示证明对象；
3. `m_pub` 和 `public_ctx` 被视为显式公开输入的一部分。

因此，本仓库的最终展示对象更接近：

```text
Sigma = (sigma_C, m_pub, public_ctx, show_proof)
```

它不是最朴素的“拿到签名后直接公开签名”，而是一个展示证明对象。

## 5. 协议流程的工程映射

### 5.1 Issue-Request：Holder 生成承诺

在 `protocol_poseidon2_v1.c` 中，Holder 侧请求接口为：

```c
int spx_p2_issue_request_v1(uint8_t out_com[SPX_N],
                            const uint8_t *m, size_t mlen,
                            const uint8_t *r, size_t rlen)
```

其本质是：

```text
com = Commit(m; r)
```

调用底层承诺函数 `spx_p2_commit()` 完成。也就是说，Holder 提交给 Issuer 的不是明文消息，而是承诺值 `com`。

### 5.2 Issue-Sign：Issuer 对承诺签发

Issuer 侧签发接口为：

```c
int spx_p2_issue_sign_v1(uint8_t out_sigma_blind[SPX_BYTES], size_t *out_sigma_blind_len,
                         const uint8_t *issuer_sk,
                         const uint8_t com[SPX_N])
```

其实现直接对 `com` 进行签名：

```text
sigma_blind = Sign_sk(com)
```

在当前仓库中，这一步底层调用的是现有 `SPHINCS+-like` 签名 API，因此 Issuer 的任务是“对承诺签发”，而不是直接对消息签发。

### 5.3 Unblind：Holder 组织内部凭证

去盲接口为：

```c
int spx_p2_unblind_v1(spx_p2_cred_internal *out_cred,
                      const uint8_t com[SPX_N],
                      const uint8_t sigma_blind[SPX_BYTES], size_t sigma_blind_len,
                      const uint8_t *omega2, size_t omega2_len)
```

从当前实现看，这一步的主要作用是：

- 把 `com`、`sigma_com`、`omega2` 收入内部凭证；
- 形成后续 `ShowProve` 需要的 witness 容器。

需要注意：从严格密码学角度说，当前 `unblind` 并不是文献里最复杂的去盲变换，而是工程化地把 Issuer 返回的签名结果与 Holder 私有见证组装成后续可证明对象。这也是后文需要保守表述的重要原因之一。

### 5.4 Issue-Unblind 一体化包装

仓库还提供了便利接口：

```c
int spx_p2_issue_unblind_v1(...)
```

它自动串联：

1. `IssueRequest`
2. `IssueSign`
3. `Unblind`

并在调用方不提供 `omega2` 时自动采样 `omega2`。这使得测试和演示链能够直接以“完整签发闭环”方式运行。

### 5.5 ShowProve：Holder 生成展示对象

当前对外默认 `show_prove` 已冻结到 strict 路径：

```c
int spx_p2_show_prove(...)
{
    return spx_p2_show_prove_v2_strict(...);
}
```

而默认 strict prove 入口又会路由到最终 statement-bound 语义，即在验证语句中显式纳入 `m_pub`、`public_ctx` 和独立的 `pk_E` 绑定。

这说明当前仓库最终默认口径已经不是早期过渡对象，而是：

- 使用 strict public-statement 路径；
- 要求显式 witness `m / r / omega2`；
- 生成最终展示证明对象。

### 5.6 ShowVerify：Verifier 验证展示对象

当前默认验证接口也冻结到 strict 路径：

```c
int spx_p2_show_verify(...)
{
    return spx_p2_show_verify_v2_strict(...);
}
```

其默认要求 `show` 中携带 `m_pub`，并在验证阶段显式把 `m_pub` 纳入最终 public statement。

这意味着最终验证语句不再是“只看 `pk + com + pi`”，而是显式把 `m_pub` 纳入 public statement。

## 6. strict public-statement 路径的语句与见证

### 6.1 FFI 层 public input 与 witness 结构

`stark/ffi_v1.h` 中定义了 strict 路径的 public input 与 witness：

```c
typedef struct
{
    const uint8_t *pk;
    const uint8_t *pk_e;
    size_t pk_e_len;
    const uint8_t *com;
    const uint8_t *m_pub;
    size_t m_pub_len;
    const uint8_t *public_ctx;
    size_t public_ctx_len;
    const uint8_t *sigma_c;
    size_t sigma_c_len;
} spx_p2_ffi_public_inputs_v1;
```

```c
typedef struct
{
    const uint8_t *sigma_com;
    const uint8_t *m;
    size_t mlen;
    const uint8_t *r;
    size_t rlen;
    const uint8_t *omega2;
    size_t omega2_len;
} spx_p2_ffi_private_witness_v1;
```

因此，本仓库当前 strict 路径的公开输入和见证可概括为：

- 公开输入：`(pk_sig, pk_E, com, m_pub, public_ctx, sigma_C)`
- 见证：`(sigma_com, m, r, omega2)`

### 6.2 当前最终公开语句的仓库口径

结合 `protocol_poseidon2_v1.c` 与 `show_poseidon2_v1.c`，当前仓库更适合写成以下“工程冻结口径”：

```text
x = (pk_sig, pk_E, m_pub, ctx_pub, sigma_C)
w = (m, r, omega2, com, sigma_com)
```

需要证明或检查的核心关系包括：

1. `com = Commit(m; r)`
2. `Verify(pk_sig, com, sigma_com) = 1`
3. `sigma_C` 与 `(pk_E, com, sigma_com, omega2)` 满足仓库当前定义的构造关系
4. `public_ctx`、`m_pub`、`sigma_C` 参与最终 statement digest / verify 绑定

这已经明显接近 Fischlin 框架的语义，但又保留了仓库自己的工程对象形式，因此论文中应写成“基于 Fischlin 框架的方案实现”，而不宜写成“标准形式下的逐项等价复现”。

### 6.3 为什么 verify 端要求显式 `m_pub`

`protocol_poseidon2_v1.c` 中明确收紧了 verify 语义：

- 当 `show` 携带 `m_pub` 时，通用 `verify_v1` 不再隐式接受；
- 调用方必须改走显式 statement-bound 验证入口；
- 这样最终公开语句才能收敛到显式 `x = (pk_sig, pk_E, m_pub, ctx_pub, sigma_C)`。

这是一项很重要的设计决策，因为它意味着：

- `m_pub` 不是可有可无的 UI 字段；
- 它确实被提升为验证语句的一部分；
- `ShowVerify` 的接受/拒绝结果依赖它，而不是仅依赖 `show` 对象内部缓存。

## 7. `sigma_C` 与展示证明对象的设计作用

### 7.1 `sigma_C` 的作用

在本仓库中，`sigma_C` 是最终展示对象中的核心公开字段之一。它并不是早期简单的 `com` 复制，而是在 strict 路径中由 witness 重新构造：

- 加密键绑定路径会通过内部 helper 生成；
- statement-bound 路径也会通过对应的内部 helper 生成。

从 `show_poseidon2_v1.c` 可见，最终 statement-bound prove 路径会：

1. 先根据 witness 构造 `sigma_C`；
2. 再把 `sigma_C` 与 `m_pub/public_ctx/pk_E` 等一起送入 FFI 证明；
3. verify 端则要求 `sigma_C` 的前缀与 `com` 一致，并使用其完整值参与验证。

因此，`sigma_C` 在仓库里承担的是“外部公开对象中的承载字段”，对应你可以在论文中理解为 Fischlin 框架里外部展示对象 `C` 的工程化载体。

### 7.2 展示证明对象的作用

最终展示证明对象是 strict 路径下的证明格式。结合 `thesis-notes-stark-v2.md` 和 `project-final-summary-v1.md`，当前仓库对该对象的冻结口径包括：

- final proof 格式已经固定；
- 外部对象中不再泄露 `sigma_com`；
- verify 侧会检查头字段、系统 ID、statement version 等信息；
- 默认 final 接口均走该展示证明对象对应的 strict prove/verify 路径。

因此，在第四章写作中可以把它解释为：

- Fischlin 框架中“存在性证明”的工程实现载体；
- 仓库当前 final 版本的证明对象；
- 连接 C 侧 show 接口与 Rust STARK 后端的统一 proof 格式。

## 8. 本仓库中真正完成的协议主链

### 8.1 已打通的完整闭环

根据 `poseidon2_roles_interaction.c`、`poseidon2_fischlin_blind_e2e.c` 和 `project-final-summary-v1.md`，当前仓库已经完成并可复现的工程闭环是：

```text
Commit -> Issue -> Unblind -> ShowProve -> ShowVerify
```

其中：

- `roles_interaction` 测试从三角色视角演示整条 final 演示链；
- `fischlin_blind_e2e` 测试验证不同 `public_ctx` 下 show 对象可区分，并检查 tamper 会被拒绝；
- `protocol_flow_statement_bound` 与 `fischlin_spec_flow_v1` 测试进一步检查 `m_pub/pk_E/public_ctx` 的严格 public-statement 语义。

### 8.2 已实现的关键绑定关系

从 strict 路径与测试来看，当前仓库已经实现并显式校验了以下几类绑定：

1. **承诺打开关系绑定**
   - `m`、`r` 与 `com` 的一致性被 prove 输入或 witness precheck 检查；
   - 错 `m`、错 `r` 会导致 strict 路径拒绝。

2. **签名验证关系绑定**
   - `pk_sig`、`com`、`sigma_com` 之间的关系被检查；
   - 错 `pk_sig`、错 `sigma_com` 会触发拒绝。

3. **公开语句绑定**
   - `m_pub`、`public_ctx`、`pk_E`、`sigma_C` 都参与 strict verify；
   - 错 `m_pub`、错 `public_ctx`、错 `pk_E`、错 `sigma_C` 都会被拒绝。

4. **proof / statement digest 绑定**
   - 展示证明对象不是外壳；
   - 篡改 statement version、public input digest、proof bytes 会被检测。

### 8.3 已有负例覆盖

结合 `poseidon2_stark_strict_core_enforcement.c`、`poseidon2_statement_binding.c`、`poseidon2_trace_replay_binding.c` 和 `TESTING.md`，当前仓库至少覆盖了以下关键 tamper 项：

- `m_pub`
- `m`
- `r`
- `pk_sig`
- `sigma_com`
- `pk_E`
- `omega2`
- `sigma_C`
- `public_ctx`
- 缺失 `m_pub`
- 缺失 `omega2`

这为论文第四章中的“正确性与拒绝性验证”提供了较强的工程证据。

## 9. STARK 在本方案中的定位

### 9.1 STARK 不是外加展示，而是 strict 路径核心组成

当前仓库中，默认 final `show_prove/show_verify` 已经接到 strict STARK 路径上，而不是把 STARK 当作可选附属模块。因此在论文中可以写：

- `ShowProve` 阶段由 Holder 生成展示证明对象；
- `ShowVerify` 阶段由 Verifier 验证展示证明对象与 public statement；
- Rust STARK 后端已经是 final strict 路径的默认证明后端。

### 9.2 但 STARK 的成果应保守表述

尽管 strict prove/verify 主链已经打通，但从 `最终版方案.md`、`fischlin-stark-full-gap-and-milestone-v1.md` 以及项目总结文档看，论文中仍应保守表述为：

- 已实现“部分关键关系的 STARK 约束增强”；
- 已完成 strict prove/verify 主链；
- 已实现 statement binding、ctx binding、commitment binding 等关键闭环；
- 尚不应声称“Fischlin 三关系已完整统一内生化到单一 AIR 中”。

这一区分非常重要，因为它关系到第四章成果定位是否过界。

## 10. 可声明成果与不宜声明的内容

### 10.1 可以稳定声明的成果

结合 `最终版方案.md` 与 `project-final-summary-v1.md`，当前最稳妥的成果表述是：

- 本文实现了一个基于 Fischlin 框架的、可完整运行的后量子盲签原型系统。
- 本文在 `Poseidon2` 替换底层哈希的 `SPHINCS+-like` 结构上，实现了 `Commit -> Issue -> Unblind -> Show -> Verify` 的完整流程。
- 本文设计并实现了 strict public-statement 路径，使 `m_pub / pk_E / public_ctx / sigma_C` 显式参与展示验证。
- 本文接入真实 Rust STARK 后端，实现了最终展示证明对象的生成与验证，并对多类关键篡改给出拒绝验证结果。

### 10.2 不宜直接声明的内容

以下表述在当前仓库口径下风险较高，不建议直接写入论文主结论：

- “本文完整实现了标准 Fischlin 盲签方案。”
- “本文完成了 Fischlin 三关系的完整 STARK 内生化。”
- “本文已给出完整形式化安全归约并达成终态证明系统实现。”
- “本文实现与标准文献构造逐项严格等价。”

原因主要有三点：

1. 当前 `unblind` 更偏工程化 witness 组织，而不是完整文献式去盲构造；
2. `sigma_C`、展示证明对象、strict public-statement 是仓库的工程化对象设计；
3. STARK 路径虽然已打通，但仓库文档明确建议将其表述为“部分关系约束增强”，而非完整终态内生证明系统。

## 11. 第四章可直接采用的写作口径

### 11.1 方案定义

可在第四章正文中将本方案定义为：

> 本文在 Poseidon2 替换底层哈希的 SPHINCS+-like 签名结构上，引入 Fischlin 风格的盲签框架。具体地，Holder 首先对消息进行承诺并向 Issuer 请求签发，Issuer 对承诺值签名，随后 Holder 基于内部 witness 构造展示证明对象，Verifier 则基于公开语句和零知识证明对该展示对象进行验证。

### 11.2 工程落地描述

可进一步写成：

> 在工程实现上，本文将协议流程组织为 `Commit -> Issue -> Unblind -> ShowProve -> ShowVerify` 五个阶段，并将最终对外展示对象设计为包含 `sigma_C`、`m_pub`、`public_ctx` 与展示证明字段的结构。其中，`sigma_com` 仅保留在 Holder 私有 witness 中，不作为外部展示对象字段公开。

### 11.3 STARK 定位描述

建议写成：

> 为增强展示阶段的可验证性，本文进一步引入 strict STARK 证明链，对公开语句与私有见证之间的关键一致性关系进行约束和验证。当前实现已完成 strict prove/verify 主链与多类篡改拒绝测试，但仍将“全部密码学关系完全内生化到统一 AIR 中”保留为后续工作。

### 11.4 成果表述

建议最终结论使用如下风格：

> 综上，本文完成了一个基于 Fischlin 框架的 SPHINCS+-like 后量子盲签原型系统，实现了从承诺签发到展示验证的完整运行链路，并结合 Poseidon2 与 STARK 机制完成了工程级的验证增强。

## 12. 与第三章的衔接关系

第三章重点说明的是：

- Poseidon2 如何替换 SPHINCS+ 底层哈希；
- 为什么需要重新做参数搜索与性能/证明规模评估。

第四章则建立在第三章之上，说明：

- 第三章得到的 `Poseidon2-SPHINCS+-like` 签发原语，如何进一步嵌入 Fischlin 框架；
- 如何从“对承诺的签名”过渡到“面向验证者的展示证明对象”；
- 为什么需要在该阶段接入 strict public-statement 与 STARK 证明链。

因此，第三章与第四章的关系可以概括为：

```text
第三章解决“底层签名原语替换与参数选择”
第四章解决“基于该原语构造盲签协议与展示验证系统”
```

## 13. 建议在第四章中引用的仓库依据

建议引用以下实现和文档作为第四章写作依据：

- `ref/show/protocol_poseidon2.h`
- `ref/show/protocol_poseidon2_v1.h`
- `ref/show/protocol_poseidon2_v1.c`
- `ref/show/show_poseidon2.h`
- `ref/show/show_poseidon2.c`
- `ref/show/show_poseidon2_v1.h`
- `ref/show/show_poseidon2_v1.c`
- `ref/stark/ffi_v1.h`
- `ref/test/poseidon2_roles_interaction.c`
- `ref/test/poseidon2_fischlin_blind_e2e.c`
- `ref/test/poseidon2_fischlin_spec_flow_v1.c`
- `ref/test/poseidon2_stark_strict_core_enforcement.c`
- `ref/final-results-v1/core-experiments/project-final-summary-v1.md`
- `ref/final-results-v1/core-experiments/thesis-notes-stark-v2.md`
- `ref/logs/fischlin-upgrade-v1/最终版方案.md`
- `ref/logs/fischlin-upgrade-v1/fischlin-stark-full-gap-and-milestone-v1.md`
- `ref/logs/fischlin-blind-sign-spec-v1.md`

## 14. 后续可补写内容

如果后续还需要继续完善第四章，建议补充以下材料：

- 三角色交互时序图；
- `Show_v1 -> Show_v2 -> final show proof` 的对象演化图；
- strict public-statement 的“公开输入/私有见证”表格；
- 正例/负例测试矩阵表；
- “已完成 / 保守声明 / 未来工作”三栏对照表。

这些内容都已经能从当前仓库中继续提取并组织成论文图表。
