# 第三章：Poseidon2 替换 SPHINCS+ 底层哈希与参数选择总结

## 1. 文档目的

本文档面向论文第三章写作，结合本仓库当前实现与参数重搜实验，整理两部分内容：

1. 用 Poseidon2 适配 SPHINCS+ 底层哈希接口 `PRF_msg`、`H_msg`、`prf_addr`、`thash` 的具体设计。
2. 对应本仓库参数重搜实验的实现细节、筛选流程、评价指标与最终推荐参数。

需要说明的是，以下内容以本仓库 `ref/` 目录中的实际代码和实验脚本为准，因此其表述重点是“工程实现口径”和“可复现实验口径”。其中参数筛选中的安全过滤阶段明确采用仓库自定义的 `proxy-v1` 口径，它是可复现的工程过滤规则，不应在论文中表述为对标准安全证明的直接替代。

## 2. 设计目标与总体思路

SPHINCS+ 原始方案依赖底层哈希原语完成以下几类任务：

- 通过地址相关 PRF 生成 WOTS/FORS 等节点所需的伪随机值；
- 通过消息随机化机制生成签名随机值 `R`；
- 通过 `H_msg` 将消息映射到 FORS 摘要、子树索引和叶子索引；
- 通过 `thash` 实现 `F / H / T_l` 等树上压缩哈希。

本仓库的 Poseidon2 替换方案并没有改动 SPHINCS+ 的上层结构，也没有改动地址编码、密钥布局和签名流程的语义，而是遵循以下原则：

- 保留原 SPHINCS+ 的输入拼接结构；
- 保留 `ADRS` 的 32 字节编码方式；
- 保留 `pub_seed`、`sk_seed`、`sk_prf`、`optrand` 等参与关系；
- 用显式域分离标签替代“同一哈希函数复用多个语义接口”的歧义风险；
- 用 Poseidon2 海绵吸收-压缩流程替换原始底层 SHAKE/SHA2 风格接口。

因此，这一替换是“底层哈希后端的替换”，而不是“签名结构的重设计”。

### 2.1 为何不能直接沿用原 SPHINCS+ 参数

在论文表述中，需要特别说明：虽然本仓库保留了 SPHINCS+ 的总体结构，但在底层哈希从 SHA2/SHAKE 类原语切换为 Poseidon2 之后，不能简单地把原 SPHINCS+ 参数直接照搬过来，原因主要有以下几类。

#### 2.1.1 底层成本模型已经发生变化

原 SPHINCS+ 参数设计主要面向传统 CPU 上的哈希开销与经典实现效率，而本仓库的目标不仅是“能完成签名”，还要兼顾 Poseidon2 在零知识证明中的约束规模、trace 长度和证明时间。因此，新的成本函数不再只是：

- 公钥大小；
- 签名大小；
- 签名/验证时间。

而是同时包含：

- `witness_rows`
- `trace_calls`
- `trace_lanes`
- `prove_e2e_ms`
- `stark_verify_ms`

也就是说，原参数可能在传统哈希后端下是合适的，但在 Poseidon2 + STARK 场景下未必仍然是优选。


#### 2.1.2 Poseidon2 的安全与性能权衡口径不同于原始哈希

原 SPHINCS+ 参数集的许多权衡，隐含依赖于原始哈希原语的输出长度、安全预期与性能特征。替换为 Poseidon2 后，虽然上层结构仍是 SPHINCS+，但底层具体权衡已经发生变化：

- 同样的 `n` 会对应不同的哈希实现成本；
- 不同的 `k`、`a` 会改变 FORS 部分规模，也会改变 STARK 约束成本；
- `w`、`d` 等参数对普通签名耗时和证明规模的影响，不再完全沿用原哈希后端下的直觉。

因此，本仓库需要重新枚举候选、重算尺寸、重新 benchmark，并结合新的后端成本模型给出结论。

#### 2.1.3 本仓库目标是“面向零知识友好后端的工程再平衡”

本工作不是简单证明“Poseidon2 也能跑 SPHINCS+”，而是要支撑后续 STARK/trace 分析、协议适配和证明生成。因此参数选择目标天然比原始方案更多维：

1. 结构合法；
2. 代理安全可接受；
3. 普通签名和验证可运行；
4. Poseidon2 调用轨迹可记录；
5. witness 行数和证明时间处于可接受范围。

在这个意义上，参数重搜不是附属实验，而是 Poseidon2 替换落地到零知识友好实现时的必要步骤。

## 3. Poseidon2 后端实现概览

### 3.1 参数轮廓

本仓库中的 Poseidon2 后端在 `poseidon2.h` 中定义了如下固定配置：

- 有限域：64 位 Goldilocks 域；
- 状态宽度：`t = 12`；
- 容量字数：`capacity = 6`；
- 速率字数：`rate = 6`；
- 全轮数：`R_F = 8`；
- 部分轮数：`R_P = 22`。

对应宏如下：

```c
#define SPX_POSEIDON2_FIELD_BITS 64
#define SPX_POSEIDON2_T 12
#define SPX_POSEIDON2_CAPACITY_WORDS 6
#define SPX_POSEIDON2_RATE_WORDS (SPX_POSEIDON2_T - SPX_POSEIDON2_CAPACITY_WORDS)
#define SPX_POSEIDON2_RATE_BYTES (SPX_POSEIDON2_RATE_WORDS * sizeof(uint64_t))
#define SPX_POSEIDON2_RF 8
#define SPX_POSEIDON2_RP 22
```

### 3.2 海绵接口与域分离

仓库实现采用增量海绵接口：

- `poseidon2_inc_init()`
- `poseidon2_inc_absorb()`
- `poseidon2_inc_finalize()`
- `poseidon2_inc_squeeze()`

其关键特点有三点：

1. 初始化时首先吸收 1 字节域标签；
2. 消息按字节流吸收，底层再按 64 位 lane 映射到 Goldilocks 域元素；
3. 结束时使用 `pad10*1` 填充，然后开始 squeeze。

核心逻辑如下：

```c
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx,
                        spx_poseidon2_domain domain_tag)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->domain_tag = (uint8_t)domain_tag;
    poseidon2_inc_absorb(ctx, &ctx->domain_tag, 1);
}
```

```c
void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx)
{
    ctx->absorb_buf[ctx->absorb_pos] ^= 0x01u;
    ctx->absorb_buf[SPX_POSEIDON2_RATE_BYTES - 1] ^= 0x80u;
    p2_absorb_block(ctx, ctx->absorb_buf);
}
```

这意味着仓库中的域分离不是依赖人工字符串前缀，而是由独立枚举值在海绵起始处直接注入状态。与第三章写作最相关的域标签为：

```c
SPX_P2_DOMAIN_PRF_ADDR = 0x01
SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM = 0x02
SPX_P2_DOMAIN_HASH_MESSAGE = 0x03
SPX_P2_DOMAIN_THASH_F = 0x11
SPX_P2_DOMAIN_THASH_H = 0x12
SPX_P2_DOMAIN_THASH_TL = 0x13
```

因此，本方案在统一使用 Poseidon2 的前提下，仍然保留了 `prf_addr`、`PRF_msg`、`H_msg`、`F/H/T_l` 之间的语义隔离。

## 4. 四类底层接口的 Poseidon2 适配设计

### 4.1 `prf_addr` 的适配

#### 4.1.1 仓库实现

`hash_poseidon2.c` 中的实现如下：

```c
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[SPX_P2_ENCODED_PRF_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    poseidon2_hash_bytes_domain(out, SPX_N, SPX_P2_DOMAIN_PRF_ADDR,
                                buf, sizeof(buf));
}
```

仓库同时在 `poseidon2.h` 中将其编码长度固定为：

```c
#define SPX_P2_ENCODED_PRF_ADDR_BYTES (2 * SPX_N + SPX_ADDR_BYTES)
```

#### 4.1.2 论文中可表述的设计

可将 `prf_addr` 的 Poseidon2 化定义写成：

```text
prf_addr_P2(pub_seed, ADRS, sk_seed)
  = Poseidon2_domain(PRF_ADDR, pub_seed || ADRS || sk_seed)
```

其中：

- `pub_seed` 仍然承担公开域参数/实例分离作用；
- `ADRS` 仍然承担节点定位和功能区分作用；
- `sk_seed` 仍然承担私钥化、密钥化输入作用。

#### 4.1.3 `ADRS` 与 `public seed` 如何保留

这一接口最能体现“替换底层哈希而不改变 SPHINCS+ 寻址机制”的原则：

- `ADRS` 没有被删除，也没有简化成高层标签，而是仍以原始 `32` 字节输入参与哈希；
- `pub_seed` 仍然被放在输入最前部，因此不同公参实例下同一地址不会得到相同输出；
- `sk_seed` 仍保留在末端，使该接口保持 PRF 的“密钥化”语义。

从而，Poseidon2 替换后保留了原先“公开实例参数 + 结构地址 + 私有种子”的三元绑定关系。

### 4.2 `PRF_msg` / `gen_message_random` 的适配

#### 4.2.1 仓库实现

仓库中与 `PRF_msg` 对应的函数名为 `gen_message_random()`：

```c
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    spx_poseidon2_inc_ctx p2ctx;
    (void)ctx;

    poseidon2_inc_init(&p2ctx, SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM);
    poseidon2_inc_absorb(&p2ctx, sk_prf, SPX_N);
    poseidon2_inc_absorb(&p2ctx, optrand, SPX_N);
    poseidon2_inc_absorb(&p2ctx, m, (size_t)mlen);
    poseidon2_inc_finalize(&p2ctx);
    poseidon2_inc_squeeze(R, SPX_N, &p2ctx);
}
```

#### 4.2.2 论文中可表述的设计

其定义可写为：

```text
PRF_msg_P2(sk_prf, optrand, M)
  = Poseidon2_domain(GEN_MESSAGE_RANDOM, sk_prf || optrand || M)
```

输出为 `R`，长度为 `SPX_N` 字节。

#### 4.2.3 keying/randomization 如何保留

该接口中，原 SPHINCS+ 的“密钥化 + 随机化”机制被完整保留：

- `sk_prf` 仍是私有密钥输入，承担 message-dependent randomness 的密钥化来源；
- `optrand` 仍是外部随机化项，用于减弱消息重复、侧信道和确定性签名带来的风险；
- `M` 仍直接进入哈希，保证 `R` 与消息绑定。

因此，Poseidon2 替换后 `R` 的语义没有变化，只是底层从 SHAKE/SHA2 风格 XOF 变成了 Poseidon2 海绵。

### 4.3 `H_msg` / `hash_message` 的适配

#### 4.3.1 仓库实现

对应实现如下：

```c
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    spx_poseidon2_inc_ctx p2ctx;

    poseidon2_inc_init(&p2ctx, SPX_P2_DOMAIN_HASH_MESSAGE);
    poseidon2_inc_absorb(&p2ctx, R, SPX_N);
    poseidon2_inc_absorb(&p2ctx, pk, SPX_PK_BYTES);
    poseidon2_inc_absorb(&p2ctx, m, (size_t)mlen);
    poseidon2_inc_finalize(&p2ctx);
    poseidon2_inc_squeeze(buf, SPX_DGST_BYTES, &p2ctx);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

    if (SPX_D == 1) {
        *tree = 0;
    } else {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
```

#### 4.3.2 论文中可表述的设计

其高层定义可写为：

```text
H_msg_P2(R, PK, M)
  = Poseidon2_domain(HASH_MESSAGE, R || PK || M)
```

随后将输出流切分为三部分：

- `digest`：供 FORS 使用的消息摘要；
- `tree`：高层子树索引；
- `leaf_idx`：当前子树中的叶子索引。

#### 4.3.3 语义保持分析

这里被保留的机制主要有两层：

1. **随机绑定保留**
   - 输入最前端仍为 `R`，因此 `H_msg` 仍继承消息随机化阶段的结果。

2. **公钥绑定保留**
   - 输入中仍包含完整 `pk`，因此摘要不仅依赖消息，还依赖签名公钥实例。

3. **SPHINCS+ 输出切分语义保留**
   - 输出并不是简单作为一个哈希值使用，而是继续按照 SPHINCS+ 规范切成 `digest/tree/leaf_idx` 三部分；
   - 仓库中仍保留树索引与叶索引的位掩码处理逻辑。

#### 4.3.4 当前实现边界

仓库当前实现显式限制：

- `tree_bits <= 64`
- `leaf_bits <= 32`

这既体现在 `hash_message()` 中，也被参数重搜脚本当作结构合法性条件使用。因此论文中可以表述为：本实现采用 `uint64_t` 保存子树索引、`uint32_t` 保存叶索引，所以参数空间搜索需要满足相应实现边界。

### 4.4 `thash` 的适配

#### 4.4.1 仓库实现

实现位于 `thash_poseidon2_simple.c`：

```c
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, SPX_P2_ENCODED_THASH_BYTES(inblocks));

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, inblocks * SPX_N);

    poseidon2_hash_thash_by_inblocks(out, SPX_N,
                                     buf, SPX_P2_ENCODED_THASH_BYTES(inblocks),
                                     inblocks);
}
```

其编码长度宏定义为：

```c
#define SPX_P2_ENCODED_THASH_BYTES(inblocks) \
    (SPX_N + SPX_ADDR_BYTES + (inblocks) * SPX_N)
```

同时，`poseidon2_hash_thash_by_inblocks()` 用 `inblocks` 决定语义域：

- `1 block -> F`
- `2 blocks -> H`
- `>=3 blocks -> T_l`

#### 4.4.2 论文中可表述的设计

因此可写成：

```text
THASH_P2(pub_seed, ADRS, X_1, ..., X_inblocks)
  = Poseidon2_domain(THASH_semantic(inblocks),
      pub_seed || ADRS || X_1 || ... || X_inblocks)
```

其中：

- 当 `inblocks = 1` 时，对应 `F`；
- 当 `inblocks = 2` 时，对应 `H`；
- 当 `inblocks >= 3` 时，对应 `T_l`。

#### 4.4.3 `ADRS` 和 `public seed` 如何保留

`thash` 替换后仍然保留了 SPHINCS+ 最关键的两类命名空间：

- `pub_seed` 提供跨实例隔离；
- `ADRS` 提供节点位置、层级和用途的绑定。

因此，尽管底层不再是原始哈希函数，树上节点压缩仍然是“带地址上下文”的哈希，而不是对裸输入块做普通压缩。

## 5. `ADRS`、`public seed`、keying、randomization 的整体保留方式

### 5.1 `ADRS` 的保留

本仓库没有改动 SPHINCS+ 地址结构。`address.h` 和 `address.c` 仍然保留了 8 个 32 位字的地址表示，以及原有字段操作函数：

- `set_layer_addr()`
- `set_tree_addr()`
- `set_type()`
- `set_keypair_addr()`
- `set_chain_addr()`
- `set_hash_addr()`
- `set_tree_height()`
- `set_tree_index()`

地址类型也保持不变：

- `SPX_ADDR_TYPE_WOTS`
- `SPX_ADDR_TYPE_WOTSPK`
- `SPX_ADDR_TYPE_HASHTREE`
- `SPX_ADDR_TYPE_FORSTREE`
- `SPX_ADDR_TYPE_FORSPK`
- `SPX_ADDR_TYPE_WOTSPRF`
- `SPX_ADDR_TYPE_FORSPRF`

因此，Poseidon2 方案没有改变 SPHINCS+ 的寻址体系，而只是把这些地址字段继续作为哈希输入的一部分。

### 5.2 `public seed` 的保留

`spx_ctx` 结构仍然保留：

```c
typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[SPX_N];
} spx_ctx;
```

在本仓库中：

- `prf_addr` 使用 `pub_seed || ADRS || sk_seed`；
- `thash` 使用 `pub_seed || ADRS || in`。

因此 `pub_seed` 仍然是整个哈希命名空间和实例分离的重要组成部分，并没有因为改用 Poseidon2 而失去作用。

### 5.3 keying 的保留

本仓库中不同接口的 keying 机制分别由以下私有输入承担：

- `prf_addr`：`sk_seed`
- `PRF_msg`：`sk_prf`
- `H_msg`：不直接私钥化，但通过 `R` 和 `pk` 绑定签名上下文

这说明 Poseidon2 替换后并未把所有底层函数改成“无密钥普通哈希”，而是继续沿用 SPHINCS+ 各接口原有的密钥化边界。

### 5.4 randomization 的保留

随机化主要体现在 `PRF_msg / gen_message_random` 阶段：

- `optrand` 仍然保留；
- 其输出 `R` 继续作为 `H_msg` 的前缀输入；
- 所以消息随机化对后续 FORS 摘要和树索引选择仍然产生影响。

换言之，本方案保留的是“先随机生成 `R`，再由 `R` 参与消息摘要”的两阶段机制，而不是将随机化简化为额外盐值或完全删除。

## 6. 工程实现细节

### 6.1 字节到域元素的映射

Poseidon2 后端采用 little-endian 方式把字节流打包为 64 位 lane，再映射到 Goldilocks 域元素。其辅助函数包括：

- `p2_load_lane_le()`
- `p2_store_lane_le()`

在适配 STARK/trace 的辅助代码中，仓库也显式提供了：

```c
int spx_p2_encode_bytes_to_lanes(uint64_t *out_lanes, size_t *out_count,
                                 const uint8_t *in_bytes, size_t in_len)
```

这说明本实现既服务于签名后端，也兼顾了后续零知识证明中对 Poseidon2 调用轨迹的记录和约束分析。

### 6.2 Poseidon2 的轮函数实现

`poseidon2.c` 中实现了：

- Goldilocks 域加法、乘法；
- `x^7` S-box；
- 外部混合层 `p2_mix_external()`；
- 内部混合层 `p2_mix_internal()`；
- `poseidon2_permute()`。

排列执行顺序为：

1. 前半段全轮；
2. 中间部分轮；
3. 后半段全轮。

因此仓库当前并不是“用 SHAKE 包一层 Poseidon2 名字”，而是已经有独立的 Poseidon2 排列后端实现。

### 6.3 `thash` 的语义路由

仓库没有为 `F`、`H`、`T_l` 写三套完全不同的树哈希实现，而是采取：

- 统一输入编码 `pub_seed || ADRS || in`
- 再根据 `inblocks` 选择不同域标签

这种设计的优点是：

- 编码逻辑统一；
- 语义域清晰；
- 更便于后续 trace、约束统计和 ZK 证明复用。

### 6.4 trace 与约束统计适配

`hash_poseidon2_adapter.c` 为每次 Poseidon2 调用记录：

- `domain_tag`
- 输入字节长度和输出字节长度
- `ADRS` 对应的 8 个 32 位字
- 输入 lane 数和输出 lane 数

这为后续 STARK 统计、证明电路抽象、调用次数与 witness 行数估计提供了统一接口，也说明本仓库的 Poseidon2 替换并不只是“能签名”，而是兼顾了零知识友好实现的后续分析需求。

### 6.5 设计决策理由

除了“怎么实现”，论文中还应补足“为什么这样实现”。本仓库当前的 Poseidon2 后端配置可以理解为：面向 SPHINCS+ 结构适配与 STARK 友好分析的一个固定工程基线。这里的“固定”强调的是可复现、可比较和易于约束，而不是声称它已经穷尽了所有可能配置中的全局最优。

### 6.6 为什么采用 Goldilocks 域

本仓库选择 64 位 Goldilocks 域，主要基于以下动机：

- 与当前实现中的 `uint64_t` lane 表示天然对齐，字节流到域元素的映射直接、实现简单；
- 便于在 C 端完成较高效的域运算与状态更新，不必引入更重的大整数实现；
- 更适合后续 STARK/trace 场景下的 witness 表达和约束组织；
- 当前仓库的 Poseidon2 profile 常量、对角矩阵和轮常量也已经围绕 Goldilocks 固定下来，便于整条链路保持一致。

从工程角度看，Goldilocks 域的意义在于：它把“底层哈希替换”和“后续零知识友好实现”统一到同一数域语境中，使签名后端与证明后端之间不需要额外的跨域转换层。

### 6.7 为什么选用固定的 `t=12, rate=6, capacity=6`

本仓库当前将状态宽度固定为 `t = 12`，并采用：

- `capacity = 6`
- `rate = 6`

这一本质上是一个“吞吐量与证明成本之间折中”的工程选择。

其动机可以概括为：

1. **要有足够的吸收速率**
   - `prf_addr`、`thash`、`H_msg` 的输入都不是极短固定常量，而是包含 `pub_seed`、`ADRS`、输入块甚至长消息；
   - 若 `rate` 过小，会显著增加吸收轮数与 trace 长度。

2. **又不能把状态做得过宽**
   - 在零知识证明视角下，状态宽度越大，每轮 witness 和约束负担通常也越大；
   - 因此不能单纯为了吞吐量一味增大 `t`。

3. **`rate = capacity = 6` 使实现和分析更规整**
   - 一半速率、一半容量的布局便于工程实现与调试；
   - 对不同接口使用统一海绵配置，便于 trace 复用、统计比较和脚本化 benchmark；
   - 不同底层接口共享同一状态结构，也减少了为单独场景维护多套 Poseidon2 参数的复杂度。

因此，这里采用的不是“针对某一个接口单点最优”的宽度设计，而是“服务于整套 SPHINCS+ 底层接口和后续 ZK 分析的统一固定配置”。

### 6.8 为什么选 `R_F = 8, R_P = 22`

本仓库在 `poseidon2.h` 中将轮数固定为：

- `R_F = 8`
- `R_P = 22`

并在 `poseidon2_params_goldilocks_profile.h` 中固化了对应的轮常量和对角常量。这样选择的理由主要有三层。

第一，这是当前仓库已经稳定接入、可重复 benchmark 的 profile。若在实验过程中频繁变动轮数，不仅普通签名耗时会变化，STARK witness 行数、trace 长度和最终 Pareto 结果也都会连带变化，导致参数重搜失去统一基线。

第二，固定轮数有利于把“参数重搜”和“后端 profile 选择”两个问题分开处理。当前仓库优先解决的是：

- 在一个固定 Poseidon2 profile 下，SPHINCS+ 参数该如何重搜；
- 在这个 profile 下，哪些候选在签名大小、签名时间和证明规模上更平衡。

如果在参数重搜时同时让 `R_F/R_P` 也浮动，会导致搜索空间膨胀，难以解释每个结果到底来自 SPHINCS+ 参数变化，还是来自 Poseidon2 内部 profile 变化。

第三，当前轮数组合已经与本仓库的实现、trace 记录、测试集和 benchmark 结果形成一致口径，因此在论文中更适合表述为“本实现采用的固定 Poseidon2 backend profile”，而不是声称这是脱离仓库上下文的普适最优解。

### 6.9 为什么 `thash` 要按 `inblocks` 做语义路由

`thash` 在 SPHINCS+ 中并不是单一语义，而是承载 `F`、`H`、`T_l` 等不同角色。仓库当前并没有为每个角色复制一套完全独立的输入编码逻辑，而是采取：

- 统一编码 `pub_seed || ADRS || in`
- 再由 `inblocks` 决定选择 `THASH_F / THASH_H / THASH_TL` 域标签

这样设计的原因主要有：

1. **保留 SPHINCS+ 语义差异**
   - `F`、`H`、`T_l` 虽然都属于树哈希，但并不应混为同一域；
   - 按 `inblocks` 路由可以自然对应这三类调用语义。

2. **减少实现重复**
   - 如果分别为三者写独立编码器，代码会更分散，也更容易在地址拼接或长度处理上出现不一致；
   - 统一编码更利于维护和审计。

3. **更利于 trace 和约束系统复用**
   - 对证明系统而言，统一输入布局可以减少解析分支；
   - 仅通过域标签和 `inblocks` 区分语义，更适合做模块化统计和规则检查。

4. **更贴合仓库的“统一后端 + 显式域分离”原则**
   - 这里的关键不是为每个接口造不同 Poseidon2，而是在统一 Poseidon2 backend 上通过域分离保留语义边界；
   - `thash` 的 `inblocks` 路由正是这一原则在树哈希接口上的具体体现。

### 6.10 为什么采用固定 profile，而不是为每个接口单独选 Poseidon2 配置

从理论上说，完全可以设想：

- 给 `prf_addr` 选一套 profile；
- 给 `H_msg` 选另一套 profile；
- 给 `thash` 再选第三套 profile。

但本仓库没有这么做，原因在于这种方式会显著增加：

- 代码复杂度；
- trace 解释复杂度；
- benchmark 对比难度；
- 参数重搜与论文表述难度。

当前采用固定 backend profile 的好处是：

- 所有底层接口共享同一域与同一置换结构；
- 所有测试、trace、约束估计和 benchmark 都建立在同一基线上；
- 参数搜索实验的结果更容易解释为“SPHINCS+ 参数变化造成的差异”，而不是“后端 profile 变化造成的差异”。

因此，本仓库在设计上优先选择“固定后端、变化 SPHINCS+ 参数”的实验策略，这也是第三章中更容易自洽叙述的技术路线。

## 7. 参数重搜实验的总体设计

本仓库的参数重搜实验主要由四个阶段组成，可在论文中概括为 `M2 -> M3 -> M4 -> M5` 流程。

### 7.1 M2：结构枚举与静态过滤

脚本：`scripts/search_params_poseidon2.py`

枚举轴为：

- `n`
- `h`
- `d`
- `k`
- `a`
- `w`
- `q`

对应候选元组为：

```text
(n, h, d, k, a, w, q)
```

其核心检查包括：

- `h % d == 0`
- `w` 必须受支持，当前仅允许 `16` 或 `256`
- `w` 必须是 2 的幂
- `tree_bits <= 64`
- `leaf_bits <= 32`

其中：

- `tree_height = h / d`
- `tree_bits = tree_height * (d - 1)`
- `leaf_bits = tree_height`

这些条件既体现了 SPHINCS+ 结构要求，也体现了本仓库 C 实现中 `hash_message()` 的索引位宽限制。

### 7.2 M2 中的派生指标

脚本还会为每个候选计算：

- `wots_len1`
- `wots_len2`
- `wots_len`
- `fors_msg_bits`
- `fors_msg_bytes`
- `hmsg_needed_bytes`
- `pk_bytes`
- `sk_bytes`
- `sig_bytes`

其中签名字节数的计算式为：

```text
sig_bytes
 = n
 + (a + 1) * k * n
 + d * wots_len * n
 + h * n
```

这对应：

- `R` 部分；
- FORS 签名部分；
- 每层 WOTS 签名部分；
- 每层认证路径部分。

因此，M2 的输出不仅是“合法/不合法”，也是后续多目标优化的尺寸基础。

### 7.3 M3：安全过滤

脚本：`scripts/eval_security_poseidon2.py`

这一阶段采用仓库定义的 `proxy-v1` 规则。它明确声明：

- 这是可复现的工程安全过滤；
- 不是标准证明意义下的严格安全界。

核心量包括：

- `hash_bits = 8 * n`
- `fors_bits = k * a`
- `comb_security_bits = min(hash_bits, fors_bits)`
- `poseidon2_security_bits = poseidon2_floor_bits`
- `budget_security_bits = comb_security_bits - budget_penalty_bits`
- `claimed_security_bits = min(comb, p2_floor, budget)`

其中预算惩罚与签名次数上界 `q` 相关：

- 当 `q <= q_reference` 时，不扣减；
- 当 `q > q_reference` 时，按 `log2(q) - log2(q_reference)` 扣减。

默认口径下：

- `target_bits = 128`
- `poseidon2_floor_bits = 128`
- `q_reference = 2^16`

因此，M3 的作用可以概括为：在工程实现约束外，再按安全代理指标剔除明显不合适的候选。

### 7.4 M4：候选重编译与实测 benchmark

脚本：`scripts/collect_benchmark_params.sh`

在修正后的流程中，M4 首先面向全部 `M3 security-pass` 候选执行全量 STARK 统计，而不是只对前若干候选做采样。也就是说，`collect_benchmark_params.sh` 在这一阶段应设置 `TOP_K=0`，表示“不截断、按输入 CSV 全量执行”。

这一阶段并不是直接使用理论估计，而是对每个候选：

1. 生成临时参数头文件 `params/params-sphincs-poseidon2-searchtmp.h`；
2. 基于该参数重新编译测试程序；
3. 分别运行常规签名 benchmark 与 STARK 统计程序；
4. 记录每个候选的性能和证明规模指标。

其输出指标包括：

- `keygen_us_median / p95 / stddev`
- `sign_us_median / p95 / stddev`
- `verify_us_median / p95 / stddev`
- `pk_bytes / sk_bytes / sig_bytes`
- `trace_calls`
- `trace_lanes`
- `witness_rows`
- `proof_bytes`
- `preprocess_ms_median`
- `prove_core_ms_median`
- `prove_e2e_ms_median`
- `stark_verify_ms_median`

因此，M4 体现的是“真实实现上的可用性与开销”，而不是停留在静态公式层面。

进一步地，修正后的参数重搜流程把 M4 拆成两层理解：

1. **M4-STARK 全量层**
   - 输入：全部 `M3 security-pass` 候选；
   - 输出：`logs/params-benchmark-v1-full.csv`；
   - 含义：确定哪些候选在当前 STARK 后端下“确实可跑通并可导出约束/证明指标”。

2. **M4-sign/verify 补跑层**
   - 输入：全部 `M4-STARK status=ok` 候选；
   - 输出：`logs/params-signverify-m4-ok-v1.csv`；
   - 含义：对所有 STARK 可用候选补跑普通签名/验签时间，保证后续 Pareto 比较建立在统一全集上。

为支持这一修正流程，仓库新增了：

- `scripts/select_m4_ok_for_signverify.py`
- `scripts/run_param_signverify_global_pareto.sh`

前者负责从全量 STARK 结果中抽取全部 `M4-ok` 候选，后者负责串联“抽取 `M4-ok` -> 全量补跑 sign/verify -> 全局 Pareto 分析”。

### 7.5 M5：全局 Pareto 前沿与最终推荐

脚本：`scripts/analyze_pareto_poseidon2.py`

修正后的 M5 不再以“少量入围候选子集”作为输入，而是基于：

- `M3 security-pass`
- `M4 STARK status=ok`
- `M4-ok` 全量 `sign/verify status=ok`

三者的交集来构建最终有效候选集合。也就是说，M5 的比较全集应为：

```text
Valid = M3_pass ∩ M4_stark_ok ∩ M4_ok_signverify_ok
```

然后从这一全局有效候选集中提取四个最小化目标轴：

- `sig_bytes`
- `sign_ms`
- `verify_ms`
- `witness_rows`

然后计算 Pareto 前沿，并进一步给出三类推荐：

- 最小签名；
- 最小约束；
- 综合平衡。

这意味着本仓库最终并没有只给一个唯一参数，而是给出三种面向不同目标的参数口径，适合论文中分别对应“通信量优先”“证明规模优先”“综合折中”三种场景。

需要强调的是，只有在这一“全量 `M4-ok` 补跑 sign/verify，再全局 Pareto”的流程下，最终推荐参数才能稳妥地写成“全局重搜后的推荐结果”。若只在少量入围子集上补跑 `sign/verify`，则更准确的说法只能是“入围组内比较结果”。

## 8. 参数重搜实验的结果总结

### 8.1 候选数量变化的正确解释

仓库早期结果文档中曾出现如下数量口径：

- M3 安全通过候选数：`612`
- M4 STARK 可用候选数：`526`
- sign/verify 补跑可用候选数：`10`
- 合并后有效候选数：`10`
- Pareto 前沿候选数：`6`

这一组数字不能直接解释为“526 个候选经过全局 Pareto 只剩 10 个有效候选”。更准确地说：

- `612 -> 526` 反映的是从 `M3 security-pass` 到 `M4 STARK status=ok` 的自然收缩；
- `526 -> 10` 在旧流程里并不是自然淘汰，而是因为只对少量入围候选补跑了 `sign/verify`；
- 因此，旧口径下的 `10` 是“入围组规模”，不是“全局有效候选规模”。

这也是为什么本仓库后续将参数重搜流程修正为：

1. 对全部 `M3 pass` 候选跑全量 `M4 STARK`；
2. 对全部 `M4-ok` 候选补跑 `sign/verify`；
3. 在全集上重新计算全局 Pareto。

因此，在论文中更稳妥的写法是：旧结果仅可视为一次“基于入围组的局部比较快照”，正式结论应以后续全量 `M4-ok` 补跑并重新生成的 Pareto 结果为准。

### 8.2 Pareto 前沿候选

在修正后的流程下，Pareto 前沿候选应从全局有效候选集重新计算得到。因此，论文中的最终前沿表格应在完成“全量 `M4-ok` 补跑 sign/verify”后再填入，而不应继续直接沿用旧的入围子集版结果。

在完成新一轮全局重跑前，可以先保留如下定性观察：

- 签名字节数、普通签名时间、验证时间、`witness_rows` 之间存在显著多目标冲突；
- 某些参数族可能在 STARK 指标上较优，但普通签名耗时明显偏大；
- 某些参数族的普通签名较快，但未必能给出最小的证明规模；
- 因此最终推荐不应由单一指标决定，而必须基于全局 Pareto 前沿。

### 8.3 三类最终推荐参数

修正后的推荐参数应继续按三种口径给出：

#### 1. 最小签名

```text
待全量 M4-ok 补跑后更新
```

适合在论文中表述为：当首要目标是压缩签名字节数时，应从全局 Pareto 前沿中选择 `sig_bytes` 最小的候选。

#### 2. 最小约束

```text
待全量 M4-ok 补跑后更新
```

适合在论文中表述为：当首要目标是减少零知识证明中的 witness 行数或约束规模时，应从全局 Pareto 前沿中选择 `witness_rows` 最小的候选。

#### 3. 综合平衡

```text
待全量 M4-ok 补跑后更新
```

适合在论文中作为默认推荐口径，因为它应在通信量、普通签名时间、验证时间和证明规模之间取得更均衡的折中。

## 9. 第三章可直接采用的归纳表述

如果需要把本节直接改写进论文正文，可采用如下归纳：

### 9.1 对底层哈希替换的结论

本仓库的 Poseidon2 替换方案并未改变 SPHINCS+ 的上层签名结构，而是以 Poseidon2 海绵替换底层哈希后端，并通过显式域分离分别实现 `prf_addr`、`PRF_msg`、`H_msg` 与 `thash`。在这一过程中：

- `ADRS` 仍以原始 32 字节编码进入哈希；
- `pub_seed` 仍作为公开实例分离参数保留；
- `sk_seed` 与 `sk_prf` 仍分别承担地址 PRF 和消息随机化 PRF 的密钥化输入；
- `optrand` 仍保留消息随机化功能；
- `H_msg` 仍按 `R || pk || m` 的结构生成 `digest/tree/leaf_idx`。

因此，该方案本质上是“保持 SPHINCS+ 结构语义不变的 Poseidon2 底层替换”。

### 9.2 对参数选择方法的结论

本仓库没有直接照搬标准参数，而是围绕 Poseidon2 与零知识证明场景重新进行了参数重搜。其方法为：

1. 先做结构合法性过滤；
2. 再做 `proxy-v1` 安全过滤；
3. 再做逐候选真实重编译和 benchmark；
4. 最后按签名字节数、签名时间、验证时间、witness 行数四目标计算 Pareto 前沿。

这种方法的优点是：

- 能显式纳入本实现的位宽边界和工程约束；
- 能把签名性能与 STARK 证明规模同时纳入选择标准；
- 能为不同应用目标给出不同推荐参数，而不是只输出单一解。

### 9.3 论文写作时的表述边界

建议在论文中明确以下边界：

- M3 阶段的安全判断是仓库的 `proxy-v1` 过滤规则；
- 它可用于工程筛选和实验复现；
- 但不应表述为对标准 SPHINCS+ 安全证明的完整替代。

更稳妥的写法是：本文基于实现约束、代理安全指标、性能测量和证明规模指标进行了参数重搜，并从 Pareto 前沿中给出三类推荐配置。

## 10. 建议在论文中引用的仓库依据

可在撰写时引用如下文件作为实现依据：

- `ref/hash_poseidon2.c`
- `ref/thash_poseidon2_simple.c`
- `ref/poseidon2.h`
- `ref/poseidon2.c`
- `ref/address.h`
- `ref/address.c`
- `ref/context.h`
- `ref/hash_poseidon2_adapter.c`
- `ref/scripts/search_params_poseidon2.py`
- `ref/scripts/eval_security_poseidon2.py`
- `ref/scripts/collect_benchmark_params.sh`
- `ref/scripts/analyze_pareto_poseidon2.py`
- `ref/final-results-v1/param-search/params-pareto-v1.md`
- `ref/final-results-v1/param-search/params-final-candidates-v1.md`

## 11. 后续可扩展内容

如果后续需要把这一章继续展开，本仓库信息还可以继续支撑以下小节：

- Poseidon2 与 SHA2/Shake 版本在 `thash` 调用次数、约束数上的差异；
- trace 记录如何映射到 STARK witness；
- `thash exact` 分支实验与当前 simple 版本的关系；
- 推荐参数在不同目标函数下的可视化比较。

这些内容可作为第三章后半节或第四章实验章节的延伸。
