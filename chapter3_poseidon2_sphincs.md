# 3. SPHINCS+的Poseidon2哈希替换

本章围绕本文实现中的核心改动展开，即在保持SPHINCS+上层签名结构基本不变的前提下，将其底层哈希接口替换为面向零知识证明友好的Poseidon2后端。与重新设计一种签名算法不同，本文的目标是在尽可能保留SPHINCS+寻址机制、密钥材料布局、签名流程语义和验证流程的基础上，完成底层哈希实例化的工程替换，并进一步给出适合Poseidon2与STARK证明场景的参数选择方法。

本章首先说明替换设计的总体原则与边界，然后分别给出`prf_addr`、`PRF_msg`、`H_msg`和`thash`四类底层接口的Poseidon2适配方式；随后介绍Poseidon2后端的海绵接口、域分离和字节到有限域元素的映射；最后基于实现中的参数重搜实验，讨论候选过滤、benchmark统计、Pareto前沿和最终推荐参数。需要强调的是，本章所述安全筛选中的`proxy-v1`口径是一种工程可复现的代理过滤规则，不能等同于对标准SPHINCS+安全证明的完整替代。

## 3.1 设计目标与替换边界

SPHINCS+的安全性和模块化结构高度依赖底层哈希原语。其签名流程中，地址相关伪随机函数用于派生WOTS+和FORS节点秘密值，消息随机化函数用于生成签名随机值\(R\)，消息哈希函数用于将消息映射到FORS摘要、子树索引和叶子索引，而树哈希函数则负责实现\(F\)、\(H\)、\(T_l\)等可调哈希压缩操作。因此，将底层哈希替换为Poseidon2时，不能简单地把所有哈希调用改写为同一个普通哈希函数，而必须保持各接口之间的语义边界。

本文实现遵循“上层结构不变、底层后端替换”的原则。具体而言，超树层数、FORS结构、WOTS+链式计算方式、ADRS地址编码、`public seed`参与方式、私钥种子使用方式以及签名输出结构均保持SPHINCS+原有语义；变化主要集中在哈希后端，即将SHA2/SHAKE风格的字节哈希接口替换为基于Goldilocks域的Poseidon2海绵接口，并用显式域分离标签区分不同调用语义。

> 图3.1 占位：Poseidon2替换SPHINCS+底层哈希接口的总体结构。建议图中保留SPHINCS+上层结构，并标出`PRF_msg`、`H_msg`、`prf_addr`、`thash`统一接入Poseidon2后端；同时标注ADRS、`pub_seed`、`sk_seed`、`sk_prf`、`optrand`与消息\(M\)的输入路径。

### 3.1.1 不能直接沿用标准参数的原因

虽然本文保留SPHINCS+的整体结构，但在底层哈希函数由SHA2/SHAKE类原语切换为Poseidon2后，参数选择的评价标准已经发生变化。标准SPHINCS+参数主要面向传统软件环境下的签名尺寸、签名速度和验证速度，而本文还需要考虑哈希调用在STARK证明中的算术化成本，例如`trace_calls`、`trace_lanes`、`witness_rows`和端到端证明时间等指标。

因此，原参数集在传统哈希后端下可能是合理折中，但在Poseidon2与STARK结合的场景下未必仍然是最优。特别是FORS参数\(k\)、\(a\)，超树高度\(h\)，层数\(d\)以及Winternitz参数\(w\)会共同影响签名大小、普通签名耗时和证明约束规模。本文采用重新枚举、静态过滤、安全代理评估、逐候选重编译benchmark以及Pareto分析的方式重新选择参数。

### 3.1.2 替换后保留的SPHINCS+语义

本文的Poseidon2替换不是对SPHINCS+签名结构的重新设计，而是对底层哈希后端的实例化替换。具体保留关系如表3.1所示。ADRS仍以32字节地址编码参与`prf_addr`和`thash`；`pub_seed`仍作为公开实例分离参数参与相关哈希；`sk_seed`和`sk_prf`仍分别承担地址PRF与消息随机化PRF的密钥化来源；`optrand`仍参与消息随机化；`H_msg`仍按\(R\)、\(PK\)和消息\(M\)生成FORS摘要、子树索引与叶子索引。

表3.1 Poseidon2替换中保留的SPHINCS+核心语义

| 保留对象 | 原SPHINCS+作用 | Poseidon2替换后的处理方式 |
|---|---|---|
| ADRS | 区分层级、节点位置和调用类型 | 仍以32字节编码作为哈希输入 |
| `pub_seed` | 提供公开参数与实例分离 | 在`prf_addr`和`thash`输入前缀中保留 |
| `sk_seed` | 派生WOTS+/FORS秘密节点 | 作为`prf_addr`的私钥化输入保留 |
| `sk_prf` | 生成消息相关随机值\(R\) | 作为`PRF_msg`的密钥化输入保留 |
| `optrand` | 对冲签名随机化 | 与`sk_prf`和消息共同输入Poseidon2 |
| `digest/tree/leaf_idx` | 选择FORS消息和超树位置 | 仍由`H_msg`输出流切分得到 |

## 3.2 Poseidon2后端与域分离设计

本文实现中的Poseidon2后端采用64位Goldilocks域，状态宽度\(t=12\)，容量字数`capacity=6`，速率字数`rate=6`，全轮数\(R_F=8\)，部分轮数\(R_P=22\)。该配置不是针对某一个接口的单点最优，而是作为所有SPHINCS+底层哈希接口共享的固定后端profile。统一profile有利于保持实现可复现、trace统计口径一致，并减少为不同接口维护多套Poseidon2参数所带来的工程复杂度。

```c
#define SPX_POSEIDON2_FIELD_BITS 64
#define SPX_POSEIDON2_T 12
#define SPX_POSEIDON2_CAPACITY_WORDS 6
#define SPX_POSEIDON2_RATE_WORDS (SPX_POSEIDON2_T - SPX_POSEIDON2_CAPACITY_WORDS)
#define SPX_POSEIDON2_RATE_BYTES (SPX_POSEIDON2_RATE_WORDS * sizeof(uint64_t))
#define SPX_POSEIDON2_RF 8
#define SPX_POSEIDON2_RP 22
```

从零知识证明角度看，Goldilocks域与`uint64_t` lane表示天然匹配，使字节流到域元素的映射较为直接，并避免在C端引入复杂的大整数运算。状态宽度\(t=12\)与`rate=6`、`capacity=6`的组合则在吞吐量和证明成本之间取得折中：较大的rate可以减少长输入吸收次数，而不过度增大状态宽度又可控制每轮trace和约束规模。

### 3.2.1 增量海绵接口

Poseidon2后端以增量海绵接口对外提供可变长度哈希能力。接口包括初始化、吸收、结束填充和挤出四个阶段。初始化阶段首先吸收1字节域标签；吸收阶段按字节流接收输入，再由底层以little-endian方式映射为64位lane；结束阶段采用`pad10*1`填充；挤出阶段输出所需字节数。

```c
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx,
                        spx_poseidon2_domain domain_tag)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->domain_tag = (uint8_t)domain_tag;
    poseidon2_inc_absorb(ctx, &ctx->domain_tag, 1);
}

void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx)
{
    ctx->absorb_buf[ctx->absorb_pos] ^= 0x01u;
    ctx->absorb_buf[SPX_POSEIDON2_RATE_BYTES - 1] ^= 0x80u;
    p2_absorb_block(ctx, ctx->absorb_buf);
}
```

上述设计的关键在于：域标签不是以人工字符串前缀的形式散落在各接口中，而是在海绵初始化时被明确注入状态。这样既减少了编码不一致风险，也便于后续trace记录和约束系统根据`domain_tag`直接识别调用语义。

### 3.2.2 域分离标签

由于SPHINCS+在不同位置复用哈希原语，如果不做域分离，不同语义的输入可能落入同一哈希命名空间，增加实现混淆与安全分析难度。本文实现为地址PRF、消息随机化、消息哈希以及树哈希中的\(F\)、\(H\)、\(T_l\)分别设置独立域标签。

表3.2 Poseidon2后端中使用的主要域分离标签

| 域标签 | 取值 | 对应接口语义 |
|---|---:|---|
| `SPX_P2_DOMAIN_PRF_ADDR` | `0x01` | 地址相关PRF，用于WOTS+/FORS秘密值派生 |
| `SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM` | `0x02` | 消息随机化PRF，生成\(R\) |
| `SPX_P2_DOMAIN_HASH_MESSAGE` | `0x03` | 消息摘要`H_msg`，输出`digest/tree/leaf_idx` |
| `SPX_P2_DOMAIN_THASH_F` | `0x11` | 单输入块树哈希\(F\) |
| `SPX_P2_DOMAIN_THASH_H` | `0x12` | 双输入块树哈希\(H\) |
| `SPX_P2_DOMAIN_THASH_TL` | `0x13` | 多输入块树哈希\(T_l\) |

## 3.3 四类底层哈希接口的适配

本节分别给出`prf_addr`、`PRF_msg`、`H_msg`和`thash`的Poseidon2适配方式。为了保持论文表述清晰，下面采用“输入编码形式、实现代码片段、语义保持分析”的顺序展开。

### 3.3.1 `prf_addr`接口

`prf_addr`用于根据公开种子、地址和私钥种子生成地址相关的伪随机值，是WOTS+和FORS秘密节点派生过程的重要组成部分。本文实现将输入编码为`pub_seed || ADRS || sk_seed`，并在Poseidon2中使用`PRF_ADDR`域标签。其形式化定义可写为：

\[
prf\_addr_{P2}(pub\_seed, ADRS, sk\_seed)
= Poseidon2_{domain}(PRF\_ADDR, pub\_seed \parallel ADRS \parallel sk\_seed)
\]

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

该接口完整保留了SPHINCS+中“公开实例参数、结构地址、私有种子”的三元绑定关系。`pub_seed`保证不同公钥实例下同一地址不会产生相同命名空间，ADRS绑定节点位置和用途，`sk_seed`则提供私钥化来源。

### 3.3.2 `PRF_msg`与消息随机化

`PRF_msg`用于生成签名随机值\(R\)。本文实现中对应函数为`gen_message_random`，其输入为`sk_prf`、`optrand`和消息\(M\)，输出长度为`SPX_N`字节。其定义可表示为：

\[
PRF\_msg_{P2}(sk\_prf, optrand, M)
= Poseidon2_{domain}(GEN\_MESSAGE\_RANDOM, sk\_prf \parallel optrand \parallel M)
\]

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

这里保留了SPHINCS+原有的密钥化与随机化机制。`sk_prf`使\(R\)依赖签名者私钥材料，`optrand`提供对冲随机性，消息\(M\)直接参与输入，从而避免同一密钥下不同消息共享相同随机化值。该设计也与第二章所述Pure模式中的双遍处理问题相衔接：\(R\)依赖完整消息，因此`H_msg`阶段必须在\(R\)生成后再次处理消息。

### 3.3.3 `H_msg`接口

`H_msg`负责将\(R\)、公钥和消息映射为FORS摘要、超树子树索引和叶子索引。本文实现保持SPHINCS+输出切分语义不变，只是将底层输出流改为Poseidon2海绵挤出结果。其定义为：

\[
H\_msg_{P2}(R, PK, M)
= Poseidon2_{domain}(HASH\_MESSAGE, R \parallel PK \parallel M)
\]

Poseidon2输出的`SPX_DGST_BYTES`字节缓冲区随后被依次切分为三部分：前`SPX_FORS_MSG_BYTES`字节作为FORS消息摘要；接下来的`SPX_TREE_BYTES`字节解释为`tree`，并按`SPX_TREE_BITS`掩码；最后`SPX_LEAF_BYTES`字节解释为`leaf_idx`，并按`SPX_LEAF_BITS`掩码。当前C实现使用`uint64_t`保存`tree`、`uint32_t`保存`leaf_idx`，因此参数搜索时要求`tree_bits <= 64`且`leaf_bits <= 32`。

```c
poseidon2_inc_init(&p2ctx, SPX_P2_DOMAIN_HASH_MESSAGE);
poseidon2_inc_absorb(&p2ctx, R, SPX_N);
poseidon2_inc_absorb(&p2ctx, pk, SPX_PK_BYTES);
poseidon2_inc_absorb(&p2ctx, m, (size_t)mlen);
poseidon2_inc_finalize(&p2ctx);
poseidon2_inc_squeeze(buf, SPX_DGST_BYTES, &p2ctx);

memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
bufp += SPX_FORS_MSG_BYTES;
*tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
*tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
bufp += SPX_TREE_BYTES;
*leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
*leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
```

### 3.3.4 `thash`接口

`thash`是SPHINCS+中可调哈希抽象的核心接口，用于实现WOTS+链、FORS树和XMSS树中的压缩操作。本文实现将输入统一编码为`pub_seed || ADRS || in`，并根据`inblocks`选择不同域标签：`inblocks = 1`时对应\(F\)，`inblocks = 2`时对应\(H\)，`inblocks >= 3`时对应\(T_l\)。

\[
THASH_{P2}(pub\_seed, ADRS, X_1,\ldots,X_s)
= Poseidon2_{domain}(THASH\_semantic(s), pub\_seed \parallel ADRS \parallel X_1 \parallel \cdots \parallel X_s)
\]

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

按`inblocks`进行语义路由的好处在于：一方面，\(F\)、\(H\)和\(T_l\)作为不同树哈希语义不被混入同一域；另一方面，输入编码逻辑保持统一，便于代码维护、trace统计和后续约束系统复用。对于STARK证明而言，统一输入布局减少了解析分支，仅需依据`domain_tag`和`inblocks`区分调用语义。

表3.3 四类Poseidon2适配接口的输入编码

| 接口 | 域标签 | 输入编码 | 输出用途 |
|---|---|---|---|
| `prf_addr` | `PRF_ADDR` | `pub_seed || ADRS || sk_seed` | 地址相关伪随机值 |
| `PRF_msg` | `GEN_MESSAGE_RANDOM` | `sk_prf || optrand || M` | 签名随机值\(R\) |
| `H_msg` | `HASH_MESSAGE` | `R || PK || M` | `digest`、`tree`、`leaf_idx` |
| `thash-F` | `THASH_F` | `pub_seed || ADRS || X` | 单块链式压缩 |
| `thash-H` | `THASH_H` | `pub_seed || ADRS || X_1 || X_2` | 二叉树节点压缩 |
| `thash-T_l` | `THASH_TL` | `pub_seed || ADRS || X_1 || ... || X_s` | 多块WOTS+公钥压缩 |

## 3.4 工程实现细节

除了接口层替换外，Poseidon2后端还需要处理字节流与有限域元素之间的映射、轮函数实现、trace记录与约束统计等工程问题。这些细节决定了替换方案是否能够被后续STARK证明系统稳定消费，而不只是完成普通签名和验证。

### 3.4.1 字节到Goldilocks域元素的映射

本文实现采用little-endian方式将输入字节打包为64位lane，再映射到Goldilocks域元素。该方式与C语言中的`uint64_t`表示直接对齐，实现简单且易于复现。在trace适配代码中，还提供了将字节编码为lane数组的辅助接口，用于记录每次Poseidon2调用的输入规模。

```c
int spx_p2_encode_bytes_to_lanes(uint64_t *out_lanes, size_t *out_count,
                                 const uint8_t *in_bytes, size_t in_len);
```

这种设计把签名后端与证明后端统一到同一数据表示上：普通签名阶段处理的是字节数组，证明统计阶段则可以进一步解释为有限域lane序列，从而为后续AIR约束或trace表格生成提供直接入口。

### 3.4.2 轮函数与固定profile

Poseidon2置换由前半段全轮、中间部分轮和后半段全轮组成。实现中包含Goldilocks域加法、乘法、\(x^7\) S-box、外部混合层、内部混合层和完整置换函数。本文采用固定\(R_F=8\)、\(R_P=22\)的profile，主要原因是保持参数重搜实验的统一基线。若在重搜SPHINCS+参数的同时改变Poseidon2轮数和状态结构，则实验结果将难以区分是由签名参数变化导致，还是由哈希后端profile变化导致。

因此，本章将该profile视为工程基线，而非脱离具体仓库上下文的全局最优断言。后续工作仍可在固定SPHINCS+参数后进一步搜索Poseidon2内部profile，以寻找证明成本与安全裕度之间更优的组合。

### 3.4.3 trace与约束统计适配

为了服务STARK证明场景，本文实现为每次Poseidon2调用记录`domain_tag`、输入字节长度、输出字节长度、ADRS、输入lane数量和输出lane数量等信息。该记录机制使得签名流程中的哈希调用可以被统一统计，并进一步转换为`witness_rows`、`trace_calls`和证明时间等指标。

> 图3.2 占位：Poseidon2调用trace与STARK统计的适配流程。建议图中表示从签名执行到trace记录，再到`witness_rows`、`trace_calls`、`trace_lanes`、`prove_e2e_ms`统计的流水线；同时标出`hash_poseidon2_adapter.c`在签名后端与STARK统计之间的位置。

## 3.5 参数重搜实验设计

在Poseidon2后端固定后，本文进一步对SPHINCS+参数空间进行重搜。参数搜索流程分为M2至M5四个阶段：M2负责结构枚举与静态过滤，M3采用`proxy-v1`安全代理指标进行过滤，M4先对全部`M3 security-pass`候选进行全量STARK实测，再对全部`M4-ok`候选补跑普通签名/验签benchmark，M5在`M3 pass ∩ M4 ok ∩ sign/verify ok`的全集上提取全局Pareto前沿并给出推荐参数。

> 图3.3 占位：Poseidon2参数重搜的M2-M5流程。建议图中表示“M2结构枚举 → M3 proxy-v1安全过滤 → M4-STARK全量实测 → M4-sign/verify对全部M4-ok候选补跑 → M5全局Pareto分析与三类推荐参数”。

### 3.5.1 M2：结构枚举与静态过滤

M2阶段枚举候选元组\((n,h,d,k,a,w,q)\)，其中\(n\)为安全参数字节数，\(h\)为总树高，\(d\)为超树层数，\(k\)和\(a\)为FORS参数，\(w\)为Winternitz参数，\(q\)为签名次数预算。结构过滤首先要求\(h\)能被\(d\)整除，\(w\)必须为受支持的2的幂；同时，结合`H_msg`实现中的整数类型边界，要求`tree_bits <= 64`且`leaf_bits <= 32`。

\[
tree\_height = \frac{h}{d},\quad
tree\_bits = tree\_height \cdot (d - 1),\quad
leaf\_bits = tree\_height
\]

M2还会计算WOTS长度、FORS消息字节数、公私钥大小和签名字节数。其中签名大小由\(R\)、FORS签名、\(d\)层WOTS+签名以及认证路径共同构成，其计算式为：

\[
sig\_bytes = n + (a + 1)kn + d \cdot wots\_len \cdot n + hn
\]

### 3.5.2 M3：`proxy-v1`安全过滤

M3阶段采用仓库定义的`proxy-v1`规则作为工程安全过滤口径。该规则的目的不是替代标准SPHINCS+安全证明，而是在大规模参数枚举中剔除明显不合适的候选，使后续benchmark集中在较有希望的参数区域。

该阶段计算`hash_bits = 8n`、`fors_bits = k · a`，并令`comb_security_bits = min(hash_bits, fors_bits)`。同时，将Poseidon2后端安全下界记为`poseidon2_floor_bits`，并根据签名次数预算\(q\)引入`budget_penalty_bits`。最终声明安全位数取comb、Poseidon2下界和预算扣减后三者的最小值。默认实验口径采用`target_bits = 128`、`poseidon2_floor_bits = 128`和`q_reference = 2^16`。

\[
claimed\_security\_bits =
\min(comb\_security\_bits,\ poseidon2\_floor\_bits,\ comb\_security\_bits - budget\_penalty\_bits)
\]

### 3.5.3 M4：逐候选重编译与benchmark

M4阶段不再只依赖静态公式，而是对每个候选生成临时参数头文件，重新编译测试程序并进行真实实测。该阶段可分为两步：第一步对全部`M3 security-pass`候选进行全量STARK统计，得到`params-benchmark-v1-full.csv`；第二步从中抽取全部`status=ok`的`M4-ok`候选，对其全量补跑普通签名与验签benchmark，得到`params-signverify-m4-ok-v1.csv`。这样可以保证后续Pareto比较建立在统一的全局有效候选集上。

表3.4 M4阶段采集的主要benchmark指标

| 指标类别 | 具体指标 | 含义 |
|---|---|---|
| 普通签名性能 | `keygen_us`、`sign_us`、`verify_us` | 密钥生成、签名和验证耗时统计 |
| 尺寸指标 | `pk_bytes`、`sk_bytes`、`sig_bytes` | 公钥、私钥和签名字节数 |
| trace规模 | `trace_calls`、`trace_lanes` | Poseidon2调用次数与lane数量 |
| 证明规模 | `witness_rows`、`proof_bytes` | STARK witness行数与证明大小 |
| 证明耗时 | `preprocess_ms`、`prove_core_ms`、`prove_e2e_ms`、`stark_verify_ms` | 预处理、证明生成和验证耗时 |

### 3.5.4 M5：Pareto前沿与推荐策略

M5阶段以`sig_bytes`、`sign_ms`、`verify_ms`和`witness_rows`作为四个最小化目标，在`M3 pass ∩ M4 ok ∩ sign/verify ok`的全集上提取全局Pareto前沿。若一个候选在所有目标上均不劣于另一个候选，且至少一个目标更优，则后者被前者支配；未被任何候选支配的集合即为Pareto前沿。由于不同应用场景对通信量、签名速度和证明成本的偏好不同，本文不强制给出唯一最优参数，而是从前沿中选出最小签名、最小约束和综合平衡三类推荐。

表3.5 参数重搜各阶段的候选数量变化

| 阶段 | 候选数 | 说明 |
|---|---:|---|
| M3安全通过 | 612 | 通过`proxy-v1`代理安全过滤 |
| M4 STARK可用 | 526 | 可完成STARK统计的候选 |
| sign/verify补跑可用 | 待全量重跑 | 应为全部`M4-ok`候选的补跑结果，而非入围子集 |
| 合并后有效候选 | 待全量重跑 | 应从`M3 pass ∩ M4 ok ∩ sign/verify ok`全集重新统计 |
| Pareto前沿 | 待全量重跑 | 需在全局有效候选集上重新计算 |

## 3.6 参数重搜结果与推荐参数

本节用于汇总全局Pareto分析得到的参数结果。最终推荐参数应以完成全部`M4-ok`候选`sign/verify`补跑后的全局Pareto结果为准，并在论文定稿时统一填入下列表格与文字说明。

表3.6 Poseidon2参数重搜得到的全局Pareto前沿候选

| 候选ID | \(n\) | \(h\) | \(d\) | \(k\) | \(a\) | \(w\) | \(q\) | 签名/B | 签名/ms | 验证/ms | `witness_rows` | 证明/ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 待实验完成后填入 | - | - | - | - | - | - | - | - | - | - | - | - |

从全局Pareto前沿的定义可知，最小签名字节数并不必然对应最小`witness_rows`，普通签名耗时较低的候选也未必在STARK证明规模上最优。因此，参数选择应结合应用场景进行分层推荐，而不宜只依据单一指标排序。

### 3.6.1 最小签名参数

当首要目标是降低通信开销或压缩签名字节数时，本文从全局Pareto前沿中选择`sig_bytes`最小的候选作为“最小签名参数”。正式定稿时可采用如下模板填入：

```text
最小签名参数：candidate_id = [待填入]
参数组：(n=[待填入], h=[待填入], d=[待填入], k=[待填入], a=[待填入], w=[待填入], q=[待填入])
sig_bytes = [待填入]
sign_ms = [待填入]
verify_ms = [待填入]
witness_rows = [待填入]
prove_e2e_ms = [待填入]
```

### 3.6.2 最小约束参数

当首要目标是降低STARK证明规模时，本文从全局Pareto前沿中选择`witness_rows`最小的候选作为“最小约束参数”。正式定稿时可采用如下模板填入：

```text
最小约束参数：candidate_id = [待填入]
参数组：(n=[待填入], h=[待填入], d=[待填入], k=[待填入], a=[待填入], w=[待填入], q=[待填入])
witness_rows = [待填入]
sig_bytes = [待填入]
sign_ms = [待填入]
verify_ms = [待填入]
prove_e2e_ms = [待填入]
```

### 3.6.3 综合平衡参数

若需要在通信量、普通签名耗时、验证耗时和证明规模之间取得折中，则可从全局Pareto前沿中进一步选择综合得分最优的候选作为“综合平衡参数”。正式定稿时可采用如下模板填入：

```text
综合平衡参数：candidate_id = [待填入]
参数组：(n=[待填入], h=[待填入], d=[待填入], k=[待填入], a=[待填入], w=[待填入], q=[待填入])
sig_bytes = [待填入]
sign_ms = [待填入]
verify_ms = [待填入]
witness_rows = [待填入]
prove_e2e_ms = [待填入]
```

表3.7 三类推荐参数对比

| 推荐类型 | 候选ID | 参数组\((n,h,d,k,a,w,q)\) | 主要优势 | 适用场景 |
|---|---:|---|---|---|
| 最小签名 | 待实验完成后填入 | 待实验完成后填入 | `sig_bytes`最小 | 带宽受限或存储受限场景 |
| 最小约束 | 待实验完成后填入 | 待实验完成后填入 | `witness_rows`最小 | 证明生成成本敏感场景 |
| 综合平衡 | 待实验完成后填入 | 待实验完成后填入 | 多目标折中较优 | 默认实验与原型系统参数 |

## 3.7 安全性讨论与表述边界

Poseidon2替换后的安全性需要从两个层面理解。第一，在SPHINCS+结构层面，本文尽量保留原方案中ADRS、`public seed`、密钥化输入、消息随机化和输出切分等关键语义，从而使替换后的接口仍对应原有安全分析中的功能角色。第二，在具体实例化层面，Poseidon2作为具体哈希函数，其安全性依赖所选有限域、状态宽度、轮数、S-box指数和轮常量等参数，需要结合已知代数攻击和统计攻击进行评估。

本文参数重搜中使用的`proxy-v1`安全过滤规则仅作为工程筛选工具。它有助于在大量候选中剔除明显不满足目标安全位数或预算条件的参数，但并不构成对SPHINCS+标准安全证明的完整替代。因此，在论文表述中，应将其称为“代理安全指标”或“工程安全过滤口径”，而不应声称其已经证明替换后方案在QROM或标准SPHINCS+模型下完全安全。

更严格的安全论证需要进一步形式化Poseidon2实例化后的可调哈希函数族，并分析其在多目标、不同tweak和量子访问模型下是否满足SPHINCS+安全归约所需的性质。本文当前工作重点是工程替换、参数重搜和证明友好性评估，因此将这一问题作为后续理论分析方向。

## 3.8 本章小结

本章给出了将Poseidon2替换为SPHINCS+底层哈希后端的设计与实现方案。该方案不改变SPHINCS+上层签名结构，而是通过统一的Poseidon2海绵接口和显式域分离标签，分别适配`prf_addr`、`PRF_msg`、`H_msg`和`thash`四类底层接口。在适配过程中，ADRS、`pub_seed`、`sk_seed`、`sk_prf`、`optrand`以及`H_msg`输出切分语义均被保留，从而使替换后的实现保持SPHINCS+原有的结构边界。

在参数选择方面，本章说明了为何不能直接沿用标准SPHINCS+参数，并基于M2至M5流程完成面向Poseidon2与STARK证明场景的参数重搜设计。论文定稿时，可依据全局Pareto分析结果分别填写最小签名、最小约束和综合平衡三类推荐参数，为后续盲签名协议设计和STARK证明集成提供实现基础。
