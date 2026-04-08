# Poseidon2 草案规范（Goldilocks + Sponge-First）

## 1. 目标与边界

本文档定义本仓库 `ref/poseidon2.c` 的下一阶段接口规范与参数草案，目标是：

- 保持 SPHINCS+ 上层调用稳定；
- 先交付统一且可审计的 sponge 版本；
- 在正确性固化前，不提前做 compression 特化优化。

当前状态说明：

- 代码接口已按本规范演进；
- 置换内核 `poseidon2_permute()` 仍为占位；
- 暂不宣称“已完成密码学标准一致实现”。

## 2. 有限域选择（STARK 背景）

首选域：Goldilocks 素域

- 素数：`p = 2^64 - 2^32 + 1`
- 元素存储：`uint64_t`
- 规范要求：任何进入域运算的 lane 都必须是**规范表示**（canonical form）`[0, p-1]`
- 选择理由：
  - 64-bit CPU 软件性能高；
  - 对 STARK 友好，约束和实现成本较低；
  - 工程生态成熟，便于后续证明系统对接。

## 3. 参数草案与安全解释

当前草案参数（`poseidon2.h`）：

- `t = 12`（状态总字数）
- `capacity = 6`（容量字数）
- `rate = 6`（吸收/挤出字数）
- `rate_bytes = 48`

安全直觉与解释（针对 `SPX_N = 24`，即 192-bit 级别）：

- 容量位数：`c_bits = 6 * 64 = 384`
- 与哈希型应用常见经验比较：`c_bits >= 2n = 384`，满足 192-bit 目标的容量基线
- `rate = 384 bit` 能兼顾吞吐与实现简洁，适合先做一致性版本

备注：

- 上述解释是工程草案层面的容量论证，不替代对完整 Poseidon2 参数（轮数、常量、线性层）的正式安全分析。

## 4. 字节到域元素的规范映射（写死规则）

必须固定以下映射，不允许只写成“转成 uint64_t”而不做域规约：

1. 输入按 `rate_bytes = 48` 分块。
2. 每块拆成 6 个 lane，每个 lane 为 8 字节小端。
3. 小端解码得到 `x in [0, 2^64-1]`。
4. 规范映射到 Goldilocks 元素：
   - 若 `x < p`，则 `fe = x`
   - 否则 `fe = x - p`
5. 对不足 8 字节的尾部 lane，先按小端零填充再执行步骤 3-4。

说明：

- 由于 `p` 接近 `2^64`，单次条件减法即可完成规范化。
- 该规则必须在 native 与电路实现中完全一致。

## 5. Sponge 填充与挤出规则

吸收阶段：

1. 首先吸收 1 字节语义域标签（domain tag）。
2. 再吸收消息字节流。
3. 采用 `pad10*1` 风格固定填充：
   - 在消息后追加 `0x01`
   - 终块最后一个 rate 字节按位或 `0x80`
4. 每吸收满一个 rate 块后调用一次 `poseidon2_permute()`。

挤出阶段：

1. 从 rate 部分按小端导出字节；
2. 输出不足时继续置换并挤出；
3. 截断到 `outlen`。

## 6. 域分离策略（含 THASH 细分）

本仓库当前约定域标签：

- `SPX_P2_DOMAIN_PRF_ADDR`
- `SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM`
- `SPX_P2_DOMAIN_HASH_MESSAGE`
- `SPX_P2_DOMAIN_THASH_F`
- `SPX_P2_DOMAIN_THASH_H`
- `SPX_P2_DOMAIN_THASH_TL`

THASH 语义入口要求：

- `poseidon2_hash_thash_f()`
- `poseidon2_hash_thash_h()`
- `poseidon2_hash_thash_tl()`
- `poseidon2_hash_thash_by_inblocks()` 作为桥接函数：
  - `inblocks == 1 -> F`
  - `inblocks == 2 -> H`
  - `inblocks >= 3 -> T_l`

## 7. 正式接口与过渡接口

正式接口（后续代码必须优先使用）：

- `poseidon2_hash_bytes_domain(...)`
- `poseidon2_hash_thash_f/h/tl(...)`
- `poseidon2_hash_thash_by_inblocks(...)`

过渡接口（兼容旧调用）：

- `poseidon2_hash_bytes(...)`

规范约束：

- `poseidon2_hash_bytes(...)` 仅作为迁移期兼容层；
- 新增代码不得绕开 domain API 直接长期依赖该接口。

## 8. 测试计划（含边界差分）

除 KAT 外，必须新增并长期保留编码/填充差分测试，至少覆盖长度：

- `0, 1, 7, 8, 9, 47, 48, 49`

建议测试项：

1. one-shot 与 incremental 一致性（同 domain、同输入）。
2. 相邻边界长度差分（同前缀、不同长度输出应不同）。
3. THASH `F/H/TL` 域分离差分（同输入不同域输出应不同）。
4. `SPX` 主流程回归：`test/spx`、`test/fors`。

## 9. 一致性验收门槛

在宣称“真实 Poseidon2 后端完成”前，至少满足：

1. 置换级 KAT 通过；
2. sponge 编码/填充 KAT 通过；
3. 与参考实现差分比对通过；
4. SPHINCS+ 功能回归通过；
5. 边界长度差分测试通过。

## 10. 当前非目标

- 不在本草案阶段实现 robust-thash；
- 不在本草案阶段实现 SIMD/x4/x8 后端；
- 不在本草案阶段给出最终性能调优结论。
