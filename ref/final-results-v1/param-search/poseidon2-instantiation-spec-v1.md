# Poseidon2-SPHINCS+ Simple 接口实例化说明 v1（M1）

## 1. 文档目的
- 冻结当前仓库中 SPHINCS+ simple 路径对 Poseidon2 的接口实例化规则。
- 给参数重搜阶段提供可执行、可复核的对象定义，避免“只说替换哈希”但不定义接口语义。

## 2. Poseidon2 配置（当前实现）
- 有限域：Goldilocks prime `2^64 - 2^32 + 1`。
- 状态宽度：`t=12`。
- 容量：`c=6` words；速率：`r=6` words（48 bytes）。
- 轮数：`RF=8`、`RP=22`。
- S-box：`x^7`。
- 实现入口：`poseidon2.c` / `poseidon2.h`。

## 3. 域分离与接口映射

### 3.1 域标签
- `PRF`（`PRF_ADDR`）：`0x01`
- `PRF_msg`：`0x02`
- `H_msg`：`0x03`
- `T_l/F/H`：
- `THASH_F`：`0x11`
- `THASH_H`：`0x12`
- `THASH_TL`：`0x13`
- `COMMIT`（盲签辅助接口）：`0x20`

### 3.2 六类接口实例化
- `PRF`：`PRF(pk_seed || ADRS || sk_seed)`，域 `PRF_ADDR`。
- `PRF_msg`：`PRF_msg(sk_prf || optrand || m)`，域 `GEN_MESSAGE_RANDOM`。
- `H_msg`：`H_msg(R || pk || m)`，域 `HASH_MESSAGE`，输出切分为 `digest/tree/leaf`。
- `F/H/T_l`：统一编码 `pk_seed || ADRS || inblocks*SPX_N`，根据 `inblocks` 映射到 `F/H/T_l` 域。

## 4. 编码规则（冻结）
- `PRF_ADDR` 输入长度固定：`2*SPX_N + SPX_ADDR_BYTES`。
- `THASH` 输入长度固定：`SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N`。
- `H_msg` 前缀长度：`SPX_N + SPX_PK_BYTES`（后接消息）。
- 以上长度定义已在 `poseidon2.h` 固化为：
- `SPX_P2_ENCODED_PRF_ADDR_BYTES`
- `SPX_P2_ENCODED_THASH_BYTES(inblocks)`
- `SPX_P2_HMSG_PREFIX_BYTES`

## 5. ADRS 与防混淆规则
- ADRS 按现有 SPHINCS+ 地址字节布局原样拼接（`SPX_ADDR_BYTES=32`）。
- 接口之间不通过“输入前缀猜测”区分，而通过域标签强制区分。
- `THASH` 三类语义共享同一编码模板，但域标签严格分离。

## 6. 实现对照（代码锚点）
- `PRF_ADDR`：`hash_poseidon2.c:prf_addr`
- `PRF_msg`：`hash_poseidon2.c:gen_message_random`
- `H_msg`：`hash_poseidon2.c:hash_message`
- `F/H/T_l` 映射：`thash_poseidon2_simple.c:thash` -> `poseidon2_hash_thash_by_inblocks`
- 域标签与常量：`poseidon2.h`

## 7. M1 验收测试
- 新增测试：`test/poseidon2_instantiation_m1.c`
- 覆盖点：
- `inblocks=1/2/3` 到 `F/H/T_l` 的映射正确；
- `F/H/T_l` 域分离有效（同输入不同域输出应不同）。

## 8. 说明与后续
- 本文档只冻结 simple 路径，不覆盖 robust 变体。
- 参数重搜阶段（M2+）若修改任一编码规则或域标签，必须同步升版（`v2`）并补回归测试。

## 9. M5 入围与 sign/verify 补跑规则（v1）
- 目标：在已完成全量 STARK 的候选中，自动选出少量候选补跑 `sign/verify`，用于最终推荐。
- 输入文件：
- 全量 STARK 结果：`logs/params-benchmark-v1-full.csv`
- 安全筛选结果：`logs/params-security-pass-v1.csv`
- 入围硬条件（必须同时满足）：
- `params-benchmark-v1-full.csv` 中 `status=ok`
- `params-benchmark-v1-full.csv` 中 `error=signverify_disabled`
- 仅保留在 `params-security-pass-v1.csv` 中 `security_pass=1` 的同 `candidate_id`
- 入围排序键（从优到次）：
- `prove_e2e_ms_median` 升序（优先端到端证明更快）
- `proof_bytes` 升序（同速率下优先证明更小）
- `sig_bytes` 升序（同上再优先签名更小）
- `candidate_id` 升序（保证稳定、可复现）
- 入围数量：
- 默认 `TOP_SIGNVERIFY=10`
- 若候选总数不足 `10`，则全量入围
- 补跑执行：
- 由入围 `candidate_id` 从 `params-security-pass-v1.csv` 抽取子集 CSV
- 执行 `collect_benchmark_params.sh`，设置 `ENABLE_SIGNVERIFY=1`、`ENABLE_STARK=0`
- 建议 `RUNS_SIGNVERIFY=3`，统计中位数、P95、标准差
- 产物：
- `logs/params-signverify-finalists.csv`（仅入围候选的 sign/verify 统计）
