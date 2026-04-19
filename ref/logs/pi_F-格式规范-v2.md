# pi_F 格式规范 v2（M13）

## 1. 目标
- 定义 `pi_F_v2` 的稳定字节级格式。
- 明确 `v2` 与 `v1` 的核心差异：`v2` 不携带 `sigma_com` 明文。
- 支持后续真实 STARK proof blob 的无歧义封装与校验。

## 2. 版本与标识
- `magic`：`"PFP2"`（小端 u32 常量）。
- `version`：`2`。
- `proof_system_id`：由实现方定义，`v2` 默认使用 STARK 系统标识。

## 3. 编码布局（小端）
固定头（u32）：
1. `magic`
2. `version`
3. `flags`
4. `header_len`
5. `total_len`
6. `proof_system_id`
7. `statement_version`

固定载荷：
- `public_input_digest[SPX_N]`：绑定 `pk/com/public_ctx/statement` 的摘要。
- `ctx_binding[SPX_N]`：`H(public_ctx)`。
- `commitment[SPX_N]`：proof commitment 或等价绑定值。
- `proof_len`（u32）。
- `proof_bytes[proof_len]`。
- `reserved[2]`（u32）：
  - `v2` 解析时必须全 0；
  - 非零视为格式错误。

## 4. 强校验规则
- `magic/version/header_len/total_len` 必须严格匹配。
- `proof_len` 必须与剩余 payload 长度一致。
- `total_len` 必须与实际输入长度一致。
- `reserved` 任一字节非零必须拒绝。

## 5. 与 v1 差异
- 删除 `sigma_com` 序列化字段。
- 增加 `public_input_digest` 与 `statement_version`，强化语句绑定。
- 保持“版本升级而非复用 reserved 扩语义”的策略。

## 6. M13 验收标准
- 编解码可对称往返（encode/decode 一致）。
- 关键篡改（`magic/header_len/total_len/proof_len/reserved`）均被拒绝。
- 结构层不泄露私有签名字段。
