# Fischlin-Strict 技术规范 v1

## 1. 目标
- 冻结最终证明语句与接口语义，作为实现与测试唯一口径。
- 明确从当前 `Show_v2=(com,pi_f,public_ctx)` 迁移到 `Sigma=(C,pi)` 的技术边界。

## 2. 最终语句冻结

### 2.1 公开输入
- `x = (pk_sig, pk_E, m_pub, ctx_pub)`。

### 2.2 见证
- `w = (r, omega2, c, sigma')`。

### 2.3 证明关系
- `c = Com(m_pub; r)`。
- `Verify(pk_sig, c, sigma') = 1`。
- `C = Enc(pk_E, c || sigma'; omega2)`。

### 2.4 验证语义
- 验证器输入 `Sigma=(C,pi)` 与 `x`。
- 当且仅当存在见证 `w` 使三关系同时成立时，验证通过。

## 3. 对象与接口冻结

### 3.1 展示对象
- final 对象冻结为 `Sigma=(C,pi)`。
- legacy 对象仅允许通过 compat 路径处理。

### 3.2 接口边界
- `ShowProve`: 输入 witness 与公开输入，输出 `Sigma`。
- `ShowVerify`: 仅基于 `Sigma + x` 判定，不依赖 prove 前 guard 结论。
- strict 路径必须拒绝 legacy 格式。

## 4. 约束实现要求
- 三关系必须内生到统一证明语句，不允许“部分在外部检查、部分在证明内检查”的替代方案充当最终安全语义。
- 语句派生函数必须单一实现，禁止 prover/verifier 双口径。
- 证明对象绑定值（digest/commitment 类字段）必须覆盖 `C` 与完整语句上下文。

## 5. 安全与工程要求
- 隐私：公开对象不得泄露 `sigma'`、`r`、`omega2`。
- 完备性：合法 witness 必须稳定通过。
- 可靠性：任一关系被篡改必须拒绝。
- 可复现：新语句下 benchmark 与参数搜索必须可脚本化重跑。

## 6. 测试冻结口径
- 正例：
  - 合法 `w` 下 `ShowProve/ShowVerify` 通过。
- 负例（最小集合）：
  - 篡改 `C`。
  - 篡改 `m_pub` 或 `ctx_pub`。
  - 篡改 `sigma'` 导致签名关系失效。
  - 篡改 `r` 导致承诺关系失效。
  - 篡改 `omega2` 导致加密关系失效。

## 7. 数据口径冻结
- 必须重跑：
  - 约束规模、proof size、prove/verify 时间、参数搜索。
- 可作为历史对照：
  - 旧语句版本的已发布 benchmark 与参数曲线。
