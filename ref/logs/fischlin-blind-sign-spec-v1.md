# Fischlin 盲签规范 v1（M12）

## 1. 文档目的
- 冻结 Fischlin 框架下的盲签协议语义，明确 Issuer / Holder / Verifier 三方边界。
- 约束本项目中 `SPHINCS+ + Poseidon2 + STARK` 的盲签展示流程，避免将“公开签名展示”误当作“盲签展示”。
- 为 M13 `pi_F_v2` 格式与后续端到端实现提供唯一上游协议语义。

## 2. 角色与威胁模型
- `Issuer`：签发方，持有签发密钥，不应获得可链接到最终展示会话的 Holder 隐私细节。
- `Holder`：凭证持有方，完成盲化请求、去盲化处理与展示证明生成。
- `Verifier`：只验证展示对象，不应获得签名本体 `sigma_com`。

最小威胁模型：
- 防伪造：攻击者不能在未知有效 witness 的条件下伪造可通过验证的展示对象。
- 防泄露：展示对象不泄露 `sigma_com`、`m`、`r`。
- 防链接：Issuer 视角难以将盲签发放阶段与后续展示阶段稳定链接到同一用户会话。

## 3. 协议对象
- 内部私有 witness：`(m, r, sigma_com, trace, aux)`。
- 公开输入：`(pk, com, public_ctx)`。
- 展示对象：`Show_v2 = (com, pi_F_v2, public_ctx)`。

强约束：
- `pi_F_v2` 禁止包含 `sigma_com` 明文字段。
- `public_ctx` 仅承载公开绑定语义，不得承载私密 witness 数据。

## 4. 抽象流程
1. `BlindIssue-Request`：Holder 生成盲化请求并发送给 Issuer。
2. `BlindIssue-Sign`：Issuer 对盲化对象执行签发，返回盲签结果。
3. `Unblind`：Holder 去盲化得到可用于内部证明构造的签名 witness。
4. `ShowProve`：Holder 生成 `Show_v2`，输出 `com + pi_F_v2 + public_ctx`。
5. `ShowVerify`：Verifier 对 `Show_v2` 做验证，获得接受/拒绝结论。

## 5. 与现有工程接口映射
- `Commit` 语义保持：`com = Commit(m || r)`。
- `verify_com` / `trace_verify_com` 保持 prover 内部 helper 角色。
- `show` 层仅处理 `Show_v2`，不暴露 `sigma_com`。

## 6. 一致性约束
- 协议一致性：盲签流程语义必须与展示证明语义一致。
- 后端一致性：C 与 Rust 后端在相同公开输入上给出相同接受/拒绝结果。
- 语句一致性：`ShowVerify` 结论等价于“存在有效 witness”。

## 7. M12 验收标准
- 可用本规范单独回答“为何该实现满足盲签而非普通展示签名”。
- 工程对象边界清晰：公开对象不含 `sigma_com`。
- 协议流程、角色职责、威胁模型和接口映射无冲突。
