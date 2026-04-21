# C -> Rust 约束映射表 v1（执行中）

## 1. 说明
- 目的：把 C 侧 `air_verify_full` 语义逐项映射到 Rust AIR/验证逻辑。
- 状态标记：
  - `done`：已在 Rust 侧有对应实现；
  - `wip`：进行中；
  - `todo`：尚未落地。

## 2. 映射项
| C 侧语义项 | C 参考实现 | Rust 对应位置 | 状态 |
|---|---|---|---|
| `verify_com(pk, com, sigma)` 有效性 | `air_verify_full.c` | `ffi_v2_strict` 前置验签 | done |
| `trace_verify_com` 重放一致性 | `air_verify_full.c` | Rust statement 派生统一 + trace_digest/witness_rows/trace_calls 绑定到 commitment | done |
| witness row 重建一致性 | `witness_builder.c` + `air_verify_full.c` | Rust commitment 绑定 `witness_rows` + 篡改拒绝测试 | done |
| 模块约束：PRF/THASH/HASH_MESSAGE | `air_verify_full.c` | C guard（`ffi_v2_strict`）+ Rust AIR 内生 `trace_calls/row_count/module_acc/prf_acc/thash_acc/hmsg_acc/addr_acc/thash_rule_acc/prf_rule_acc/hmsg_rule_acc/rule_mix_acc` 约束 + `THASH(inblocks/addr_type)`、`PRF_ADDR(addr_type)`、`HASH_MESSAGE(mode)` 白名单约束（inblocks∈{1,2,3}, addr_type∈{0..4}, mode∈{0..3}, profile∈{0..2}） + statement 绑定 | done（守卫级 + AIR内生部分） |
| 根绑定（top merkle root == pk root） | `air_verify_full.c` | C guard（root binding）+ Rust AIR 内生 `root_hint` 公开输入与断言绑定 | done（守卫级 + AIR内生部分） |
| proof bytes + statement -> commitment 一致性 | `pi_F_v2` 规范 + verify | Rust verify 重算 `H(proof_bytes, public_input_digest, ctx_binding)` | done |
| `public_ctx` 绑定 | `ctx_binding` 校验 | Rust verify 重算 `ctx_binding` | done |

## 3. 收口状态（当前）
1. 模块约束内生：已完成工程定义下的核心收口（分项累积 + 规则耦合 + 跨规则 `rule_mix` + 白名单约束 + statement/commitment 绑定）。
2. 一致性样本：`valid/tamper_sig/tamper_com/tamper_pk_root` 已覆盖并通过，C/Rust 结论一致。
3. 发布材料：M17 回归脚本、benchmark 采集、consistency report、release checklist 已形成闭环。

## 4. 发布后可选增强（非阻塞）
1. 将规则 hint 进一步替换为更“状态列原生推导”的约束表达，继续降低 hint 占比。
2. 在不增大证明体积过快的前提下，逐步收紧 verify 可接受策略门限。
