# Blind Sign E2E v2（M16）

## 1. 目标
- 打通工程化闭环：`BlindIssue -> Unblind -> ShowProve -> ShowVerify`。
- 在现有代码边界内增加可链接性工程检查与失败路径断言。

## 2. 本轮落地
- 新增测试入口：`test/poseidon2_fischlin_blind_e2e_v2.c`。
- 闭环步骤：
  - Holder 生成 `com` 并提交盲签请求（工程化简版）。
  - Issuer 对 `com` 签发 `sigma_blind`。
  - Holder 执行去盲（当前为身份映射占位）并构造内部凭证。
  - Holder 调用 `show_prove` 生成展示对象。
  - Verifier 调用 `show_verify` 验证展示对象。

## 3. 可链接性工程检查
- 同一凭证在不同 `public_ctx` 下生成两个 show 对象，要求 `pi_f` 不同。
- 该检查用于工程阶段确认上下文绑定生效，不等价于完整匿名性证明。

## 4. 兼容口径
- 当前版本已切换为 `v2-strict` 路径：
  - `ShowProve` 必须生成 `pi_F_v2`；
  - `ShowVerify` 仅接受 `pi_F_v2`。
- 若后端无法提供 `pi_F_v2`（例如未启用 Rust STARK 后端），测试应失败并提示配置问题。

## 5. 风险边界
- 当前去盲流程仍为工程占位，不代表最终盲签密码学流程完备实现。
- 本轮完成的是 M16 工程闭环与断言基础，后续继续收口匿名性评估与发布口径。
