# Cross-Backend Consistency v1

## 1. 目标
- 在共同样本集上对齐：
  - C 侧 `verify_full` 约束守卫结论；
  - Rust strict 路径 `show_prove` 生成资格结论。

## 2. 样本集
- `valid`: 原始 `(pk, com, sig)`。
- `tamper_sig`: 篡改 `sig[0]`。
- `tamper_com`: 篡改 `com[0]`。
- `tamper_pk_root`: 篡改 `pk` 末尾 root 字节。

## 3. 判定规则
- `valid`：C=accept 且 Rust=accept。
- `tamper_sig`：C=reject 且 Rust=reject。
- `tamper_com`：C=reject 且 Rust=reject。
- `tamper_pk_root`：C=reject 且 Rust=reject。

## 4. 回归入口
- `test/poseidon2_cross_backend_consistency.c`

## 5. 说明
- 当前是一致性样本的第一版（资格对齐）。
- 已覆盖到 root 绑定相关的 `tamper_pk_root` 资格一致性样本。
- 后续继续扩展到更多模块约束样本（PRF/THASH/HASH_MESSAGE 细粒度）并形成矩阵。
