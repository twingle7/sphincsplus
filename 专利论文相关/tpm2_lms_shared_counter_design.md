# 多个 LMS 签名密钥共享单个 TPM2 Counter 的状态管理方法

技术方案简报

目标：在 TPM2 NV counter 数量有限的条件下，保障多个 LMS 签名密钥状态的独立性、不可回滚性与安全性。

## 核心结论

不要把一个 TPM2 counter 直接切分成多个 LMS counter。更稳妥的方法是把它作为全局不可回滚提交序号，并用认证 append-only 状态账本维护每个 LMS 密钥各自的 `next_q`。崩溃时宁可烧掉一段 LMS leaf，也不能允许 leaf 复用。

## 1. 方法要解决的问题

LMS/HSS 属于 stateful hash-based signature。它的安全性依赖一个强约束：同一个 LMS 私钥下的同一个 leaf index `q` 只能用于一次签名。如果某个 `q` 被重复用于不同消息，攻击者可能获得足够结构信息来破坏该一次性签名实例，进而影响该 LMS 公钥下签名的可靠性。

在普通文件系统中保存 `next_q` 很容易遇到回滚问题。攻击者可以恢复旧快照，或者系统崩溃导致状态文件与实际已发出的签名不一致。一旦软件状态回到旧值，签名服务就可能再次使用已消耗的 `q`。

TPM2 NV counter 可以提供硬件保护的单调递增状态，但设备可用 counter 数量通常很少，不适合为每个 LMS 私钥单独分配一个 TPM counter。实际系统又可能有多种用途、多个业务租户、多个签名密钥、多个 HSS 层级或轮换密钥。因此需要一个方法，让多个不同 LMS 签名密钥共享同一个 TPM2 counter，同时仍然保持每个密钥状态独立。

该方法要解决四类目标：

- 安全目标一：任何 LMS key 下的 `q` 不得被重复用于签名。
- 安全目标二：攻击者不能通过回滚本地状态文件，让签名服务回到旧的 `next_q`。
- 安全目标三：一个 key 的状态消耗、耗尽或误用不能污染另一个 key 的 `q` 空间。
- 工程目标：减少 TPM NV counter 数量占用，并降低 TPM NV 写入频率对性能和寿命的影响。

## 2. 核心思路

该方法把单个 TPM2 NV counter 定义为全局提交时钟 `G`。`G` 不表示任何一个 LMS key 的 `q`，而是表示“系统已经完成了第几个不可回滚的状态提交”。所有 LMS key 的 `next_q` 仍保存在软件账本中，但账本的每次状态变更都必须绑定一个新的 TPM counter 值。

账本 `L` 采用 append-only 结构。每条记录包含：

```text
record = {
  seq: TPM counter value,
  key_id: H(LMS public key || params || key generation id),
  q_start: 本次预留的 LMS leaf index,
  q_count: 预留数量，通常为 1，也可批量预留,
  prev_hash: 前一条账本记录 hash,
  state_after: 该 key 的 next_q 更新后摘要,
  mac: HMAC_Klog(all fields)
}
```

其中 `Klog` 是日志认证密钥，应由 TPM sealed key 保护，只允许受信签名服务在正确 policy/PCR 条件下解封。LMS 私钥种子也应由 TPM sealed key、HSM、TEE 或其他密钥保护机制独立保护。

字段作用如下：

| 字段 | 含义 | 安全作用 |
| --- | --- | --- |
| `seq` | TPM2 NV counter 递增后的全局序号 | 把软件状态提交绑定到不可回滚硬件状态 |
| `key_id` | `H(LMS public key || params || generation id)` | 隔离不同 LMS key 的状态命名空间 |
| `q_start`, `q_count` | 本次预留的 leaf 区间 | 允许单次预留或批量预留，崩溃后整体视为已消耗 |
| `prev_hash` | 上一条账本记录哈希 | 防止删除、重排或截断中间记录 |
| `state_after` | 该 key 更新后的 `next_q` 摘要 | 便于恢复和审计每个 key 的状态 |
| `mac` | `HMAC_Klog(record fields)` | 防止离线伪造账本记录 |

## 3. 签名与恢复流程

### 3.1 签名流程

1. 签名服务对全局状态管理器加锁，确保同一时刻只有一个分配动作修改账本。
2. 从账本恢复目标 `key_id` 的 `next_q`，并检查 `next_q + q_count` 不超过该 LMS 参数集的 leaf 上限。
3. 调用 `TPM2_NV_Increment(G)`，让全局 counter 前进一次。
4. 读取新的 counter 值 `seq`，并写入 reserve 账本记录：`key_id`、`q_start`、`q_count`、`seq`、`prev_hash`、`state_after`、`mac`。
5. 账本记录落盘并 `fsync` 成功后，才用 `q_start` 对消息执行 LMS 签名。
6. 如果签名过程中崩溃，恢复时该 `q` 或该 `q` 区间仍视为已消耗，只允许跳过，不允许重用。

顺序原则：必须先预留并持久化 leaf，再生成或释放签名结果。这个顺序把故障后果限制为 leaf 浪费，而不是 leaf 复用。

### 3.2 恢复流程

1. 启动时读取 TPM counter 当前值 `G_now`。
2. 校验账本哈希链和 HMAC，得到账本中最大 `seq`：`L_last`。
3. 若 `L_last == G_now`，按账本恢复所有 key 的 `next_q`。
4. 若 `L_last < G_now`，说明 TPM 已经前进但账本缺失尾部记录，系统无法判断哪些 `q` 已经预留，必须 fail-stop 或从远程备份恢复。
5. 若 `L_last > G_now`，说明账本来自未来、TPM 被替换，或者出现回滚/迁移错误，也必须 fail-stop。

## 4. 安全性分析

该设计的关键是职责分离：TPM counter 只承担不可回滚时钟，账本承担多 key 状态索引，LMS 私钥材料仍由密钥保护机制独立保护。共享 counter 不参与任何 LMS 私钥派生，因此不会把不同 key 的密码学安全性耦合在一起。

安全性可以从以下角度理解：

- 防 leaf 复用：账本记录 `q` 预留区间，恢复时只会推进 `next_q`，不会倒退。
- 防状态回滚：账本最大 `seq` 必须与 TPM counter 当前值匹配；旧账本无法通过检查。
- 防跨 key 干扰：每个 `key_id` 有独立 `next_q`，某个 key 的 `q` 消耗不会改变其他 key 的 `q`。
- 防伪造账本：`HMAC_Klog` 和哈希链阻止攻击者伪造、删除或重排状态记录。
- 故障安全：崩溃后可以浪费 `q` 或一个预留块，但不能重新使用已可能暴露的 `q`。

该方法不能防止所有 DoS。攻击者如果能调用签名服务或触发预留流程，仍可能消耗某个 key 的 leaf 或推进全局 counter。因此服务端还需要访问控制、配额、审计和异常速率检测。但这类问题属于可用性与资源耗尽，不等价于签名伪造。

## 5. 可选方案比较

| 方案 | 做法 | 优点 | 主要风险或代价 |
| --- | --- | --- | --- |
| 每个 key 一个 TPM counter | 为每个 LMS key 建一个独立 NV counter | 模型最直观，恢复逻辑简单 | counter 数量不足；NV 资源占用高；密钥轮换后资源管理复杂 |
| 单 counter + 认证账本 | 本文方案，用全局 `seq` 保护多 key `next_q` | 节省 TPM counter；key 状态独立；容易审计 | 需要可靠账本、`fsync`、备份和 fail-stop 策略 |
| 批量预留 leaf | 一次 counter increment 预留一段 `q` | 显著降低 TPM 调用频率，适合高吞吐 | 崩溃时浪费整段 leaf；块大小需要按业务调参 |
| 远程状态服务 | 集中式服务维护 `next_q` 和防回滚日志 | 便于多节点共享与集中审计 | 引入在线依赖；服务本身必须强一致和高可用 |
| TEE/安全元件状态 | 用 TEE monotonic counter 或安全元件替代 TPM counter | 可根据平台选择更快或更多 counter | 平台差异大；可信计算边界与认证方式需重做 |
| 仅文件锁 + 本地数据库 | 用 SQLite/WAL 等本地事务保存 `next_q` | 实现简单，性能好 | 不能抵抗有权限攻击者或磁盘快照回滚 |

## 6. 推荐的工程化变体

### 6.1 小规模高安全场景

每次签名预留一个 `q`，`q_count = 1`。该模式浪费最少、状态最清晰，适合根证书、固件发布、低频代码签名等场景。缺点是每次签名都需要一次 TPM counter increment，吞吐量受限。

### 6.2 高吞吐签名服务

采用批量预留，例如 `q_count = 32`、`128` 或 `1024`。服务在内存中消耗预留块，块耗尽后再递增 TPM counter 并追加新记录。批量大小应由签名频率、可接受 leaf 浪费、TPM 性能、LMS 树高和密钥轮换周期共同决定。

### 6.3 多节点部署

如果多个节点共享同一 LMS key，不能让每个节点各自维护本地 `next_q`。应由一个 leader 签名服务集中分配 `q`，或者让远程状态服务统一预留 `q` 区间。每个节点只能使用被分配给自己的 `q` 块，且必须在签名结果对外可见前完成持久化记录。

## 7. 应用案例

### 案例一：固件发布系统

厂商可能为不同产品线、不同发布通道、不同安全等级维护多个 LMS/HSS 签名密钥。TPM counter 数量不足以一一对应，但可以由发布服务使用一个 TPM counter 保护所有密钥的签名状态账本。

### 案例二：离线根签名机

根签名机通常签名频率低但安全要求高。可以将每次 `q` 预留与一次 TPM counter increment 绑定，并把账本导出到只追加介质或远程审计系统中。

### 案例三：多租户代码签名服务

每个租户拥有不同 LMS key，服务平台使用同一个硬件 TPM counter 保护全局状态提交序号。租户之间通过 `key_id`、访问控制和 per-key `next_q` 完成隔离。

### 案例四：后量子迁移阶段的混合签名网关

系统可能同时维护传统签名密钥和 LMS/HSS 备份签名密钥。共享 counter 方案可作为 LMS 状态管理子系统，嵌入现有签名网关或 CI/CD 发布流水线。

## 8. 实施注意事项

- TPM counter 的写权限应绑定到签名服务身份或 PCR policy，普通业务进程不能直接递增 counter。
- 账本写入必须使用 append-only 语义、强制落盘，并定期复制到远程只追加存储。
- LMS 私钥种子和 `Klog` 应分别保护，避免日志认证密钥泄露后攻击者能伪造状态记录。
- 恢复检查必须 fail-stop。发现 counter 与账本不一致时，不应自动猜测修复。
- 签名 API 不应暴露 `q`。外部调用者只提交 `key_id` 与消息，由签名服务内部完成 `q` 分配。
- 应为每个 key 设置 leaf 余量告警、签名配额和轮换流程，防止耗尽后业务中断。

## 9. 参考规范

- TCG TPM 2.0 Library Specification, Part 2: Structures，关于 NV Index 类型和 `TPM_NT_COUNTER`。
- TCG TPM 2.0 Library Specification, Part 3: Commands，关于 `TPM2_NV_Increment`。
- RFC 8554: Leighton-Micali Hash-Based Signatures，关于 LMS/HSS 签名状态与私钥更新要求。
- NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes，关于 stateful hash-based signature 的使用约束。
