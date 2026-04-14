# trace-spec-v0（M3 冻结版）

## 1. 目标
- 定义 v0 阶段 `HashCall` 的唯一序列化规范。
- 保证 `THASH_F/H/TL`、`HASH_MESSAGE`、`PRF_ADDR` 可无歧义落盘与复放。
- 禁止 bytes/felts 混用字段。

## 2. 记录结构
- `HashCall` 字段顺序固定如下：
- `domain_tag`
- `addr_words[8]`
- `input_real_len`
- `input_lane_count`
- `input_lane_offset`
- `output_real_len`
- `output_lane_count`
- `output_lane_offset`

其中：
- `input_lanes` 与 `output_lanes` 存储在全局 lane 池中，通过 `offset + count` 引用。
- `input_real_len`、`output_real_len` 为强制字段，用于恢复真实字节长度。

## 3. 编码规则
- lane 编码规则唯一：little-endian 8-byte 装载，尾块零扩展。
- lane 计数规则：`lane_count = (real_len + 7) / 8`。
- 调用域标签按 `poseidon2.h`：
- `PRF_ADDR(0x01)`
- `GEN_MESSAGE_RANDOM(0x02)`
- `HASH_MESSAGE(0x03)`
- `THASH_F(0x11)`
- `THASH_H(0x12)`
- `THASH_TL(0x13)`
- `COMMIT(0x20)`

## 4. addr_words 语义
- 对 `PRF_ADDR` 与 `THASH_F/H/TL`，按输入布局 `pub_seed || addr || ...` 解析 `addr_words[8]`。
- 其余域默认 `addr_words` 全零。
- 若后续输入布局变更，必须同步升级解析规则与版本号。

## 5. 采集与容量
- 采集入口：`poseidon2_hash_bytes_domain` 的 trace 回调。
- 容量上限：`MAX_CALLS` 与 `MAX_LANES`（当前在 `hash_poseidon2_adapter.h` 固定）。
- 超限行为：递增 `dropped_calls/dropped_lanes`，不中断验签流程。

## 6. 版本与兼容
- 本规范版本：`trace-spec-v0`。
- 字段语义或顺序变更时，必须：
- 新增版本号；
- 更新测试向量；
- 更新 witness 生成器解析器。

## 7. 最小一致性检查
- 任一 `HashCall` 必须满足：
- `input_lane_count == (input_real_len + 7) / 8`
- `output_lane_count == (output_real_len + 7) / 8`
- `offset + count` 不得越界 lane 池。
