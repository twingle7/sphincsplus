# witness-format-v1（M6 冻结版）

## 1. 目标
- 将 `HashCall trace` 唯一展开为可进入 STARK 子系统的 witness rows。
- 冻结 `trace -> rows` 的确定性规则，避免后续 prover 与文档分叉。
- 保证在不公开 `sigma_com` 的前提下完成 witness 构造。

## 2. 输入与输出
- 输入：`spx_p2_trace`
- 输出：`spx_p2_witness_row_v1[]`

约束：
- 相同 trace 输入必须得到完全一致的 row 序列；
- 不允许在 row 中混用“字节视图”和“felts 视图”字段；
- row 中只保存 lane（u64）及其元数据，字节长度通过 `real_len` 保留。

## 3. Row 结构（v1）
- `kind`：`HEADER / INPUT_LANE / OUTPUT_LANE`
- `domain_tag`：来自 `HashCall.domain_tag`
- `lane_role`：`NONE / INPUT / OUTPUT`
- `call_index`：调用序号
- `lane_index`：当前 lane 序号（HEADER 行为 0）
- `real_len`：输入或输出真实字节长度（HEADER 行填 input_real_len）
- `lane_count`：输入或输出 lane 总数（HEADER 行填 input_lane_count）
- `addr_words[8]`：来自 `HashCall.addr_words`
- `lane_value`：当前 lane 值（HEADER 行为 0）

## 4. 唯一展开规则（trace -> rows）
对每个 `HashCall`，按固定顺序展开：

1. 追加 1 条 `HEADER` 行；
2. 追加 `input_lane_count` 条 `INPUT_LANE` 行；
3. 追加 `output_lane_count` 条 `OUTPUT_LANE` 行。

其中：
- 输入 lane 取自 `trace.lanes[input_lane_offset + i]`；
- 输出 lane 取自 `trace.lanes[output_lane_offset + i]`；
- 任一越界视为构造失败并返回错误码。

## 5. 计数规则
- 理论总行数：
- `sum_over_calls(1 + input_lane_count + output_lane_count)`
- 若调用方提供缓冲不足，构造器返回容量不足错误，不做部分成功承诺。

## 6. 元数据公开策略（M6）
- `real_len/lane_count/domain_tag/addr_words` 均作为 witness row 元数据保留；
- `sigma_com` 不进入公开对象，仅在 prover 内部构造 trace 与 witness。

## 7. 与 M7 的衔接
- M7a/M7b 可直接消费 `kind/domain_tag/lane_value` 序列；
- 后续若新增模块列，不改变本版 row 的主键语义（`call_index + kind + lane_index`）。
