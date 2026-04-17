# air-layout-v1（M7a + M7b 阶段）

## 1. 目的
- 定义 v1 在 M7a 的最小 `POSEIDON2_PERM` 约束布局。
- 先保证“单次 permutation 正确性可验证”，再扩展到 sponge 与序列级约束。

## 2. 当前范围
- 覆盖单次 `poseidon2_permute`（M7a）：
- 输入状态 `state_in[12]`
- 输出状态 `state_out[12]`
- 约束：`state_out == Permute(state_in)`
- 覆盖单次 sponge 调用（M7b）：
- `domain_tag`
- `input_lanes + input_real_len`
- `output_lanes + output_real_len`
- 约束：`output == Sponge(domain_tag, input)`

不在本阶段实现：
- 完整 FRI/STARK 证明系统；
- 多轮轨迹分列展开与低度检验；
- HashCall 序列与 verify_com 高层语义（M8/M9 再做）。

## 3. Witness 形态（M7a）
- `perm_witness_v1 = (state_in[12], state_out[12])`
- 字段类型统一为 64-bit lane，保持与 Poseidon2 后端一致。

## 4. 约束函数（M7a）
- 约束函数语义：
- `expected = poseidon2_permute(copy(state_in))`
- `violations = count(expected[i] != state_out[i])`
- 接受条件：`violations == 0`

## 5. 证明对象（M7a 占位）
- `perm_proof_v1` 字段：
- `commitment[SPX_N]`
- `constraint_count`
- `violation_count`
- `constraint_count` 当前固定为 12（每个 lane 一条等式约束）。
- `commitment` 由 `state_in || state_out` 派生域分离哈希，用于抗篡改检测与调试。

## 6. M7a 验收口径
- 对真实 `(state_in, state_out)`：
- `prove` 成功，`verify` 通过。
- 对任意篡改：
- 改 `state_out` 任一 lane -> `verify` 失败；
- 改 `state_in` 任一 lane -> `verify` 失败；
- 改 `proof.commitment` -> `verify` 失败。

## 7. Sponge 子布局（M7b）
- witness：
- `domain_tag`
- `input_lanes[i]`, `input_lane_count`, `input_real_len`
- `output_lanes[i]`, `output_lane_count`, `output_real_len`
- 约束：
- 按固定 lane->bytes 规则重建输入字节流；
- 调用 `poseidon2_hash_bytes_domain` 重算期望输出；
- 将期望输出按相同规则映射为输出字节流并比较；
- 任意输入 lane / padding / 输出 lane 篡改导致违规数 > 0。

## 8. 与后续阶段衔接
- M8 将把 permutation/sponge 子约束挂接到 `HashCall` 序列主轨迹；
- 当前 `perm_proof_v1` 与 `sponge_proof_v1` 为最小可调试 harness，不等价于最终 STARK 证明对象。
