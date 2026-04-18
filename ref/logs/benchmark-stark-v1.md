# benchmark-stark-v1（M11-P2）

## 指标口径
- `trace_calls`：`HashCall` 调用数
- `trace_lanes`：trace lane 数
- `witness_rows`：witness 行数
- `proof_bytes`：`pi_F` 字节长度
- `prove_ms`：proof 生成耗时（毫秒）
- `verify_ms`：proof 验证耗时（毫秒）

## 采集命令
```bash
make PARAMS=sphincs-poseidon2-192s THASH=simple CC=gcc test/poseidon2_stark_stats_v1
./test/poseidon2_stark_stats_v1
```

## 结果模板
| date | params | trace_calls | trace_lanes | witness_rows | proof_bytes | prove_ms | verify_ms |
|---|---|---:|---:|---:|---:|---:|---:|
| 2026-04-18 | sphincs-poseidon2-192s | TBD | TBD | TBD | TBD | TBD | TBD |
