#ifndef SPX_THASH_BENCH_H
#define SPX_THASH_BENCH_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

#define SPX_THASH_BENCH_BACKEND_SHA2_V1 1u
#define SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 2u
#define SPX_THASH_BENCH_MODE_BENCHMARK_V1 0u
#define SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1 1u
#define SPX_THASH_BENCH_MODE_SHA2_EXACT_V1 2u
#define SPX_THASH_BENCH_MAX_INBLOCKS SPX_WOTS_LEN

typedef struct
{
    uint32_t backend_id;
    uint32_t mode;
    uint32_t inblocks;
    uint32_t rounds;
    uint8_t pub_seed[SPX_N];
    uint32_t addr[8];
    uint8_t input[SPX_THASH_BENCH_MAX_INBLOCKS * SPX_N];
    uint8_t expected_output[SPX_N];
} spx_thash_bench_instance_v1;

typedef struct
{
    uint32_t backend_id;
    uint32_t mode;
    uint32_t inblocks;
    uint32_t rounds;
    uint32_t trace_width;
    uint32_t trace_length;
    uint32_t transition_constraints;
    uint32_t boundary_assertions;
    uint64_t constraint_eval_total;
    uint64_t proof_bytes;
    double prove_ms;
    double verify_ms;
    uint32_t exact_primitive_calls;
    uint32_t exact_round_rows;
    uint64_t input_mix;
    uint64_t output_mix;
    uint64_t result_tag;
} spx_thash_bench_stats_v1;

int spx_thash_bench_prepare_instance_v1(spx_thash_bench_instance_v1 *inst,
                                        uint32_t backend_id,
                                        uint32_t mode,
                                        uint32_t inblocks,
                                        uint32_t rounds);

int spx_thash_bench_run_v1(spx_thash_bench_stats_v1 *out_stats,
                           const spx_thash_bench_instance_v1 *inst);

const char *spx_thash_bench_backend_name_v1(uint32_t backend_id);
const char *spx_thash_bench_mode_name_v1(uint32_t mode);

#endif
