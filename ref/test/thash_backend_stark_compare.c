#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../address.h"
#include "../params.h"
#include "../stark/thash_bench.h"

static uint32_t env_u32(const char *name, uint32_t default_value)
{
    const char *value = getenv(name);
    char *end = 0;
    unsigned long parsed;

    if (value == 0 || *value == '\0')
    {
        return default_value;
    }
    parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0')
    {
        return default_value;
    }
    return (uint32_t)parsed;
}

static uint32_t env_mode(void)
{
    const char *value = getenv("SPX_THASH_BENCH_MODE");

    if (value == 0 || *value == '\0')
    {
        return SPX_THASH_BENCH_MODE_BENCHMARK_V1;
    }
    if (strcmp(value, "benchmark") == 0)
    {
        return SPX_THASH_BENCH_MODE_BENCHMARK_V1;
    }
    if (strcmp(value, "poseidon2_exact") == 0)
    {
        return SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1;
    }
    if (strcmp(value, "sha2_exact") == 0)
    {
        return SPX_THASH_BENCH_MODE_SHA2_EXACT_V1;
    }
    return SPX_THASH_BENCH_MODE_BENCHMARK_V1;
}

static void print_result(const spx_thash_bench_stats_v1 *stats)
{
    printf("thash_backend_stark_compare: backend=%s mode=%s inblocks=%u rounds=%u ",
           spx_thash_bench_backend_name_v1(stats->backend_id),
           spx_thash_bench_mode_name_v1(stats->mode),
           stats->inblocks,
           stats->rounds);
    printf("trace_width=%u trace_length=%u constraints=%u assertions=%u constraint_eval_total=%llu ",
           stats->trace_width,
           stats->trace_length,
           stats->transition_constraints,
           stats->boundary_assertions,
           (unsigned long long)stats->constraint_eval_total);
    printf("proof_bytes=%llu prove_ms=%.3f verify_ms=%.3f ",
           (unsigned long long)stats->proof_bytes,
           stats->prove_ms,
           stats->verify_ms);
    printf("exact_primitive_calls=%u exact_round_rows=%u ",
           stats->exact_primitive_calls,
           stats->exact_round_rows);
    printf("input_mix=%llu output_mix=%llu result_tag=%llu\n",
           (unsigned long long)stats->input_mix,
           (unsigned long long)stats->output_mix,
           (unsigned long long)stats->result_tag);
}

static int run_backend(uint32_t backend_id, uint32_t mode, uint32_t inblocks, uint32_t rounds)
{
    spx_thash_bench_instance_v1 inst;
    spx_thash_bench_stats_v1 stats;

    if (spx_thash_bench_prepare_instance_v1(&inst, backend_id, mode, inblocks, rounds) != 0)
    {
        printf("FAIL: prepare backend=%s mode=%s inblocks=%u rounds=%u\n",
               spx_thash_bench_backend_name_v1(backend_id),
               spx_thash_bench_mode_name_v1(mode),
               inblocks, rounds);
        return 1;
    }
    if (spx_thash_bench_run_v1(&stats, &inst) != 0)
    {
        printf("FAIL: prove backend=%s mode=%s inblocks=%u rounds=%u\n",
               spx_thash_bench_backend_name_v1(backend_id),
               spx_thash_bench_mode_name_v1(mode),
               inblocks, rounds);
        return 1;
    }
    print_result(&stats);
    return 0;
}

int main(void)
{
    uint32_t inblocks = env_u32("SPX_THASH_BENCH_INBLOCKS", 2u);
    uint32_t rounds = env_u32("SPX_THASH_BENCH_ROUNDS", 64u);
    uint32_t mode = env_mode();

    if (inblocks == 0u || inblocks > SPX_WOTS_LEN)
    {
        printf("FAIL: invalid inblocks=%u\n", inblocks);
        return 1;
    }
    if (rounds < 8u || (rounds & (rounds - 1u)) != 0u)
    {
        printf("FAIL: rounds must be power-of-two and >= 8, got %u\n", rounds);
        return 1;
    }

    if (mode == SPX_THASH_BENCH_MODE_BENCHMARK_V1)
    {
        if (run_backend(SPX_THASH_BENCH_BACKEND_SHA2_V1, mode, inblocks, rounds) != 0)
        {
            return 1;
        }
        if (run_backend(SPX_THASH_BENCH_BACKEND_POSEIDON2_V1, mode, inblocks, rounds) != 0)
        {
            return 1;
        }
        return 0;
    }
    if (mode == SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1)
    {
        return run_backend(SPX_THASH_BENCH_BACKEND_POSEIDON2_V1, mode, inblocks, rounds);
    }
    if (mode == SPX_THASH_BENCH_MODE_SHA2_EXACT_V1)
    {
        return run_backend(SPX_THASH_BENCH_BACKEND_SHA2_V1, mode, inblocks, rounds);
    }
    return 1;
}
