#include "thash_bench.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../address.h"
#include "../context.h"
#include "../poseidon2.h"
#include "../sha2.h"

typedef struct
{
    uint32_t backend_id;
    uint32_t mode;
    uint32_t inblocks;
    uint32_t rounds;
    const uint8_t *pub_seed;
    const uint32_t *addr;
    const uint8_t *input;
    size_t input_len;
    const uint8_t *expected_output;
} spx_thash_bench_instance_raw_v1;

int spx_p2_rust_run_thash_bench_v1(spx_thash_bench_stats_v1 *out_stats,
                                   const spx_thash_bench_instance_raw_v1 *inst);
int spx_p2_rust_run_poseidon2_thash_exact_v1(spx_thash_bench_stats_v1 *out_stats,
                                             const spx_thash_bench_instance_raw_v1 *inst);
int spx_p2_rust_run_sha2_thash_exact_v1(spx_thash_bench_stats_v1 *out_stats,
                                        const spx_thash_bench_instance_raw_v1 *inst);

static void fill_seq(uint8_t *buf, size_t len, uint8_t base)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(base + (uint8_t)i);
    }
}

static void init_addr(uint32_t addr[8], uint32_t inblocks)
{
    memset(addr, 0, 8u * sizeof(uint32_t));
    set_layer_addr(addr, 3u);
    set_tree_addr(addr, 0x0123456789abcdefULL ^ (uint64_t)inblocks);
    if (inblocks == 1u)
    {
        set_type(addr, SPX_ADDR_TYPE_WOTS);
        set_chain_addr(addr, 9u);
        set_hash_addr(addr, 7u);
    }
    else if (inblocks == 2u)
    {
        set_type(addr, SPX_ADDR_TYPE_HASHTREE);
        set_tree_height(addr, 4u);
        set_tree_index(addr, 33u);
    }
    else if (inblocks == SPX_FORS_TREES)
    {
        set_type(addr, SPX_ADDR_TYPE_FORSPK);
        set_keypair_addr(addr, 19u);
    }
    else
    {
        set_type(addr, SPX_ADDR_TYPE_WOTSPK);
        set_keypair_addr(addr, 11u);
    }
}

static void sha2_seed_state_local(uint8_t state256[40], uint8_t state512[72],
                                  const uint8_t pub_seed[SPX_N])
{
    uint8_t block[SPX_SHA512_BLOCK_BYTES];
    memset(block, 0, sizeof(block));
    memcpy(block, pub_seed, SPX_N);
    sha256_inc_init(state256);
    sha256_inc_blocks(state256, block, 1u);
    sha512_inc_init(state512);
    sha512_inc_blocks(state512, block, 1u);
}

static int thash_bench_sha2_simple(uint8_t out[SPX_N],
                                   const uint8_t pub_seed[SPX_N],
                                   const uint32_t addr[8],
                                   const uint8_t *in,
                                   uint32_t inblocks)
{
    size_t msg_len = (size_t)SPX_SHA256_ADDR_BYTES + (size_t)inblocks * SPX_N;
    uint8_t *buf = (uint8_t *)malloc(msg_len);
    uint8_t state256[40];
    uint8_t state512[72];

    if (buf == 0)
    {
        return -1;
    }

    sha2_seed_state_local(state256, state512, pub_seed);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, (size_t)inblocks * SPX_N);

    if (SPX_N >= 24u && inblocks > 1u)
    {
        uint8_t outbuf[SPX_SHA512_OUTPUT_BYTES];
        sha512_inc_finalize(outbuf, state512, buf, msg_len);
        memcpy(out, outbuf, SPX_N);
    }
    else
    {
        uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
        sha256_inc_finalize(outbuf, state256, buf, msg_len);
        memcpy(out, outbuf, SPX_N);
    }

    free(buf);
    return 0;
}

static int thash_bench_poseidon2_simple(uint8_t out[SPX_N],
                                        const uint8_t pub_seed[SPX_N],
                                        const uint32_t addr[8],
                                        const uint8_t *in,
                                        uint32_t inblocks)
{
    size_t msg_len = SPX_P2_ENCODED_THASH_BYTES(inblocks);
    uint8_t *buf = (uint8_t *)malloc(msg_len);

    if (buf == 0)
    {
        return -1;
    }

    memcpy(buf, pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, (size_t)inblocks * SPX_N);
    poseidon2_hash_thash_by_inblocks(out, SPX_N, buf, msg_len, inblocks);
    free(buf);
    return 0;
}

int spx_thash_bench_prepare_instance_v1(spx_thash_bench_instance_v1 *inst,
                                        uint32_t backend_id,
                                        uint32_t mode,
                                        uint32_t inblocks,
                                        uint32_t rounds)
{
    if (inst == 0 || inblocks == 0u || inblocks > SPX_THASH_BENCH_MAX_INBLOCKS || rounds < 8u)
    {
        return -1;
    }

    memset(inst, 0, sizeof(*inst));
    inst->backend_id = backend_id;
    inst->mode = mode;
    inst->inblocks = inblocks;
    inst->rounds = rounds;

    fill_seq(inst->pub_seed, sizeof(inst->pub_seed),
             (backend_id == SPX_THASH_BENCH_BACKEND_SHA2_V1) ? 0x30u : 0x70u);
    init_addr(inst->addr, inblocks);
    fill_seq(inst->input, (size_t)inblocks * SPX_N,
             (uint8_t)(0x90u + (backend_id == SPX_THASH_BENCH_BACKEND_SHA2_V1 ? 0u : 0x20u)));

    switch (backend_id)
    {
    case SPX_THASH_BENCH_BACKEND_SHA2_V1:
        return thash_bench_sha2_simple(inst->expected_output, inst->pub_seed,
                                       inst->addr, inst->input, inblocks);
    case SPX_THASH_BENCH_BACKEND_POSEIDON2_V1:
        return thash_bench_poseidon2_simple(inst->expected_output, inst->pub_seed,
                                            inst->addr, inst->input, inblocks);
    default:
        return -1;
    }
}

int spx_thash_bench_run_v1(spx_thash_bench_stats_v1 *out_stats,
                           const spx_thash_bench_instance_v1 *inst)
{
    spx_thash_bench_instance_raw_v1 raw;

    if (out_stats == 0 || inst == 0)
    {
        return -1;
    }

    memset(&raw, 0, sizeof(raw));
    raw.backend_id = inst->backend_id;
    raw.mode = inst->mode;
    raw.inblocks = inst->inblocks;
    raw.rounds = inst->rounds;
    raw.pub_seed = inst->pub_seed;
    raw.addr = inst->addr;
    raw.input = inst->input;
    raw.input_len = (size_t)inst->inblocks * SPX_N;
    raw.expected_output = inst->expected_output;
    switch (inst->mode)
    {
    case SPX_THASH_BENCH_MODE_BENCHMARK_V1:
        return spx_p2_rust_run_thash_bench_v1(out_stats, &raw);
    case SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1:
        if (inst->backend_id != SPX_THASH_BENCH_BACKEND_POSEIDON2_V1)
        {
            return -1;
        }
        return spx_p2_rust_run_poseidon2_thash_exact_v1(out_stats, &raw);
    case SPX_THASH_BENCH_MODE_SHA2_EXACT_V1:
        if (inst->backend_id != SPX_THASH_BENCH_BACKEND_SHA2_V1)
        {
            return -1;
        }
        return spx_p2_rust_run_sha2_thash_exact_v1(out_stats, &raw);
    default:
        return -1;
    }
}

const char *spx_thash_bench_backend_name_v1(uint32_t backend_id)
{
    switch (backend_id)
    {
    case SPX_THASH_BENCH_BACKEND_SHA2_V1:
        return "sha2";
    case SPX_THASH_BENCH_BACKEND_POSEIDON2_V1:
        return "poseidon2";
    default:
        return "unknown";
    }
}

const char *spx_thash_bench_mode_name_v1(uint32_t mode)
{
    switch (mode)
    {
    case SPX_THASH_BENCH_MODE_BENCHMARK_V1:
        return "benchmark";
    case SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1:
        return "poseidon2_exact";
    case SPX_THASH_BENCH_MODE_SHA2_EXACT_V1:
        return "sha2_exact";
    default:
        return "unknown";
    }
}
