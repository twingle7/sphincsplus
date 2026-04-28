#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash_profile.h"

#if defined(SPX_BACKEND_SHAKE)
#include "fips202.h"
#endif

#if defined(SPX_BACKEND_POSEIDON2)
#include "poseidon2.h"
#endif

#if defined(SPX_BACKEND_SHA2)
#include "context.h"
#include "sha2.h"
#endif

static spx_hash_profile_stats g_stats;
static int g_enabled = 0;

static uint64_t ceil_div_u64(uint64_t num, uint64_t den)
{
    if (num == 0u)
    {
        return 0u;
    }
    return 1u + (num - 1u) / den;
}

#if defined(SPX_BACKEND_SHA2)
static uint64_t sha_blocks(uint64_t input_len, uint64_t block_bytes, uint64_t len_bytes)
{
    return ceil_div_u64(input_len + 1u + len_bytes, block_bytes);
}
#endif

#if defined(SPX_BACKEND_SHAKE)
static uint64_t shake256_permutations(uint64_t input_len, uint64_t output_len)
{
    uint64_t perms = input_len / SHAKE256_RATE + 1u;
    uint64_t squeeze_blocks = ceil_div_u64(output_len, SHAKE256_RATE);
    if (squeeze_blocks > 1u)
    {
        perms += squeeze_blocks - 1u;
    }
    return perms;
}
#endif

#if defined(SPX_BACKEND_POSEIDON2)
static uint64_t poseidon2_permutations(uint64_t input_len, uint64_t output_len)
{
    uint64_t perms = input_len / SPX_POSEIDON2_RATE_BYTES + 1u;
    uint64_t squeeze_blocks = ceil_div_u64(output_len, SPX_POSEIDON2_RATE_BYTES);
    if (squeeze_blocks > 1u)
    {
        perms += squeeze_blocks - 1u;
    }
    return perms;
}
#endif

static void report_backend(char out_backend[16], char out_thash_mode[8],
                           const spx_hash_profile_stats *stats)
{
#if defined(SPX_BACKEND_SHA2)
    (void)stats;
    memcpy(out_backend, "sha2", 5u);
#elif defined(SPX_BACKEND_SHAKE)
    (void)stats;
    memcpy(out_backend, "shake", 6u);
#elif defined(SPX_BACKEND_POSEIDON2)
    (void)stats;
    memcpy(out_backend, "poseidon2", 10u);
#elif defined(SPX_BACKEND_HARAKA)
    (void)stats;
    memcpy(out_backend, "haraka", 7u);
#else
    memcpy(out_backend, "unknown", 8u);
#endif

    if (stats->thash_robust_calls != 0u)
    {
        memcpy(out_thash_mode, "robust", 7u);
    }
    else
    {
        memcpy(out_thash_mode, "simple", 7u);
    }
}

void spx_hash_profile_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

void spx_hash_profile_set_enabled(int enabled)
{
    g_enabled = (enabled != 0) ? 1 : 0;
}

int spx_hash_profile_get_enabled(void)
{
    return g_enabled;
}

void spx_hash_profile_note_thash(unsigned int inblocks, size_t input_bytes,
                                 int is_robust)
{
    unsigned int bucket = inblocks;

    if (g_enabled == 0)
    {
        return;
    }
    if (bucket > SPX_HASH_PROFILE_MAX_INBLOCKS)
    {
        bucket = SPX_HASH_PROFILE_MAX_INBLOCKS;
    }
    g_stats.thash_calls++;
    g_stats.thash_input_bytes += (uint64_t)input_bytes;
    g_stats.thash_inblocks[bucket]++;
    if (is_robust != 0)
    {
        g_stats.thash_robust_calls++;
    }
    else
    {
        g_stats.thash_simple_calls++;
    }
}

void spx_hash_profile_note_prf_addr(size_t input_bytes)
{
    if (g_enabled == 0)
    {
        return;
    }
    g_stats.prf_addr_calls++;
    g_stats.prf_addr_input_bytes += (uint64_t)input_bytes;
}

void spx_hash_profile_note_hash_message(size_t input_bytes, size_t output_bytes)
{
    if (g_enabled == 0)
    {
        return;
    }
    g_stats.hash_message_calls++;
    g_stats.hash_message_input_bytes += (uint64_t)input_bytes;
    g_stats.hash_message_output_bytes += (uint64_t)output_bytes;
}

void spx_hash_profile_note_gen_message_random(size_t input_bytes, size_t output_bytes)
{
    if (g_enabled == 0)
    {
        return;
    }
    g_stats.gen_message_random_calls++;
    g_stats.gen_message_random_input_bytes += (uint64_t)input_bytes;
    g_stats.gen_message_random_output_bytes += (uint64_t)output_bytes;
}

void spx_hash_profile_snapshot(spx_hash_profile_stats *out_stats)
{
    if (out_stats == 0)
    {
        return;
    }
    *out_stats = g_stats;
}

void spx_hash_profile_default_cost_model(spx_hash_profile_cost_model *out_model)
{
    if (out_model == 0)
    {
        return;
    }
    out_model->sha256_compression_cost = 25000u;
    out_model->sha512_compression_cost = 45000u;
    out_model->shake256_permutation_cost = 24000u;
    out_model->poseidon2_permutation_cost = 850u;
    out_model->haraka512_cost = 1200u;
    out_model->haraka256_cost = 700u;
    out_model->haraka_s_cost = 1200u;
}

void spx_hash_profile_build_report(spx_hash_profile_report *out_report,
                                   const spx_hash_profile_cost_model *model)
{
    spx_hash_profile_cost_model local_model;
    uint64_t i;

    if (out_report == 0)
    {
        return;
    }
    if (model == 0)
    {
        spx_hash_profile_default_cost_model(&local_model);
        model = &local_model;
    }

    memset(out_report, 0, sizeof(*out_report));
    out_report->exact = g_stats;
    report_backend(out_report->backend, out_report->thash_mode, &g_stats);

    for (i = 0; i <= SPX_HASH_PROFILE_MAX_INBLOCKS; i++)
    {
        uint64_t count = g_stats.thash_inblocks[i];
        uint64_t inblocks = i;
        if (count == 0u)
        {
            continue;
        }
        if (inblocks == SPX_HASH_PROFILE_MAX_INBLOCKS)
        {
            inblocks = SPX_HASH_PROFILE_MAX_INBLOCKS;
        }

#if defined(SPX_BACKEND_SHA2)
#if SPX_SHA512
        {
            const uint64_t block_bytes = SPX_SHA512_BLOCK_BYTES;
            const uint64_t len_bytes = 16u;
            const uint64_t digest_bytes = SPX_SHA512_OUTPUT_BYTES;
            const uint64_t final_blocks = sha_blocks((uint64_t)SPX_SHA256_ADDR_BYTES + inblocks * (uint64_t)SPX_N,
                                                     block_bytes, len_bytes);
            out_report->estimated_sha512_compressions += count * final_blocks;
            if (g_stats.thash_robust_calls != 0u)
            {
                const uint64_t mgf_iters = ceil_div_u64(inblocks * (uint64_t)SPX_N, digest_bytes);
                const uint64_t mgf_blocks = sha_blocks((uint64_t)SPX_N + (uint64_t)SPX_SHA256_ADDR_BYTES + 4u,
                                                       block_bytes, len_bytes);
                out_report->estimated_sha512_compressions += count * mgf_iters * mgf_blocks;
            }
        }
#else
        {
            const uint64_t block_bytes = SPX_SHA256_BLOCK_BYTES;
            const uint64_t len_bytes = 8u;
            const uint64_t digest_bytes = SPX_SHA256_OUTPUT_BYTES;
            const uint64_t final_blocks = sha_blocks((uint64_t)SPX_SHA256_ADDR_BYTES + inblocks * (uint64_t)SPX_N,
                                                     block_bytes, len_bytes);
            out_report->estimated_sha256_compressions += count * final_blocks;
            if (g_stats.thash_robust_calls != 0u)
            {
                const uint64_t mgf_iters = ceil_div_u64(inblocks * (uint64_t)SPX_N, digest_bytes);
                const uint64_t mgf_blocks = sha_blocks((uint64_t)SPX_N + (uint64_t)SPX_SHA256_ADDR_BYTES + 4u,
                                                       block_bytes, len_bytes);
                out_report->estimated_sha256_compressions += count * mgf_iters * mgf_blocks;
            }
        }
#endif
#elif defined(SPX_BACKEND_SHAKE)
        {
            const uint64_t final_input = (uint64_t)SPX_N + (uint64_t)SPX_ADDR_BYTES + inblocks * (uint64_t)SPX_N;
            out_report->estimated_shake256_permutations += count * shake256_permutations(final_input, SPX_N);
            if (g_stats.thash_robust_calls != 0u)
            {
                const uint64_t bitmask_input = (uint64_t)SPX_N + (uint64_t)SPX_ADDR_BYTES;
                out_report->estimated_shake256_permutations +=
                    count * shake256_permutations(bitmask_input, inblocks * (uint64_t)SPX_N);
            }
        }
#elif defined(SPX_BACKEND_POSEIDON2)
        {
            const uint64_t final_input = (uint64_t)SPX_P2_ENCODED_THASH_BYTES(inblocks);
            out_report->estimated_poseidon2_permutations += count * poseidon2_permutations(1u + final_input, SPX_N);
        }
#elif defined(SPX_BACKEND_HARAKA)
        if (g_stats.thash_robust_calls != 0u)
        {
            if (inblocks == 1u)
            {
                out_report->estimated_haraka256_calls += count;
                out_report->estimated_haraka512_calls += count;
            }
            else
            {
                out_report->estimated_haraka_s_calls += 2u * count;
            }
        }
        else
        {
            if (inblocks == 1u)
            {
                out_report->estimated_haraka512_calls += count;
            }
            else
            {
                out_report->estimated_haraka_s_calls += count;
            }
        }
#endif
    }

#if defined(SPX_BACKEND_SHA2)
#if SPX_SHA512
    out_report->estimated_sha512_compressions +=
        g_stats.prf_addr_calls * sha_blocks((uint64_t)SPX_SHA256_ADDR_BYTES + (uint64_t)SPX_N,
                                            SPX_SHA512_BLOCK_BYTES, 16u);
    out_report->estimated_sha512_compressions +=
        g_stats.hash_message_calls * sha_blocks((uint64_t)SPX_N + (uint64_t)SPX_PK_BYTES + (uint64_t)SPX_N,
                                                SPX_SHA512_BLOCK_BYTES, 16u);
    out_report->estimated_sha512_compressions +=
        g_stats.hash_message_calls *
        ceil_div_u64((uint64_t)SPX_FORS_MSG_BYTES + (uint64_t)((SPX_TREE_HEIGHT * (SPX_D - 1) + 7) / 8) +
                         (uint64_t)((SPX_TREE_HEIGHT + 7) / 8),
                     SPX_SHA512_OUTPUT_BYTES) *
        sha_blocks((uint64_t)(2 * SPX_N) + (uint64_t)SPX_SHA512_OUTPUT_BYTES + 4u,
                   SPX_SHA512_BLOCK_BYTES, 16u);
#else
    out_report->estimated_sha256_compressions +=
        g_stats.prf_addr_calls * sha_blocks((uint64_t)SPX_SHA256_ADDR_BYTES + (uint64_t)SPX_N,
                                            SPX_SHA256_BLOCK_BYTES, 8u);
    out_report->estimated_sha256_compressions +=
        g_stats.hash_message_calls * sha_blocks((uint64_t)SPX_N + (uint64_t)SPX_PK_BYTES + (uint64_t)SPX_N,
                                                SPX_SHA256_BLOCK_BYTES, 8u);
    out_report->estimated_sha256_compressions +=
        g_stats.hash_message_calls *
        ceil_div_u64((uint64_t)SPX_FORS_MSG_BYTES + (uint64_t)((SPX_TREE_HEIGHT * (SPX_D - 1) + 7) / 8) +
                         (uint64_t)((SPX_TREE_HEIGHT + 7) / 8),
                     SPX_SHA256_OUTPUT_BYTES) *
        sha_blocks((uint64_t)(2 * SPX_N) + (uint64_t)SPX_SHA256_OUTPUT_BYTES + 4u,
                   SPX_SHA256_BLOCK_BYTES, 8u);
#endif
#elif defined(SPX_BACKEND_SHAKE)
    out_report->estimated_shake256_permutations +=
        g_stats.prf_addr_calls * shake256_permutations((uint64_t)(2 * SPX_N + SPX_ADDR_BYTES), SPX_N);
    out_report->estimated_shake256_permutations +=
        g_stats.hash_message_calls * shake256_permutations((uint64_t)SPX_N + (uint64_t)SPX_PK_BYTES + (uint64_t)SPX_N,
                                                           (uint64_t)SPX_FORS_MSG_BYTES +
                                                               (uint64_t)((SPX_TREE_HEIGHT * (SPX_D - 1) + 7) / 8) +
                                                               (uint64_t)((SPX_TREE_HEIGHT + 7) / 8));
#elif defined(SPX_BACKEND_POSEIDON2)
    out_report->estimated_poseidon2_permutations +=
        g_stats.prf_addr_calls * poseidon2_permutations(1u + (uint64_t)SPX_P2_ENCODED_PRF_ADDR_BYTES, SPX_N);
    out_report->estimated_poseidon2_permutations +=
        g_stats.hash_message_calls * poseidon2_permutations(1u + (uint64_t)SPX_N + (uint64_t)SPX_PK_BYTES + (uint64_t)SPX_N,
                                                            (uint64_t)SPX_FORS_MSG_BYTES +
                                                                (uint64_t)((SPX_TREE_HEIGHT * (SPX_D - 1) + 7) / 8) +
                                                                (uint64_t)((SPX_TREE_HEIGHT + 7) / 8));
#elif defined(SPX_BACKEND_HARAKA)
    out_report->estimated_haraka512_calls += g_stats.prf_addr_calls;
    out_report->estimated_haraka_s_calls += g_stats.hash_message_calls;
#endif

    out_report->estimated_constraints =
        out_report->estimated_sha256_compressions * model->sha256_compression_cost +
        out_report->estimated_sha512_compressions * model->sha512_compression_cost +
        out_report->estimated_shake256_permutations * model->shake256_permutation_cost +
        out_report->estimated_poseidon2_permutations * model->poseidon2_permutation_cost +
        out_report->estimated_haraka512_calls * model->haraka512_cost +
        out_report->estimated_haraka256_calls * model->haraka256_cost +
        out_report->estimated_haraka_s_calls * model->haraka_s_cost;
}
