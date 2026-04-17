#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../address.h"
#include "../poseidon2.h"
#include "air_hashcall.h"
#include "air_verify_full.h"

static int trace_equal(const spx_p2_trace *a, const spx_p2_trace *b)
{
    size_t i;
    if (a->call_count != b->call_count ||
        a->lane_count != b->lane_count ||
        a->dropped_calls != b->dropped_calls ||
        a->dropped_lanes != b->dropped_lanes)
    {
        return 0;
    }
    for (i = 0; i < a->call_count; i++)
    {
        if (memcmp(&a->calls[i], &b->calls[i], sizeof(spx_p2_hash_call)) != 0)
        {
            return 0;
        }
    }
    for (i = 0; i < a->lane_count; i++)
    {
        if (a->lanes[i] != b->lanes[i])
        {
            return 0;
        }
    }
    return 1;
}

static int domain_tag_is_allowed(uint8_t domain_tag)
{
    if (domain_tag == SPX_P2_DOMAIN_PRF_ADDR ||
        domain_tag == SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM ||
        domain_tag == SPX_P2_DOMAIN_HASH_MESSAGE ||
        domain_tag == SPX_P2_DOMAIN_THASH_SIMPLE ||
        domain_tag == SPX_P2_DOMAIN_THASH_F ||
        domain_tag == SPX_P2_DOMAIN_THASH_H ||
        domain_tag == SPX_P2_DOMAIN_THASH_TL ||
        domain_tag == SPX_P2_DOMAIN_COMMIT ||
        domain_tag == SPX_P2_DOMAIN_CUSTOM)
    {
        return 1;
    }
    return 0;
}

static size_t bytes_to_lanes(size_t len)
{
    return (len + 7u) / 8u;
}

static uint8_t addr_get_byte(const uint32_t addr_words[8], size_t byte_index)
{
    size_t word = byte_index / 4u;
    size_t shift = (byte_index % 4u) * 8u;
    return (uint8_t)((addr_words[word] >> shift) & 0xffu);
}

static uint8_t addr_get_type(const uint32_t addr_words[8])
{
    return addr_get_byte(addr_words, SPX_OFFSET_TYPE);
}

static uint8_t addr_get_tree_height(const uint32_t addr_words[8])
{
    return addr_get_byte(addr_words, SPX_OFFSET_TREE_HGT);
}

static void lanes_to_bytes_from_trace(uint8_t *out, size_t outlen,
                                      const spx_p2_trace *trace,
                                      uint32_t lane_offset)
{
    size_t i;
    size_t lane_count = bytes_to_lanes(outlen);
    for (i = 0; i < outlen; i++)
    {
        size_t lane_idx = i / 8u;
        size_t byte_idx = i % 8u;
        uint64_t lane = trace->lanes[lane_offset + (uint32_t)lane_idx];
        out[i] = (uint8_t)((lane >> (8u * byte_idx)) & 0xffu);
    }
    (void)lane_count;
}

static int thash_inblocks_from_input_len(size_t input_real_len, size_t *out_inblocks)
{
    const size_t base = (size_t)SPX_N + (size_t)SPX_ADDR_BYTES;
    size_t payload = 0;
    if (input_real_len < base + (size_t)SPX_N || out_inblocks == 0)
    {
        return -1;
    }
    payload = input_real_len - base;
    if ((payload % (size_t)SPX_N) != 0)
    {
        return -1;
    }
    *out_inblocks = payload / (size_t)SPX_N;
    return 0;
}

int spx_p2_verify_full_air_eval_module_constraints_v1(const spx_p2_trace *trace,
                                                      uint32_t *out_constraint_count,
                                                      uint32_t *out_violation_count)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    uint32_t cnt_fors = 0;
    uint32_t cnt_wots = 0;
    uint32_t cnt_merkle = 0;
    uint32_t cnt_top_merkle = 0;
    size_t i;

    const size_t tree_bits = (size_t)SPX_TREE_HEIGHT * (size_t)(SPX_D - 1);
    const size_t tree_bytes = (tree_bits + 7u) / 8u;
    const size_t leaf_bytes = ((size_t)SPX_TREE_HEIGHT + 7u) / 8u;
    const size_t expected_hash_message_out = (size_t)SPX_FORS_MSG_BYTES + tree_bytes + leaf_bytes;

    if (trace == 0 || out_constraint_count == 0 || out_violation_count == 0)
    {
        return -1;
    }

    for (i = 0; i < trace->call_count; i++)
    {
        const spx_p2_hash_call *call = &trace->calls[i];
        uint8_t addr_type = addr_get_type(call->addr_words);
        uint8_t tree_height = addr_get_tree_height(call->addr_words);
        int is_thash = (call->domain_tag == SPX_P2_DOMAIN_THASH_SIMPLE ||
                        call->domain_tag == SPX_P2_DOMAIN_THASH_F ||
                        call->domain_tag == SPX_P2_DOMAIN_THASH_H ||
                        call->domain_tag == SPX_P2_DOMAIN_THASH_TL);

        if (call->domain_tag == SPX_P2_DOMAIN_HASH_MESSAGE)
        {
            constraints += 1;
            if ((size_t)call->output_real_len != expected_hash_message_out)
            {
                violations++;
            }
        }

        if (call->domain_tag == SPX_P2_DOMAIN_PRF_ADDR)
        {
            constraints += 3;
            if (addr_type != SPX_ADDR_TYPE_WOTSPRF && addr_type != SPX_ADDR_TYPE_FORSPRF)
            {
                violations++;
            }
            if (call->output_real_len != SPX_N)
            {
                violations++;
            }
            if ((size_t)call->input_real_len != (size_t)(2 * SPX_N + SPX_ADDR_BYTES))
            {
                violations++;
            }
        }

        if (is_thash)
        {
            size_t inblocks = 0;
            constraints += 6;
            if (thash_inblocks_from_input_len((size_t)call->input_real_len, &inblocks) != 0)
            {
                violations++;
            }
            if (call->output_real_len != SPX_N)
            {
                violations++;
            }
            if (call->domain_tag == SPX_P2_DOMAIN_THASH_F && inblocks != 1u)
            {
                violations++;
            }
            if (call->domain_tag == SPX_P2_DOMAIN_THASH_H && inblocks != 2u)
            {
                violations++;
            }
            if (call->domain_tag == SPX_P2_DOMAIN_THASH_TL && inblocks < 3u)
            {
                violations++;
            }
            if (addr_type == SPX_ADDR_TYPE_WOTS && call->domain_tag != SPX_P2_DOMAIN_THASH_F)
            {
                violations++;
            }
            if ((addr_type == SPX_ADDR_TYPE_WOTSPK || addr_type == SPX_ADDR_TYPE_FORSPK) &&
                call->domain_tag != SPX_P2_DOMAIN_THASH_TL)
            {
                violations++;
            }
        }

        constraints += 2;
        if (addr_type == SPX_ADDR_TYPE_FORSTREE &&
            tree_height > (uint8_t)SPX_FORS_HEIGHT)
        {
            violations++;
        }
        if (addr_type == SPX_ADDR_TYPE_HASHTREE &&
            tree_height > (uint8_t)SPX_TREE_HEIGHT)
        {
            violations++;
        }

        if (addr_type == SPX_ADDR_TYPE_FORSPRF ||
            addr_type == SPX_ADDR_TYPE_FORSTREE ||
            addr_type == SPX_ADDR_TYPE_FORSPK)
        {
            cnt_fors++;
        }
        if (addr_type == SPX_ADDR_TYPE_WOTSPRF ||
            addr_type == SPX_ADDR_TYPE_WOTS ||
            addr_type == SPX_ADDR_TYPE_WOTSPK)
        {
            cnt_wots++;
        }
        if (addr_type == SPX_ADDR_TYPE_HASHTREE)
        {
            cnt_merkle++;
            if ((call->domain_tag == SPX_P2_DOMAIN_THASH_H ||
                 call->domain_tag == SPX_P2_DOMAIN_THASH_TL) &&
                tree_height >= (uint8_t)(SPX_TREE_HEIGHT - 1))
            {
                cnt_top_merkle++;
            }
        }
    }

    constraints += 4;
    if (cnt_fors == 0)
    {
        violations++;
    }
    if (cnt_wots == 0)
    {
        violations++;
    }
    if (cnt_merkle == 0)
    {
        violations++;
    }
    if (cnt_top_merkle == 0)
    {
        violations++;
    }

    *out_constraint_count = constraints;
    *out_violation_count = violations;
    return 0;
}

static void compute_commitment(uint8_t out[SPX_N],
                               const uint8_t *pk, const uint8_t *com,
                               const uint8_t *sigma_com, const spx_p2_trace *trace,
                               const spx_p2_witness_row_v1 *rows,
                               size_t row_count)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_CUSTOM);
    poseidon2_inc_absorb(&ctx, pk, SPX_PK_BYTES);
    poseidon2_inc_absorb(&ctx, com, SPX_N);
    poseidon2_inc_absorb(&ctx, sigma_com, SPX_BYTES);
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->call_count, sizeof(trace->call_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->lane_count, sizeof(trace->lane_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->dropped_calls, sizeof(trace->dropped_calls));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->dropped_lanes, sizeof(trace->dropped_lanes));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)trace->calls, trace->call_count * sizeof(spx_p2_hash_call));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)trace->lanes, trace->lane_count * sizeof(uint64_t));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&row_count, sizeof(row_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)rows, row_count * sizeof(spx_p2_witness_row_v1));
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(out, SPX_N, &ctx);
}

int spx_p2_verify_full_air_eval_constraints_v1(const uint8_t *pk,
                                               const uint8_t *com,
                                               const uint8_t *sigma_com,
                                               const spx_p2_trace *trace,
                                               const spx_p2_witness_row_v1 *rows,
                                               size_t row_count,
                                               uint32_t *out_constraint_count,
                                               uint32_t *out_violation_count)
{
    spx_p2_trace replay;
    spx_p2_witness_row_v1 *expected_rows = 0;
    size_t expected_row_count = 0;
    uint32_t hashcall_constraints = 0;
    uint32_t hashcall_violations = 0;
    uint32_t module_constraints = 0;
    uint32_t module_violations = 0;
    uint32_t root_bind_candidates = 0;
    uint32_t root_bind_matches = 0;
    uint32_t violations = 0;
    uint32_t constraints = 0;
    size_t i;

    if (pk == 0 || com == 0 || sigma_com == 0 || trace == 0 ||
        rows == 0 || out_constraint_count == 0 || out_violation_count == 0)
    {
        return -1;
    }

    constraints += 1;
    if (spx_p2_verify_com(pk, com, sigma_com) != 0)
    {
        violations++;
    }

    constraints += 1;
    if (spx_p2_trace_verify_com(&replay, pk, com, sigma_com) != 0)
    {
        violations++;
    }

    constraints += 1;
    if (!trace_equal(trace, &replay))
    {
        violations++;
    }

    constraints += 1;
    if (trace->dropped_calls != 0 || trace->dropped_lanes != 0)
    {
        violations++;
    }

    for (i = 0; i < trace->call_count; i++)
    {
        const spx_p2_hash_call *call = &trace->calls[i];
        size_t expected_in_lanes = bytes_to_lanes((size_t)call->input_real_len);
        size_t expected_out_lanes = bytes_to_lanes((size_t)call->output_real_len);
        constraints += 3;
        if (!domain_tag_is_allowed(call->domain_tag))
        {
            violations++;
        }
        if ((size_t)call->input_lane_count != expected_in_lanes)
        {
            violations++;
        }
        if ((size_t)call->output_lane_count != expected_out_lanes)
        {
            violations++;
        }
    }

    if (spx_p2_verify_full_air_eval_module_constraints_v1(trace,
                                                          &module_constraints,
                                                          &module_violations) != 0)
    {
        return -1;
    }
    constraints += module_constraints + 1;
    if (module_violations != 0)
    {
        violations++;
    }

    /* Root binding: at least one top-level Merkle THASH output equals pk root. */
    for (i = 0; i < trace->call_count; i++)
    {
        const spx_p2_hash_call *call = &trace->calls[i];
        uint8_t addr_type = addr_get_type(call->addr_words);
        uint8_t tree_height = addr_get_tree_height(call->addr_words);
        uint8_t out_bytes[SPX_N];
        if (addr_type != SPX_ADDR_TYPE_HASHTREE)
        {
            continue;
        }
        if (!(call->domain_tag == SPX_P2_DOMAIN_THASH_H ||
              call->domain_tag == SPX_P2_DOMAIN_THASH_TL))
        {
            continue;
        }
        if (tree_height < (uint8_t)(SPX_TREE_HEIGHT - 1))
        {
            continue;
        }
        if (call->output_real_len != SPX_N)
        {
            continue;
        }
        if ((uint64_t)call->output_lane_offset + (uint64_t)call->output_lane_count > (uint64_t)trace->lane_count)
        {
            continue;
        }
        constraints += 1;
        root_bind_candidates++;
        lanes_to_bytes_from_trace(out_bytes, SPX_N, trace, call->output_lane_offset);
        if (memcmp(out_bytes, pk + SPX_N, SPX_N) == 0)
        {
            root_bind_matches++;
        }
    }
    constraints += 2;
    if (root_bind_candidates == 0)
    {
        violations++;
    }
    if (root_bind_matches == 0)
    {
        violations++;
    }

    if (spx_p2_witness_count_rows_v1(trace, &expected_row_count) != 0)
    {
        return -1;
    }

    constraints += 1;
    if (expected_row_count != row_count)
    {
        violations++;
    }

    if (expected_row_count != 0)
    {
        expected_rows = (spx_p2_witness_row_v1 *)malloc(expected_row_count * sizeof(spx_p2_witness_row_v1));
        if (expected_rows == 0)
        {
            return -1;
        }
        if (spx_p2_witness_build_rows_v1(expected_rows, expected_row_count,
                                         &expected_row_count, trace) != 0)
        {
            free(expected_rows);
            return -1;
        }
        for (i = 0; i < row_count; i++)
        {
            constraints += 1;
            if (memcmp(&rows[i], &expected_rows[i], sizeof(spx_p2_witness_row_v1)) != 0)
            {
                violations++;
            }
        }
    }

    if (spx_p2_hashcall_air_eval_constraints_v1(trace, rows, row_count,
                                                &hashcall_constraints,
                                                &hashcall_violations) != 0)
    {
        free(expected_rows);
        return -1;
    }
    constraints += hashcall_constraints + 1;
    if (hashcall_violations != 0)
    {
        violations++;
    }

    free(expected_rows);
    *out_constraint_count = constraints;
    *out_violation_count = violations;
    return 0;
}

int spx_p2_verify_full_air_prove_v1(spx_p2_verify_full_proof_v1 *proof,
                                    const uint8_t *pk, const uint8_t *com,
                                    const uint8_t *sigma_com,
                                    const spx_p2_trace *trace,
                                    const spx_p2_witness_row_v1 *rows,
                                    size_t row_count)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;

    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0 || rows == 0)
    {
        return -1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sigma_com, trace, rows, row_count,
                                                   &constraints, &violations) != 0)
    {
        return -1;
    }

    proof->constraint_count = constraints;
    proof->violation_count = violations;
    compute_commitment(proof->commitment, pk, com, sigma_com, trace, rows, row_count);
    if (violations != 0)
    {
        return -2;
    }
    return 0;
}

int spx_p2_verify_full_air_verify_v1(const spx_p2_verify_full_proof_v1 *proof,
                                     const uint8_t *pk, const uint8_t *com,
                                     const uint8_t *sigma_com,
                                     const spx_p2_trace *trace,
                                     const spx_p2_witness_row_v1 *rows,
                                     size_t row_count)
{
    uint8_t expected_commitment[SPX_N];
    uint32_t constraints = 0;
    uint32_t violations = 0;

    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0 || rows == 0)
    {
        return -1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sigma_com, trace, rows, row_count,
                                                   &constraints, &violations) != 0)
    {
        return -1;
    }
    if (proof->constraint_count != constraints || proof->violation_count != violations)
    {
        return -1;
    }
    if (violations != 0)
    {
        return -1;
    }
    compute_commitment(expected_commitment, pk, com, sigma_com, trace, rows, row_count);
    if (memcmp(expected_commitment, proof->commitment, SPX_N) != 0)
    {
        return -1;
    }
    return 0;
}
