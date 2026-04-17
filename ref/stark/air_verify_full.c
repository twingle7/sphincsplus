#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../poseidon2.h"
#include "air_hashcall.h"
#include "air_verify_full.h"

static int trace_equal(const spx_p2_trace *a, const spx_p2_trace *b)
{
    size_t i;
    if (a->call_count != b->call_count ||
        a->lane_count != b->lane_count ||
        a->dropped_calls != b->dropped_calls ||
        a->dropped_lanes != b->dropped_lanes) {
        return 0;
    }
    for (i = 0; i < a->call_count; i++) {
        if (memcmp(&a->calls[i], &b->calls[i], sizeof(spx_p2_hash_call)) != 0) {
            return 0;
        }
    }
    for (i = 0; i < a->lane_count; i++) {
        if (a->lanes[i] != b->lanes[i]) {
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
        domain_tag == SPX_P2_DOMAIN_CUSTOM) {
        return 1;
    }
    return 0;
}

static size_t bytes_to_lanes(size_t len)
{
    return (len + 7u) / 8u;
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
    uint32_t violations = 0;
    uint32_t constraints = 0;
    size_t i;

    if (pk == 0 || com == 0 || sigma_com == 0 || trace == 0 ||
        rows == 0 || out_constraint_count == 0 || out_violation_count == 0) {
        return -1;
    }

    constraints += 1;
    if (spx_p2_verify_com(pk, com, sigma_com) != 0) {
        violations++;
    }

    constraints += 1;
    if (spx_p2_trace_verify_com(&replay, pk, com, sigma_com) != 0) {
        violations++;
    }

    constraints += 1;
    if (!trace_equal(trace, &replay)) {
        violations++;
    }

    constraints += 1;
    if (trace->dropped_calls != 0 || trace->dropped_lanes != 0) {
        violations++;
    }

    for (i = 0; i < trace->call_count; i++) {
        const spx_p2_hash_call *call = &trace->calls[i];
        size_t expected_in_lanes = bytes_to_lanes((size_t)call->input_real_len);
        size_t expected_out_lanes = bytes_to_lanes((size_t)call->output_real_len);
        constraints += 3;
        if (!domain_tag_is_allowed(call->domain_tag)) {
            violations++;
        }
        if ((size_t)call->input_lane_count != expected_in_lanes) {
            violations++;
        }
        if ((size_t)call->output_lane_count != expected_out_lanes) {
            violations++;
        }
    }

    if (spx_p2_witness_count_rows_v1(trace, &expected_row_count) != 0) {
        return -1;
    }

    constraints += 1;
    if (expected_row_count != row_count) {
        violations++;
    }

    if (expected_row_count != 0) {
        expected_rows = (spx_p2_witness_row_v1 *)malloc(expected_row_count * sizeof(spx_p2_witness_row_v1));
        if (expected_rows == 0) {
            return -1;
        }
        if (spx_p2_witness_build_rows_v1(expected_rows, expected_row_count,
                                         &expected_row_count, trace) != 0) {
            free(expected_rows);
            return -1;
        }
        for (i = 0; i < row_count; i++) {
            constraints += 1;
            if (memcmp(&rows[i], &expected_rows[i], sizeof(spx_p2_witness_row_v1)) != 0) {
                violations++;
            }
        }
    }

    if (spx_p2_hashcall_air_eval_constraints_v1(trace, rows, row_count,
                                                 &hashcall_constraints,
                                                 &hashcall_violations) != 0) {
        free(expected_rows);
        return -1;
    }
    constraints += hashcall_constraints + 1;
    if (hashcall_violations != 0) {
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

    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0 || rows == 0) {
        return -1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sigma_com, trace, rows, row_count,
                                                    &constraints, &violations) != 0) {
        return -1;
    }

    proof->constraint_count = constraints;
    proof->violation_count = violations;
    compute_commitment(proof->commitment, pk, com, sigma_com, trace, rows, row_count);
    if (violations != 0) {
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

    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0 || rows == 0) {
        return -1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sigma_com, trace, rows, row_count,
                                                    &constraints, &violations) != 0) {
        return -1;
    }
    if (proof->constraint_count != constraints || proof->violation_count != violations) {
        return -1;
    }
    if (violations != 0) {
        return -1;
    }
    compute_commitment(expected_commitment, pk, com, sigma_com, trace, rows, row_count);
    if (memcmp(expected_commitment, proof->commitment, SPX_N) != 0) {
        return -1;
    }
    return 0;
}
