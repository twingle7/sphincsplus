#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../poseidon2.h"
#include "air_verify_minimal.h"

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

static void compute_commitment(uint8_t out[SPX_N],
                               const uint8_t *pk, const uint8_t *com,
                               const uint8_t *sigma_com, const spx_p2_trace *trace)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_CUSTOM);
    poseidon2_inc_absorb(&ctx, pk, SPX_PK_BYTES);
    poseidon2_inc_absorb(&ctx, com, SPX_N);
    poseidon2_inc_absorb(&ctx, sigma_com, SPX_BYTES);
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->call_count, sizeof(trace->call_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&trace->lane_count, sizeof(trace->lane_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)trace->calls, trace->call_count * sizeof(spx_p2_hash_call));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)trace->lanes, trace->lane_count * sizeof(uint64_t));
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(out, SPX_N, &ctx);
}

int spx_p2_verify_min_air_eval_constraints_v1(const uint8_t *pk,
                                              const uint8_t *com,
                                              const uint8_t *sigma_com,
                                              const spx_p2_trace *trace,
                                              uint32_t *out_constraint_count,
                                              uint32_t *out_violation_count)
{
    spx_p2_trace replay;
    uint32_t violations = 0;
    uint32_t constraints = 2;
    int verify_ret;
    int trace_ret;
    if (pk == 0 || com == 0 || sigma_com == 0 || trace == 0 ||
        out_constraint_count == 0 || out_violation_count == 0) {
        return -1;
    }
    verify_ret = spx_p2_verify_com(pk, com, sigma_com);
    if (verify_ret != 0) {
        violations++;
    }
    trace_ret = spx_p2_trace_verify_com(&replay, pk, com, sigma_com);
    if (trace_ret != 0) {
        violations++;
    }
    if (!trace_equal(trace, &replay)) {
        violations++;
    }
    constraints += 1;
    *out_constraint_count = constraints;
    *out_violation_count = violations;
    return 0;
}

int spx_p2_verify_min_air_prove_v1(spx_p2_verify_min_proof_v1 *proof,
                                   const uint8_t *pk, const uint8_t *com,
                                   const uint8_t *sigma_com,
                                   const spx_p2_trace *trace)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0) {
        return -1;
    }
    if (spx_p2_verify_min_air_eval_constraints_v1(pk, com, sigma_com, trace,
                                                   &constraints, &violations) != 0) {
        return -1;
    }
    proof->constraint_count = constraints;
    proof->violation_count = violations;
    compute_commitment(proof->commitment, pk, com, sigma_com, trace);
    if (violations != 0) {
        return -2;
    }
    return 0;
}

int spx_p2_verify_min_air_verify_v1(const spx_p2_verify_min_proof_v1 *proof,
                                    const uint8_t *pk, const uint8_t *com,
                                    const uint8_t *sigma_com,
                                    const spx_p2_trace *trace)
{
    uint8_t expected_commitment[SPX_N];
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || pk == 0 || com == 0 || sigma_com == 0 || trace == 0) {
        return -1;
    }
    if (spx_p2_verify_min_air_eval_constraints_v1(pk, com, sigma_com, trace,
                                                   &constraints, &violations) != 0) {
        return -1;
    }
    if (constraints != proof->constraint_count || violations != proof->violation_count) {
        return -1;
    }
    if (violations != 0) {
        return -1;
    }
    compute_commitment(expected_commitment, pk, com, sigma_com, trace);
    if (memcmp(expected_commitment, proof->commitment, SPX_N) != 0) {
        return -1;
    }
    return 0;
}
