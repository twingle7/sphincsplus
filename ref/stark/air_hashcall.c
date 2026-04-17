#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../poseidon2.h"
#include "air_hashcall.h"

static void compute_commitment(uint8_t out[SPX_N],
                               const spx_p2_witness_row_v1 *rows,
                               size_t row_count)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_CUSTOM);
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&row_count, sizeof(row_count));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)rows, row_count * sizeof(spx_p2_witness_row_v1));
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(out, SPX_N, &ctx);
}

int spx_p2_hashcall_air_eval_constraints_v1(const spx_p2_trace *trace,
                                            const spx_p2_witness_row_v1 *rows,
                                            size_t row_count,
                                            uint32_t *out_constraint_count,
                                            uint32_t *out_violation_count)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    size_t i;
    size_t row = 0;

    if (trace == 0 || rows == 0 || out_constraint_count == 0 || out_violation_count == 0) {
        return -1;
    }

    for (i = 0; i < trace->call_count; i++) {
        size_t j;
        const spx_p2_hash_call *call = &trace->calls[i];
        const spx_p2_witness_row_v1 *hdr;
        if (row >= row_count) {
            return -1;
        }
        hdr = &rows[row++];
        constraints += 1;
        if (hdr->kind != SPX_P2_ROW_KIND_HEADER ||
            hdr->domain_tag != call->domain_tag ||
            hdr->call_index != (uint32_t)i ||
            hdr->real_len != call->input_real_len ||
            hdr->lane_count != call->input_lane_count) {
            violations++;
        }
        for (j = 0; j < 8u; j++) {
            constraints += 1;
            if (hdr->addr_words[j] != call->addr_words[j]) {
                violations++;
            }
        }

        for (j = 0; j < call->input_lane_count; j++) {
            const spx_p2_witness_row_v1 *ri;
            if (row >= row_count || call->input_lane_offset + j >= trace->lane_count) {
                return -1;
            }
            ri = &rows[row++];
            constraints += 1;
            if (ri->kind != SPX_P2_ROW_KIND_INPUT_LANE ||
                ri->domain_tag != call->domain_tag ||
                ri->call_index != (uint32_t)i ||
                ri->lane_index != (uint32_t)j ||
                ri->lane_value != trace->lanes[call->input_lane_offset + j]) {
                violations++;
            }
        }

        for (j = 0; j < call->output_lane_count; j++) {
            const spx_p2_witness_row_v1 *ro;
            if (row >= row_count || call->output_lane_offset + j >= trace->lane_count) {
                return -1;
            }
            ro = &rows[row++];
            constraints += 1;
            if (ro->kind != SPX_P2_ROW_KIND_OUTPUT_LANE ||
                ro->domain_tag != call->domain_tag ||
                ro->call_index != (uint32_t)i ||
                ro->lane_index != (uint32_t)j ||
                ro->lane_value != trace->lanes[call->output_lane_offset + j]) {
                violations++;
            }
        }
    }
    constraints += 1;
    if (row != row_count) {
        violations++;
    }
    *out_constraint_count = constraints;
    *out_violation_count = violations;
    return 0;
}

int spx_p2_hashcall_air_prove_v1(spx_p2_hashcall_proof_v1 *proof,
                                 const spx_p2_trace *trace,
                                 const spx_p2_witness_row_v1 *rows,
                                 size_t row_count)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || trace == 0 || rows == 0) {
        return -1;
    }
    if (spx_p2_hashcall_air_eval_constraints_v1(trace, rows, row_count, &constraints, &violations) != 0) {
        return -1;
    }
    proof->constraint_count = constraints;
    proof->violation_count = violations;
    compute_commitment(proof->commitment, rows, row_count);
    if (violations != 0) {
        return -2;
    }
    return 0;
}

int spx_p2_hashcall_air_verify_v1(const spx_p2_hashcall_proof_v1 *proof,
                                  const spx_p2_trace *trace,
                                  const spx_p2_witness_row_v1 *rows,
                                  size_t row_count)
{
    uint8_t expected_commitment[SPX_N];
    uint32_t constraints = 0;
    uint32_t violations = 0;

    if (proof == 0 || trace == 0 || rows == 0) {
        return -1;
    }
    if (spx_p2_hashcall_air_eval_constraints_v1(trace, rows, row_count, &constraints, &violations) != 0) {
        return -1;
    }
    if (proof->constraint_count != constraints || proof->violation_count != violations) {
        return -1;
    }
    if (violations != 0) {
        return -1;
    }
    compute_commitment(expected_commitment, rows, row_count);
    if (memcmp(expected_commitment, proof->commitment, SPX_N) != 0) {
        return -1;
    }
    return 0;
}
