#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "air_poseidon2_sponge.h"

static int lanes_to_bytes(uint8_t *out, size_t out_len,
                          const uint64_t *lanes, size_t lane_count,
                          size_t real_len)
{
    size_t i;
    if (real_len > out_len) {
        return -1;
    }
    if (((real_len + 7u) / 8u) != lane_count) {
        return -1;
    }
    memset(out, 0, out_len);
    for (i = 0; i < lane_count; i++) {
        size_t j;
        size_t base = i * 8u;
        uint64_t x = lanes[i];
        size_t chunk = 8u;
        if (base + chunk > real_len) {
            chunk = real_len - base;
        }
        for (j = 0; j < chunk; j++) {
            out[base + j] = (uint8_t)(x & 0xffu);
            x >>= 8;
        }
    }
    return 0;
}

static void compute_commitment(uint8_t out[SPX_N], const spx_p2_sponge_witness_v1 *w)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_CUSTOM);
    poseidon2_inc_absorb(&ctx, &w->domain_tag, 1);
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&w->input_real_len, sizeof(w->input_real_len));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)w->input_lanes, w->input_lane_count * sizeof(uint64_t));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)&w->output_real_len, sizeof(w->output_real_len));
    poseidon2_inc_absorb(&ctx, (const uint8_t *)w->output_lanes, w->output_lane_count * sizeof(uint64_t));
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(out, SPX_N, &ctx);
}

int spx_p2_sponge_air_eval_constraints_v1(const spx_p2_sponge_witness_v1 *w,
                                          uint32_t *out_constraint_count,
                                          uint32_t *out_violation_count)
{
    uint8_t input_bytes[SPX_P2_SPONGE_AIR_MAX_LANES * 8];
    uint8_t output_bytes[SPX_P2_SPONGE_AIR_MAX_LANES * 8];
    uint8_t expected_output[SPX_P2_SPONGE_AIR_MAX_LANES * 8];
    uint32_t violations = 0;
    size_t i;

    if (w == 0 || out_constraint_count == 0 || out_violation_count == 0) {
        return -1;
    }
    if (w->input_lane_count > SPX_P2_SPONGE_AIR_MAX_LANES ||
        w->output_lane_count > SPX_P2_SPONGE_AIR_MAX_LANES) {
        return -1;
    }
    if (lanes_to_bytes(input_bytes, sizeof(input_bytes),
                       w->input_lanes, w->input_lane_count, w->input_real_len) != 0) {
        return -1;
    }
    if (lanes_to_bytes(output_bytes, sizeof(output_bytes),
                       w->output_lanes, w->output_lane_count, w->output_real_len) != 0) {
        return -1;
    }

    poseidon2_hash_bytes_domain(expected_output, w->output_real_len,
                                (spx_poseidon2_domain)w->domain_tag,
                                input_bytes, w->input_real_len);

    for (i = 0; i < w->output_real_len; i++) {
        if (expected_output[i] != output_bytes[i]) {
            violations++;
        }
    }

    *out_constraint_count = w->output_real_len;
    *out_violation_count = violations;
    return 0;
}

int spx_p2_sponge_air_prove_v1(spx_p2_sponge_proof_v1 *proof,
                               const spx_p2_sponge_witness_v1 *witness)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || witness == 0) {
        return -1;
    }
    if (spx_p2_sponge_air_eval_constraints_v1(witness, &constraints, &violations) != 0) {
        return -1;
    }
    proof->constraint_count = constraints;
    proof->violation_count = violations;
    compute_commitment(proof->commitment, witness);
    if (violations != 0) {
        return -2;
    }
    return 0;
}

int spx_p2_sponge_air_verify_v1(const spx_p2_sponge_proof_v1 *proof,
                                const spx_p2_sponge_witness_v1 *witness)
{
    uint8_t expected_commitment[SPX_N];
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || witness == 0) {
        return -1;
    }
    if (spx_p2_sponge_air_eval_constraints_v1(witness, &constraints, &violations) != 0) {
        return -1;
    }
    if (proof->constraint_count != constraints) {
        return -1;
    }
    if (proof->violation_count != violations) {
        return -1;
    }
    if (violations != 0) {
        return -1;
    }
    compute_commitment(expected_commitment, witness);
    if (memcmp(expected_commitment, proof->commitment, SPX_N) != 0) {
        return -1;
    }
    return 0;
}
