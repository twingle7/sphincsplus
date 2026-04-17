#ifndef SPX_STARK_AIR_POSEIDON2_SPONGE_H
#define SPX_STARK_AIR_POSEIDON2_SPONGE_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "../poseidon2.h"

#define SPX_P2_SPONGE_AIR_MAX_LANES 4096

typedef struct {
    uint8_t domain_tag;
    uint32_t input_real_len;
    uint32_t input_lane_count;
    uint64_t input_lanes[SPX_P2_SPONGE_AIR_MAX_LANES];
    uint32_t output_real_len;
    uint32_t output_lane_count;
    uint64_t output_lanes[SPX_P2_SPONGE_AIR_MAX_LANES];
} spx_p2_sponge_witness_v1;

typedef struct {
    uint8_t commitment[SPX_N];
    uint32_t constraint_count;
    uint32_t violation_count;
} spx_p2_sponge_proof_v1;

#define spx_p2_sponge_air_eval_constraints_v1 SPX_NAMESPACE(spx_p2_sponge_air_eval_constraints_v1)
int spx_p2_sponge_air_eval_constraints_v1(const spx_p2_sponge_witness_v1 *w,
                                          uint32_t *out_constraint_count,
                                          uint32_t *out_violation_count);

#define spx_p2_sponge_air_prove_v1 SPX_NAMESPACE(spx_p2_sponge_air_prove_v1)
int spx_p2_sponge_air_prove_v1(spx_p2_sponge_proof_v1 *proof,
                               const spx_p2_sponge_witness_v1 *witness);

#define spx_p2_sponge_air_verify_v1 SPX_NAMESPACE(spx_p2_sponge_air_verify_v1)
int spx_p2_sponge_air_verify_v1(const spx_p2_sponge_proof_v1 *proof,
                                const spx_p2_sponge_witness_v1 *witness);

#endif
