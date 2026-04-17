#ifndef SPX_STARK_AIR_POSEIDON2_PERM_H
#define SPX_STARK_AIR_POSEIDON2_PERM_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"
#include "../poseidon2.h"

typedef struct {
    uint64_t state_in[SPX_POSEIDON2_T];
    uint64_t state_out[SPX_POSEIDON2_T];
} spx_p2_perm_witness_v1;

typedef struct {
    uint8_t commitment[SPX_N];
    uint32_t constraint_count;
    uint32_t violation_count;
} spx_p2_perm_proof_v1;

#define spx_p2_perm_air_eval_constraints_v1 SPX_NAMESPACE(spx_p2_perm_air_eval_constraints_v1)
int spx_p2_perm_air_eval_constraints_v1(const spx_p2_perm_witness_v1 *w,
                                        uint32_t *out_constraint_count,
                                        uint32_t *out_violation_count);

#define spx_p2_perm_air_prove_v1 SPX_NAMESPACE(spx_p2_perm_air_prove_v1)
int spx_p2_perm_air_prove_v1(spx_p2_perm_proof_v1 *proof,
                             const spx_p2_perm_witness_v1 *witness);

#define spx_p2_perm_air_verify_v1 SPX_NAMESPACE(spx_p2_perm_air_verify_v1)
int spx_p2_perm_air_verify_v1(const spx_p2_perm_proof_v1 *proof,
                              const spx_p2_perm_witness_v1 *witness);

#endif
