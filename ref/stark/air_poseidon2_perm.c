#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "air_poseidon2_perm.h"

static void compute_commitment(uint8_t out[SPX_N], const spx_p2_perm_witness_v1 *w)
{
    uint8_t buf[2 * SPX_POSEIDON2_T * sizeof(uint64_t)];
    memcpy(buf, w->state_in, SPX_POSEIDON2_T * sizeof(uint64_t));
    memcpy(buf + SPX_POSEIDON2_T * sizeof(uint64_t),
           w->state_out, SPX_POSEIDON2_T * sizeof(uint64_t));
    poseidon2_hash_bytes_domain(out, SPX_N, SPX_P2_DOMAIN_CUSTOM, buf, sizeof(buf));
}

int spx_p2_perm_air_eval_constraints_v1(const spx_p2_perm_witness_v1 *w,
                                        uint32_t *out_constraint_count,
                                        uint32_t *out_violation_count)
{
    uint64_t expected[SPX_POSEIDON2_T];
    uint32_t violations = 0;
    size_t i;
    if (w == 0 || out_constraint_count == 0 || out_violation_count == 0) {
        return -1;
    }

    memcpy(expected, w->state_in, sizeof(expected));
    poseidon2_permute(expected);

    for (i = 0; i < SPX_POSEIDON2_T; i++) {
        if (expected[i] != w->state_out[i]) {
            violations++;
        }
    }

    *out_constraint_count = (uint32_t)SPX_POSEIDON2_T;
    *out_violation_count = violations;
    return 0;
}

int spx_p2_perm_air_prove_v1(spx_p2_perm_proof_v1 *proof,
                             const spx_p2_perm_witness_v1 *witness)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    if (proof == 0 || witness == 0) {
        return -1;
    }
    if (spx_p2_perm_air_eval_constraints_v1(witness, &constraints, &violations) != 0) {
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

int spx_p2_perm_air_verify_v1(const spx_p2_perm_proof_v1 *proof,
                              const spx_p2_perm_witness_v1 *witness)
{
    uint32_t constraints = 0;
    uint32_t violations = 0;
    uint8_t expected_commitment[SPX_N];

    if (proof == 0 || witness == 0) {
        return -1;
    }
    if (spx_p2_perm_air_eval_constraints_v1(witness, &constraints, &violations) != 0) {
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
