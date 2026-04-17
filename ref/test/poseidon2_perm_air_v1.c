#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../stark/air_poseidon2_perm.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    spx_p2_perm_witness_v1 witness;
    spx_p2_perm_proof_v1 proof;
    spx_p2_perm_witness_v1 tampered;
    uint32_t constraints = 0;
    uint32_t violations = 0;
    size_t i;

    memset(&witness, 0, sizeof(witness));
    for (i = 0; i < SPX_POSEIDON2_T; i++) {
        witness.state_in[i] = (uint64_t)(i + 1u);
        witness.state_out[i] = witness.state_in[i];
    }
    poseidon2_permute(witness.state_out);

    if (spx_p2_perm_air_eval_constraints_v1(&witness, &constraints, &violations) != 0) {
        fail("eval_constraints");
        return 1;
    }
    if (constraints != SPX_POSEIDON2_T || violations != 0) {
        fail("constraint_values");
        return 1;
    }
    if (spx_p2_perm_air_prove_v1(&proof, &witness) != 0) {
        fail("prove");
        return 1;
    }
    if (spx_p2_perm_air_verify_v1(&proof, &witness) != 0) {
        fail("verify");
        return 1;
    }

    tampered = witness;
    tampered.state_out[0] ^= 1u;
    if (spx_p2_perm_air_verify_v1(&proof, &tampered) == 0) {
        fail("tamper_out");
        return 1;
    }

    tampered = witness;
    tampered.state_in[0] ^= 1u;
    if (spx_p2_perm_air_verify_v1(&proof, &tampered) == 0) {
        fail("tamper_in");
        return 1;
    }

    printf("poseidon2_perm_air_v1 test: OK | constraints=%u\n", constraints);
    return 0;
}
