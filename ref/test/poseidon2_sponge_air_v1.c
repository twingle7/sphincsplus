#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../hash_poseidon2_adapter.h"
#include "../stark/air_poseidon2_sponge.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t input[49];
    uint8_t output[24];
    spx_p2_sponge_witness_v1 w;
    spx_p2_sponge_proof_v1 proof;
    spx_p2_sponge_witness_v1 tampered;
    size_t i;
    size_t lanes = 0;
    uint32_t constraints = 0, violations = 0;

    memset(&w, 0, sizeof(w));
    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i + 3u);
    }
    poseidon2_hash_bytes_domain(output, sizeof(output), SPX_P2_DOMAIN_HASH_MESSAGE, input, sizeof(input));

    w.domain_tag = SPX_P2_DOMAIN_HASH_MESSAGE;
    w.input_real_len = sizeof(input);
    spx_p2_encode_bytes_to_lanes(w.input_lanes, &lanes, input, sizeof(input));
    w.input_lane_count = (uint32_t)lanes;

    w.output_real_len = sizeof(output);
    spx_p2_encode_bytes_to_lanes(w.output_lanes, &lanes, output, sizeof(output));
    w.output_lane_count = (uint32_t)lanes;

    if (spx_p2_sponge_air_eval_constraints_v1(&w, &constraints, &violations) != 0) {
        fail("eval");
        return 1;
    }
    if (violations != 0) {
        fail("violations_nonzero");
        return 1;
    }
    if (spx_p2_sponge_air_prove_v1(&proof, &w) != 0) {
        fail("prove");
        return 1;
    }
    if (spx_p2_sponge_air_verify_v1(&proof, &w) != 0) {
        fail("verify");
        return 1;
    }

    tampered = w;
    tampered.output_lanes[0] ^= 1u;
    if (spx_p2_sponge_air_verify_v1(&proof, &tampered) == 0) {
        fail("tamper_output");
        return 1;
    }

    printf("poseidon2_sponge_air_v1 test: OK | constraints=%u\n", constraints);
    return 0;
}
