#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/air_verify_minimal.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t m[24];
    uint8_t r[16];
    size_t siglen = 0;
    spx_p2_trace trace;
    spx_p2_verify_min_proof_v1 proof;
    uint32_t constraints = 0, violations = 0;

    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));
    if (crypto_sign_keypair(pk, sk) != 0) {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sig, &siglen, com, SPX_N, sk) != 0 || siglen != SPX_BYTES) {
        fail("sign");
        return 1;
    }
    if (spx_p2_trace_verify_com(&trace, pk, com, sig) != 0) {
        fail("trace_verify");
        return 1;
    }

    if (spx_p2_verify_min_air_eval_constraints_v1(pk, com, sig, &trace, &constraints, &violations) != 0) {
        fail("eval");
        return 1;
    }
    if (violations != 0) {
        fail("violations_nonzero");
        return 1;
    }
    if (spx_p2_verify_min_air_prove_v1(&proof, pk, com, sig, &trace) != 0) {
        fail("prove");
        return 1;
    }
    if (spx_p2_verify_min_air_verify_v1(&proof, pk, com, sig, &trace) != 0) {
        fail("verify");
        return 1;
    }

    sig[0] ^= 1u;
    if (spx_p2_verify_min_air_verify_v1(&proof, pk, com, sig, &trace) == 0) {
        fail("tamper_sigma");
        return 1;
    }

    printf("poseidon2_verify_minimal_air_v1 test: OK | constraints=%u\n", constraints);
    return 0;
}
