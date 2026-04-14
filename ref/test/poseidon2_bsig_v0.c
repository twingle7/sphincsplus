#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../bsig_poseidon2_v0.h"

static spx_p2_bsig_ctx g_ctx;

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[48];
    uint8_t r[32];
    spx_p2_bsig_public tampered;
    size_t i;

    for (i = 0; i < sizeof(m); i++) {
        m[i] = (uint8_t)(i ^ 0x5a);
    }
    for (i = 0; i < sizeof(r); i++) {
        r[i] = (uint8_t)(0xa0u + i);
    }

    if (crypto_sign_keypair(pk, sk) != 0) {
        fail("keypair");
        return 1;
    }
    if (spx_p2_bsig_issue(&g_ctx, sk, m, sizeof(m), r, sizeof(r)) != 0) {
        fail("issue");
        return 1;
    }
    if (spx_p2_bsig_prove(&g_ctx, pk) != 0) {
        fail("prove");
        return 1;
    }
    if (g_ctx.trace.call_count == 0) {
        fail("trace_nonempty");
        return 1;
    }
    if (spx_p2_bsig_verify(&g_ctx.pub, pk) != 0) {
        fail("verify");
        return 1;
    }

    tampered = g_ctx.pub;
    tampered.sigma_com[0] ^= 0x01u;
    if (spx_p2_bsig_verify(&tampered, pk) == 0) {
        fail("tamper_sigma");
        return 1;
    }

    tampered = g_ctx.pub;
    memset(tampered.pi_f, 0, sizeof(tampered.pi_f));
    if (spx_p2_bsig_verify(&tampered, pk) == 0) {
        fail("tamper_pi_f");
        return 1;
    }

    printf("poseidon2_bsig_v0 test: OK\n");
    return 0;
}
