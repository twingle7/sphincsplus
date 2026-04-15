#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../bsig_poseidon2_v0.h"
#include "poseidon2_test_utils.h"

static spx_p2_bsig_ctx g_ctx;

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(int argc, char **argv)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[48];
    uint8_t r[32];
    spx_p2_bsig_public tampered;
    int verbose = spx_test_is_verbose(argc, argv);
    double t0 = spx_test_now_seconds();
    double t_issue0, t_issue1, t_prove0, t_prove1, t_verify0, t_verify1;
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
    t_issue0 = spx_test_now_seconds();
    if (spx_p2_bsig_issue(&g_ctx, sk, m, sizeof(m), r, sizeof(r)) != 0) {
        fail("issue");
        return 1;
    }
    t_issue1 = spx_test_now_seconds();

    t_prove0 = spx_test_now_seconds();
    if (spx_p2_bsig_prove(&g_ctx, pk) != 0) {
        fail("prove");
        return 1;
    }
    t_prove1 = spx_test_now_seconds();
    if (g_ctx.trace.call_count == 0) {
        fail("trace_nonempty");
        return 1;
    }

    t_verify0 = spx_test_now_seconds();
    if (spx_p2_bsig_verify(&g_ctx.pub, pk) != 0) {
        fail("verify");
        return 1;
    }
    t_verify1 = spx_test_now_seconds();

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

    printf("poseidon2_bsig_v0 test: OK | issue=%.6f s prove=%.6f s verify=%.6f s total=%.6f s trace_calls=%u trace_lanes=%u\n",
           t_issue1 - t_issue0,
           t_prove1 - t_prove0,
           t_verify1 - t_verify0,
           spx_test_now_seconds() - t0,
           g_ctx.trace.call_count,
           g_ctx.trace.lane_count);
    if (verbose) {
        spx_test_print_hex_prefix("com", g_ctx.pub.com, sizeof(g_ctx.pub.com), sizeof(g_ctx.pub.com));
        spx_test_print_hex_prefix("pi_f", g_ctx.pub.pi_f, sizeof(g_ctx.pub.pi_f), sizeof(g_ctx.pub.pi_f));
        printf("[bsig] dropped_calls=%u dropped_lanes=%u\n",
               g_ctx.trace.dropped_calls, g_ctx.trace.dropped_lanes);
    }
    return 0;
}
