#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/protocol_poseidon2.h"
#include "../stark/ffi.h"
#include "../stark/pi_f_format.h"
#include "../stark/stats.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    uint8_t pk_sig[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_sig[CRYPTO_SECRETKEYBYTES];
    uint8_t pk_e[SPX_N];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t com[SPX_N];
    uint8_t sigma_blind[SPX_BYTES];
    uint8_t omega2[SPX_N];
    uint8_t public_ctx[16] = {
        'S', 'T', 'A', 'R', 'K', '-', 'S', 'T',
        'A', 'T', 'S', '-', 'M', '2', '0', '1'};
    size_t sigma_blind_len = 0;
    spx_p2_stark_stats stats;
    spx_p2_ffi_public_inputs pub;
    spx_p2_ffi_private_witness wit;
    size_t i;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(&pub, 0, sizeof(pub));
    memset(&wit, 0, sizeof(wit));
    memset(m, 0x13, sizeof(m));
    memset(r, 0x31, sizeof(r));
    for (i = 0; i < sizeof(pk_e); i++)
    {
        pk_e[i] = (uint8_t)(0x80u + (uint8_t)i);
        omega2[i] = (uint8_t)(0xa0u + (uint8_t)i);
    }
    if (crypto_sign_keypair(pk_sig, sk_sig) != 0)
    {
        fail("keypair");
        return 1;
    }
    if (spx_p2_issue_request(com, m, sizeof(m), r, sizeof(r)) != SPX_P2_FLOW_OK)
    {
        fail("issue_request");
        return 1;
    }
    if (spx_p2_issue_sign(sigma_blind, &sigma_blind_len, sk_sig, com) != SPX_P2_FLOW_OK)
    {
        fail("issue_sign");
        return 1;
    }
    if (spx_p2_unblind(&cred, com, sigma_blind, sigma_blind_len, omega2, sizeof(omega2)) != SPX_P2_FLOW_OK)
    {
        fail("unblind");
        return 1;
    }
    memcpy(cred.m, m, sizeof(m));
    cred.mlen = sizeof(m);
    memcpy(cred.r, r, sizeof(r));
    cred.rlen = sizeof(r);
    if (spx_p2_protocol_show_strict_public(&show_obj, pk_sig, pk_e, sizeof(pk_e),
                                           &cred, public_ctx, sizeof(public_ctx)) != SPX_P2_FLOW_OK)
    {
        fail("show_strict_public");
        return 1;
    }

    pub.pk = pk_sig;
    pub.pk_e = pk_e;
    pub.pk_e_len = sizeof(pk_e);
    pub.com = show_obj.com;
    pub.m_pub = show_obj.m_pub;
    pub.m_pub_len = show_obj.m_pub_len;
    pub.public_ctx = show_obj.public_ctx;
    pub.public_ctx_len = show_obj.public_ctx_len;
    pub.sigma_c = show_obj.sigma_C;
    pub.sigma_c_len = show_obj.sigma_C_len;
    wit.sigma_com = cred.sigma_com;
    wit.m = cred.m;
    wit.mlen = cred.mlen;
    wit.r = cred.r;
    wit.rlen = cred.rlen;
    wit.omega2 = cred.omega2;
    wit.omega2_len = cred.omega2_len;

    if (spx_p2_stark_collect_ffi_stats(&stats, &pub, &wit) != 0)
    {
        fail("collect_ffi_stats");
        return 1;
    }
    if (stats.trace_calls == 0 || stats.trace_lanes == 0 || stats.witness_rows == 0 || stats.proof_bytes == 0)
    {
        fail("stats_zero");
        return 1;
    }
    if (stats.proof_magic != SPX_P2_PI_F_MAGIC || stats.proof_version != SPX_P2_PI_F_VERSION)
    {
        fail("proof_not_final_v2");
        return 1;
    }
    printf("poseidon2_stark_stats: calls=%u lanes=%u rows=%llu proof=%llu magic=0x%08x ver=%u preprocess_ms=%.3f prove_core_ms=%.3f prove_e2e_ms=%.3f prove_ms=%.3f verify_ms=%.3f rss_peak_kb=%llu constraints=%u assertions=%u width=%llu length=%llu\n",
           stats.trace_calls, stats.trace_lanes,
           (unsigned long long)stats.witness_rows,
           (unsigned long long)stats.proof_bytes,
           stats.proof_magic, stats.proof_version,
           stats.preprocess_ms, stats.prove_core_ms, stats.prove_e2e_ms,
           stats.prove_ms, stats.verify_ms,
           (unsigned long long)stats.peak_rss_kb,
           stats.transition_constraints,
           stats.boundary_assertions,
           (unsigned long long)stats.trace_width,
           (unsigned long long)stats.trace_length);
    return 0;
}
