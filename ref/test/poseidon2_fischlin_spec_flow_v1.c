#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/protocol_poseidon2.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    uint8_t issuer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t issuer_pk_bad[CRYPTO_PUBLICKEYBYTES];
    uint8_t issuer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t m_bad[24];
    uint8_t public_ctx[8] = {0x42, 0x19, 0x7a, 0x05, 0x11, 0x2d, 0x99, 0x01};
    uint8_t omega2_deterministic[SPX_N];
    int ret;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x35, sizeof(m));
    memset(r, 0x73, sizeof(r));

    if (crypto_sign_keypair(issuer_pk, issuer_sk) != 0)
    {
        fail("issuer_keypair");
        return 1;
    }
    memcpy(issuer_pk_bad, issuer_pk, sizeof(issuer_pk_bad));

    ret = spx_p2_issue_unblind(&cred, com, issuer_sk, m, sizeof(m), r, sizeof(r), 0, 0);
    if (ret != SPX_P2_FLOW_OK)
    {
        fail("issue_unblind");
        return 1;
    }
    if (cred.omega2_len != SPX_N)
    {
        fail("omega2_len");
        return 1;
    }

    spx_p2_commit(omega2_deterministic, cred.com, SPX_N, cred.sigma_com, SPX_BYTES);
    if (memcmp(cred.omega2, omega2_deterministic, SPX_N) == 0)
    {
        fail("omega2_should_not_be_forced_deterministic");
        return 1;
    }

    ret = spx_p2_protocol_show(&show_obj, issuer_pk, issuer_pk, SPX_N, &cred, public_ctx, sizeof(public_ctx));
    if (ret != SPX_P2_FLOW_OK)
    {
        fail("protocol_show_v1");
        return 1;
    }

    ret = spx_p2_protocol_verify_strict_public(&show_obj, issuer_pk, issuer_pk, SPX_N, cred.m, cred.mlen);
    if (ret != SPX_P2_FLOW_OK)
    {
        fail("verify_strict_public_good");
        return 1;
    }
    if (spx_p2_protocol_verify(&show_obj, issuer_pk, issuer_pk, SPX_N) == SPX_P2_FLOW_OK)
    {
        fail("verify_v1_should_require_explicit_m_pub_for_m20");
        return 1;
    }

    memcpy(m_bad, cred.m, cred.mlen);
    m_bad[0] ^= 1u;
    if (spx_p2_protocol_verify_strict_public(&show_obj, issuer_pk, issuer_pk, SPX_N, m_bad, cred.mlen) == SPX_P2_FLOW_OK)
    {
        fail("verify_strict_public_should_reject_bad_m_pub");
        return 1;
    }

    issuer_pk_bad[0] ^= 1u;
    if (spx_p2_protocol_verify_strict_public(&show_obj, issuer_pk, issuer_pk_bad, SPX_N, cred.m, cred.mlen) == SPX_P2_FLOW_OK)
    {
        fail("verify_strict_public_should_reject_bad_pk_e");
        return 1;
    }

    show_obj.public_ctx[0] ^= 1u;
    if (spx_p2_protocol_verify_strict_public(&show_obj, issuer_pk, issuer_pk, SPX_N, cred.m, cred.mlen) == SPX_P2_FLOW_OK)
    {
        fail("verify_strict_public_should_reject_bad_ctx");
        return 1;
    }

    printf("poseidon2_fischlin_spec_flow_v1 test: OK | omega2_len=%llu m_pub_len=%llu\n",
           (unsigned long long)cred.omega2_len,
           (unsigned long long)cred.mlen);
    return 0;
}
