#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../show/protocol_poseidon2.h"

static void print_hex_prefix(const uint8_t *data, size_t len, size_t prefix_len)
{
    size_t i;
    size_t end = len < prefix_len ? len : prefix_len;
    for (i = 0; i < end; i++)
    {
        printf("%02x", data[i]);
    }
}

static void fail_step(const char *step, int status)
{
    printf("[FAIL] %s: %s (%d)\n",
           step,
           spx_p2_flow_status_to_string(status),
           status);
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    spx_p2_issue_request_obj req;
    spx_p2_issue_response_obj resp;
    uint8_t issuer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t issuer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t pk_e[SPX_N];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t omega2[SPX_N];
    uint8_t public_ctx[16] = {
        'F', 'I', 'S', 'C', 'H', 'L', 'I', 'N',
        '-', 'D', 'E', 'M', 'O', '-', '2', '0'};
    uint8_t m_pub_bad[24];
    int ret;
    size_t i;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));

    for (i = 0; i < sizeof(m); i++)
    {
        m[i] = (uint8_t)(0x30u + i);
    }
    for (i = 0; i < sizeof(r); i++)
    {
        r[i] = (uint8_t)(0x80u + i);
    }
    for (i = 0; i < sizeof(pk_e); i++)
    {
        pk_e[i] = (uint8_t)(0xa0u + i);
    }
    for (i = 0; i < sizeof(omega2); i++)
    {
        omega2[i] = (uint8_t)(0xc0u + i);
    }

    printf("=== Poseidon2 Fischlin Protocol Flow Demo (final statement-bound path) ===\n");
    printf("backend=%s\n", spx_p2_protocol_backend_mode());

    if (crypto_sign_keypair(issuer_pk, issuer_sk) != 0)
    {
        printf("[FAIL] issuer_keypair\n");
        return 1;
    }
    printf("[Init] issuer keypair ready, pk_sig[0..7]=0x");
    print_hex_prefix(issuer_pk, sizeof(issuer_pk), 8);
    printf("\n");
    printf("[Init] pk_E[0..7]=0x");
    print_hex_prefix(pk_e, sizeof(pk_e), 8);
    printf("\n");

    ret = spx_p2_prepare_issue_request(&req, m, sizeof(m), r, sizeof(r));
    if (ret != SPX_P2_FLOW_OK)
    {
        fail_step("Commit", ret);
        return 1;
    }
    printf("[Commit] com[0..7]=0x");
    print_hex_prefix(req.c, sizeof(req.c), 8);
    printf(" | m_len=%llu r_len=%llu\n",
           (unsigned long long)sizeof(m),
           (unsigned long long)sizeof(r));

    ret = spx_p2_issue_respond(&resp, issuer_sk, &req);
    if (ret != SPX_P2_FLOW_OK)
    {
        fail_step("Blind Sign", ret);
        return 1;
    }
    printf("[Issue] sigma_blind_len=%llu sigma_blind[0..7]=0x",
           (unsigned long long)resp.sigma_prime_len);
    print_hex_prefix(resp.sigma_prime, resp.sigma_prime_len, 8);
    printf("\n");

    ret = spx_p2_finalize_credential(&cred, &req, &resp, m, sizeof(m), r, sizeof(r), omega2, sizeof(omega2));
    if (ret != SPX_P2_FLOW_OK)
    {
        fail_step("FinalizeCredential", ret);
        return 1;
    }
    printf("[FinalizeCredential] omega2_len=%llu omega2[0..7]=0x",
           (unsigned long long)cred.omega2_len);
    print_hex_prefix(cred.omega2, cred.omega2_len, 8);
    printf("\n");

    ret = spx_p2_protocol_show(&show_obj, issuer_pk, pk_e, sizeof(pk_e),
                               &cred, public_ctx, sizeof(public_ctx));
    if (ret != SPX_P2_FLOW_OK)
    {
        fail_step("Show", ret);
        if (!spx_p2_protocol_has_rust_backend())
        {
            printf("hint: compile with Rust STARK backend enabled\n");
        }
        return 1;
    }
    printf("[Show] sigma_C_len=%llu pi_f_len=%llu m_pub_len=%llu\n",
           (unsigned long long)show_obj.sigma_C_len,
           (unsigned long long)show_obj.pi_f_len,
           (unsigned long long)show_obj.m_pub_len);

    ret = spx_p2_protocol_verify(&show_obj, issuer_pk, pk_e, sizeof(pk_e), m, sizeof(m));
    if (ret != SPX_P2_FLOW_OK)
    {
        fail_step("Verify", ret);
        return 1;
    }
    printf("[Verify] ACCEPT\n");

    memcpy(m_pub_bad, m, sizeof(m_pub_bad));
    m_pub_bad[0] ^= 1u;
    ret = spx_p2_protocol_verify(&show_obj, issuer_pk, pk_e, sizeof(pk_e),
                                 m_pub_bad, sizeof(m_pub_bad));
    if (ret == SPX_P2_FLOW_OK)
    {
        printf("[FAIL] negative test: tampered m_pub should reject\n");
        return 1;
    }
    printf("[Negative] tampered m_pub -> REJECT (%s)\n",
           spx_p2_flow_status_to_string(ret));

    printf("demo result: OK\n");
    return 0;
}
