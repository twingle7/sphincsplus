#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/protocol_poseidon2.h"
#include "../show/show_poseidon2.h"
#include "../stark/show_proof_format.h"

typedef struct
{
    spx_p2_issue_request_obj req;
} blind_issue_request;

typedef struct
{
    spx_p2_issue_response_obj resp;
} blind_issue_response;

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

static uint32_t load_u32_le(const uint8_t in[4])
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_cred_internal cred_bad;
    static spx_p2_cred_internal cred_mismatch;
    static spx_p2_show show_a;
    static spx_p2_show show_b;
    uint8_t issuer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t issuer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t omega2[SPX_N];
    uint8_t public_ctx_a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t public_ctx_b[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    blind_issue_request req;
    blind_issue_response resp;
    uint32_t magic;
    size_t i;

    memset(m, 0x11, sizeof(m));
    memset(r, 0x22, sizeof(r));
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(&cred, 0, sizeof(cred));
    memset(&cred_bad, 0, sizeof(cred_bad));
    memset(&cred_mismatch, 0, sizeof(cred_mismatch));
    memset(&show_a, 0, sizeof(show_a));
    memset(&show_b, 0, sizeof(show_b));
    for (i = 0; i < sizeof(omega2); i++)
    {
        omega2[i] = (uint8_t)(0x90u + (uint8_t)i);
    }
    printf("INFO: final e2e start\n");

    if (spx_p2_prepare_issue_request(&req.req, m, sizeof(m), r, sizeof(r)) != SPX_P2_FLOW_OK)
    {
        fail("prepare_issue_request");
        return 1;
    }
    if (crypto_sign_keypair(issuer_pk, issuer_sk) != 0)
    {
        fail("issuer_keypair");
        return 1;
    }

    if (spx_p2_issue_respond(&resp.resp, issuer_sk, &req.req) != SPX_P2_FLOW_OK ||
        resp.resp.sigma_prime_len != SPX_BYTES)
    {
        fail("issuer_sign");
        return 1;
    }

    if (spx_p2_finalize_credential(&cred, &req.req, &resp.resp,
                                   m, sizeof(m), r, sizeof(r),
                                   omega2, sizeof(omega2)) != 0)
    {
        fail("finalize_credential");
        return 1;
    }

    resp.resp.c[0] ^= 1u;
    if (spx_p2_finalize_credential(&cred_mismatch, &req.req, &resp.resp,
                                   m, sizeof(m), r, sizeof(r),
                                   omega2, sizeof(omega2)) == 0)
    {
        fail("request_response_commitment_mismatch_should_fail");
        return 1;
    }
    resp.resp.c[0] ^= 1u;

    if (spx_p2_show_prove(&show_a, issuer_pk, &cred, public_ctx_a, sizeof(public_ctx_a)) != 0)
    {
        fail("show_prove_ctx_a_final_requires_rust_stark");
        return 1;
    }
    if (spx_p2_show_verify(&show_a, issuer_pk) != 0)
    {
        fail("show_verify_ctx_a");
        return 1;
    }
    printf("INFO: show ctx_a ok (len=%llu)\n", (unsigned long long)show_a.pi_f_len);

    if (spx_p2_show_prove(&show_b, issuer_pk, &cred, public_ctx_b, sizeof(public_ctx_b)) != 0)
    {
        fail("show_prove_ctx_b");
        return 1;
    }
    if (spx_p2_show_verify(&show_b, issuer_pk) != 0)
    {
        fail("show_verify_ctx_b");
        return 1;
    }
    printf("INFO: show ctx_b ok (len=%llu)\n", (unsigned long long)show_b.pi_f_len);
    if (show_a.pi_f_len == show_b.pi_f_len &&
        bytes_equal(show_a.pi_f, show_b.pi_f, show_a.pi_f_len))
    {
        fail("unlinkability_ctx_binding");
        return 1;
    }

    if (show_a.pi_f_len < 4u)
    {
        fail("pi_f_len_too_small");
        return 1;
    }
    magic = load_u32_le(show_a.pi_f);
    if (magic != SPX_P2_SHOW_PROOF_MAGIC)
    {
        fail("final_requires_show_proof");
        return 1;
    }

    memcpy(&cred_bad, &cred, sizeof(cred_bad));
    cred_bad.sigma_com[0] ^= 1u;
    if (spx_p2_show_prove(&show_b, issuer_pk, &cred_bad, public_ctx_a, sizeof(public_ctx_a)) == 0)
    {
        fail("tamper_sig_should_fail");
        return 1;
    }

    printf("poseidon2_fischlin_blind_e2e test: OK | pi_f_len=%llu\n",
           (unsigned long long)show_a.pi_f_len);
    return 0;
}
