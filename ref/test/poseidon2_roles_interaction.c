#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/protocol_poseidon2.h"
#include "../show/show_poseidon2.h"
#include "../stark/show_proof_format.h"

static uint32_t load_u32_le(const uint8_t in[4])
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void print_hex_prefix(const uint8_t *data, size_t len, size_t n)
{
    size_t i;
    size_t end = (len < n) ? len : n;
    for (i = 0; i < end; i++)
    {
        printf("%02x", data[i]);
    }
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    int ret = 0;
    uint8_t signer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t signer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t omega2[SPX_N];
    uint8_t sigma_blind[SPX_BYTES];
    uint8_t public_ctx[12] = {'D', 'E', 'M', 'O', '-', 'F', 'I', 'N', 'A', 'L', 0, 0};
    size_t sigma_blind_len = 0;
    uint32_t magic = 0;
    size_t i = 0;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x33, sizeof(m));
    memset(r, 0x44, sizeof(r));
    for (i = 0; i < sizeof(omega2); i++)
    {
        omega2[i] = (uint8_t)(0x80u + i);
    }

    printf("=== ROLE INTERACTION DEMO (FINAL) ===\n");
    printf("[User]    generate commitment com = Commit(m||r)\n");
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    memcpy(cred.m, m, sizeof(m));
    cred.mlen = sizeof(m);
    memcpy(cred.r, r, sizeof(r));
    cred.rlen = sizeof(r);
    printf("[User]    com[0..7]=0x");
    print_hex_prefix(com, SPX_N, 8);
    printf("\n");

    printf("[Signer]  keygen and sign request(com)\n");
    if (crypto_sign_keypair(signer_pk, signer_sk) != 0)
    {
        printf("FAIL: signer_keygen\n");
        return 1;
    }
    ret = spx_p2_issue_request(com, m, sizeof(m), r, sizeof(r));
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL: issue_request ret=%d\n", ret);
        return 1;
    }
    ret = spx_p2_issue_sign(sigma_blind, &sigma_blind_len, signer_sk, com);
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL: issue_sign ret=%d\n", ret);
        return 1;
    }
    ret = spx_p2_unblind(&cred, com, sigma_blind, sigma_blind_len, omega2, sizeof(omega2));
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL: unblind ret=%d\n", ret);
        return 1;
    }
    memcpy(cred.m, m, sizeof(m));
    cred.mlen = sizeof(m);
    memcpy(cred.r, r, sizeof(r));
    cred.rlen = sizeof(r);
    if (sigma_blind_len != SPX_BYTES)
    {
        printf("FAIL: signer_sign_len\n");
        return 1;
    }
    printf("[Signer]  sig_com issued (%llu bytes)\n", (unsigned long long)sigma_blind_len);

    printf("[User]    run ShowProve(final)\n");
    ret = spx_p2_show_prove(&show_obj, signer_pk, &cred, public_ctx, sizeof(public_ctx));
    if (ret != 0)
    {
        printf("FAIL: show_prove ret=%d\n", ret);
        return 1;
    }
    printf("[User]    show object built: pi_f_len=%llu\n", (unsigned long long)show_obj.pi_f_len);

    printf("[Verifier] run ShowVerify(final)\n");
    ret = spx_p2_show_verify(&show_obj, signer_pk);
    if (ret != 0)
    {
        printf("FAIL: show_verify ret=%d\n", ret);
        return 1;
    }
    printf("[Verifier] ACCEPT\n");

    if (show_obj.pi_f_len < 4u)
    {
        printf("FAIL: pi_f_len_too_small\n");
        return 1;
    }
    magic = load_u32_le(show_obj.pi_f);
    if (magic != SPX_P2_SHOW_PROOF_MAGIC)
    {
        printf("FAIL: proof is not final show-proof format\n");
        return 1;
    }
    printf("[Verifier] proof format: final(show_proof)\n");

    printf("[Verifier] negative test: tamper public_ctx then verify should reject\n");
    show_obj.public_ctx[0] ^= 1u;
    if (spx_p2_show_verify(&show_obj, signer_pk) == 0)
    {
        printf("FAIL: tamper_ctx_should_reject\n");
        return 1;
    }
    printf("[Verifier] REJECT (expected)\n");
    printf("poseidon2_roles_interaction test: OK\n");
    return 0;
}
