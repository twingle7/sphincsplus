#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/show_poseidon2_v1.h"
#include "../stark/pi_f_format_v2.h"

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
    static spx_p2_cred_v1_internal cred;
    static spx_p2_show_v1 show_obj;
    uint8_t signer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t signer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t public_ctx[12] = {'D', 'E', 'M', 'O', '-', 'M', '1', '7', '-', 'V', '2', 0};
    size_t siglen = 0;
    uint32_t magic = 0;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x33, sizeof(m));
    memset(r, 0x44, sizeof(r));

    printf("=== ROLE INTERACTION DEMO (M17) ===\n");
    printf("[User]    generate commitment com = Commit(m||r)\n");
    spx_p2_commit(cred.com, m, sizeof(m), r, sizeof(r));
    printf("[User]    com[0..7]=0x");
    print_hex_prefix(cred.com, SPX_N, 8);
    printf("\n");

    printf("[Signer]  keygen and sign blinded request(com)\n");
    if (crypto_sign_keypair(signer_pk, signer_sk) != 0)
    {
        printf("FAIL: signer_keygen\n");
        return 1;
    }
    if (crypto_sign_signature(cred.sigma_com, &siglen, cred.com, SPX_N, signer_sk) != 0 || siglen != SPX_BYTES)
    {
        printf("FAIL: signer_sign\n");
        return 1;
    }
    printf("[Signer]  sigma_blind issued (%llu bytes)\n", (unsigned long long)siglen);

    printf("[User]    unblind (engineering placeholder) and run ShowProve(v2-strict)\n");
    if (spx_p2_show_prove_v2_strict(&show_obj, signer_pk, &cred, public_ctx, sizeof(public_ctx)) != 0)
    {
        printf("FAIL: show_prove_v2_strict (hint: enable Rust STARK backend for real v2 proof)\n");
        return 1;
    }
    printf("[User]    show object built: pi_f_len=%llu\n", (unsigned long long)show_obj.pi_f_len);

    printf("[Verifier] run ShowVerify(v2-strict)\n");
    if (spx_p2_show_verify_v2_strict(&show_obj, signer_pk) != 0)
    {
        printf("FAIL: show_verify_v2_strict\n");
        return 1;
    }
    printf("[Verifier] ACCEPT\n");

    if (show_obj.pi_f_len < 4u)
    {
        printf("FAIL: pi_f_len_too_small\n");
        return 1;
    }
    magic = load_u32_le(show_obj.pi_f);
    if (magic == SPX_P2_PI_F_V2_MAGIC)
    {
        printf("[Verifier] proof format: pi_F_v2\n");
    }
    else
    {
        printf("FAIL: proof is not pi_F_v2 in strict mode\n");
        return 1;
    }

    printf("[Verifier] negative test: tamper public_ctx then verify should reject\n");
    show_obj.public_ctx[0] ^= 1u;
    if (spx_p2_show_verify_v2_strict(&show_obj, signer_pk) == 0)
    {
        printf("FAIL: tamper_ctx_should_reject\n");
        return 1;
    }
    printf("[Verifier] REJECT (expected)\n");
    printf("poseidon2_roles_interaction_v2: OK\n");
    return 0;
}
