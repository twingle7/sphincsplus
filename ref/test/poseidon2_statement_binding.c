#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/show_poseidon2.h"
#include "../stark/pi_f_format.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t public_ctx[8] = {3, 1, 4, 1, 5, 9, 2, 6};
    size_t siglen = 0;
    size_t statement_ver_off = 24u;
    size_t pid_off = SPX_P2_PI_F_FIXED_HEADER_BYTES;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x21, sizeof(m));
    memset(r, 0x12, sizeof(r));

    spx_p2_commit(cred.com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    if (crypto_sign_signature(cred.sigma_com, &siglen, cred.com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }
    if (spx_p2_show_prove(&show_obj, pk, &cred, public_ctx, sizeof(public_ctx)) != 0)
    {
        fail("show_prove");
        return 1;
    }
    if (spx_p2_show_verify(&show_obj, pk) != 0)
    {
        fail("show_verify");
        return 1;
    }

    if (show_obj.pi_f_len <= statement_ver_off)
    {
        fail("len_statement_off");
        return 1;
    }
    show_obj.pi_f[statement_ver_off] ^= 1u;
    if (spx_p2_show_verify(&show_obj, pk) == 0)
    {
        fail("tamper_statement_version_should_reject");
        return 1;
    }
    show_obj.pi_f[statement_ver_off] ^= 1u;

    if (show_obj.pi_f_len <= pid_off)
    {
        fail("len_public_input_digest_off");
        return 1;
    }
    show_obj.pi_f[pid_off] ^= 1u;
    if (spx_p2_show_verify(&show_obj, pk) == 0)
    {
        fail("tamper_public_input_digest_should_reject");
        return 1;
    }
    show_obj.pi_f[pid_off] ^= 1u;

    printf("poseidon2_statement_binding test: OK | pi_f_len=%llu\n",
           (unsigned long long)show_obj.pi_f_len);
    return 0;
}
