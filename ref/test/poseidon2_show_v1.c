#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/show_poseidon2_v1.h"
#include "../stark/pi_f_format_v1.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

static void fail_with_code(const char *name, int code)
{
    printf("FAIL: %s (ret=%d)\n", name, code);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t public_ctx[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t m[24];
    uint8_t r[16];
    size_t siglen = 0;
    spx_p2_cred_v1_internal cred;
    spx_p2_show_v1 show;

    memset(&cred, 0, sizeof(cred));
    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));
    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(cred.com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(cred.sigma_com, &siglen, cred.com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }
    if (spx_p2_show_prove_m10_skeleton_v1(&show, pk, &cred, public_ctx, sizeof(public_ctx)) != 0)
    {
        fail("show_prove");
        return 1;
    }
    if (spx_p2_show_verify_m10_skeleton_v1(&show, pk) != 0)
    {
        fail("show_verify");
        return 1;
    }

    show.com[0] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_com");
            return 1;
        }
    }
    show.com[0] ^= 1u;

    show.pi_f[show.pi_f_len - 1] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_pi_f");
            return 1;
        }
    }
    show.pi_f[show.pi_f_len - 1] ^= 1u;

    show.public_ctx[0] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_public_ctx");
            return 1;
        }
    }
    show.public_ctx[0] ^= 1u;

    show.pi_f[0] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_magic");
            return 1;
        }
    }
    show.pi_f[0] ^= 1u;

    show.pi_f[12] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_header_len");
            return 1;
        }
    }
    show.pi_f[12] ^= 1u;

    show.pi_f[16] ^= 1u;
    {
        int ret = spx_p2_show_verify_m10_skeleton_v1(&show, pk);
        if (ret == 0)
        {
            fail("tamper_total_len");
            return 1;
        }
        if (ret != -1)
        {
            fail_with_code("tamper_total_len_unexpected_ret", ret);
            return 1;
        }
    }
    show.pi_f[16] ^= 1u;

    printf("poseidon2_show_v1 test: OK | pi_f_len=%llu\n",
           (unsigned long long)show.pi_f_len);
    return 0;
}
