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
    uint8_t public_ctx[8] = {9, 8, 7, 6, 5, 4, 3, 2};
    size_t siglen = 0;
    size_t commitment_off;
    size_t proof_len_off;
    size_t proof_bytes_off;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));

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

    commitment_off = SPX_P2_PI_F_FIXED_HEADER_BYTES + SPX_N + SPX_N;
    if (show_obj.pi_f_len <= commitment_off)
    {
        fail("len_commitment_off");
        return 1;
    }
    show_obj.pi_f[commitment_off] ^= 1u;
    if (spx_p2_show_verify(&show_obj, pk) == 0)
    {
        fail("tamper_commitment_should_reject");
        return 1;
    }
    show_obj.pi_f[commitment_off] ^= 1u;

    proof_len_off = SPX_P2_PI_F_FIXED_HEADER_BYTES + (size_t)SPX_N * 3u;
    proof_bytes_off = proof_len_off + 4u;
    if (show_obj.pi_f_len <= proof_bytes_off)
    {
        fail("len_proof_off");
        return 1;
    }
    show_obj.pi_f[proof_bytes_off] ^= 1u;
    if (spx_p2_show_verify(&show_obj, pk) == 0)
    {
        fail("tamper_proof_should_reject");
        return 1;
    }
    show_obj.pi_f[proof_bytes_off] ^= 1u;

    printf("poseidon2_trace_replay_binding test: OK | pi_f_len=%llu\n",
           (unsigned long long)show_obj.pi_f_len);
    return 0;
}
