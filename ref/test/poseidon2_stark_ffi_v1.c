#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/ffi_v1.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t public_ctx[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t proof_buf[SPX_P2_PI_F_V1_MAX_BYTES];
    size_t siglen = 0;
    uint32_t abi_version = 0;
    spx_p2_ffi_blob_v1 proof;
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;

    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));

    if (spx_p2_ffi_get_abi_version_v1(&abi_version) != SPX_P2_FFI_OK ||
        abi_version != SPX_P2_STARK_FFI_ABI_VERSION_V1)
    {
        fail("abi_version");
        return 1;
    }
    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sig, &siglen, com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }

    proof.data = proof_buf;
    proof.len = 0;
    proof.cap = sizeof(proof_buf);
    pub.pk = pk;
    pub.com = com;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = sizeof(public_ctx);
    wit.sigma_com = sig;

    if (spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit) != SPX_P2_FFI_OK)
    {
        fail("ffi_generate");
        return 1;
    }
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub) != SPX_P2_FFI_OK)
    {
        fail("ffi_verify");
        return 1;
    }

    proof.data[0] ^= 1u;
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub) == SPX_P2_FFI_OK)
    {
        fail("tamper_proof");
        return 1;
    }
    proof.data[0] ^= 1u;

    public_ctx[0] ^= 1u;
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub) == SPX_P2_FFI_OK)
    {
        fail("tamper_ctx");
        return 1;
    }

    printf("poseidon2_stark_ffi_v1 test: OK | abi=%u pi_f_len=%llu\n",
           abi_version, (unsigned long long)proof.len);
    return 0;
}
