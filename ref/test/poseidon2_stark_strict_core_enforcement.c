#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../randombytes.h"
#include "../stark/ffi.h"
#include "../stark/relation_migration_v1.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t sigma_com[SPX_BYTES];
    uint8_t sigma_com_bad[SPX_BYTES];
    uint8_t sigma_c[2 * SPX_N];
    uint8_t sigma_c_bad[2 * SPX_N];
    uint8_t pk_sig_bad[CRYPTO_PUBLICKEYBYTES];
    uint8_t pk_e_bad[SPX_N];
    uint8_t m_pub_bad[24];
    uint8_t m_wit_bad[24];
    uint8_t r_bad[16];
    uint8_t omega2_bad[SPX_N];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t omega2[SPX_N];
    uint8_t public_ctx[8] = {9, 1, 4, 1, 9, 2, 6, 5};
    uint8_t public_ctx_bad[8];
    uint8_t *proof_buf = 0;
    size_t sigma_len = 0;
    size_t sigma_c_len = 0;
    spx_p2_ffi_blob proof;
    spx_p2_ffi_public_inputs pub;
    spx_p2_ffi_public_inputs pub_bad_pk_sig;
    spx_p2_ffi_private_witness wit;
    spx_p2_ffi_private_witness wit_bad_m;
    spx_p2_ffi_private_witness wit_bad_r;
    spx_p2_ffi_private_witness wit_bad_sig;
    spx_p2_ffi_private_witness wit_bad_omega2;
    spx_p2_ffi_private_witness wit_missing_omega2;
    spx_p2_ffi_public_inputs pub_bad_sigma_c;
    spx_p2_ffi_public_inputs pub_bad_pk_e;
    spx_p2_ffi_public_inputs pub_bad_m_pub;
    spx_p2_ffi_public_inputs pub_bad_public_ctx;
    spx_p2_ffi_public_inputs pub_missing_m_pub;
    int ret;

    memset(m, 0x27, sizeof(m));
    memset(r, 0x64, sizeof(r));
    memset(&proof, 0, sizeof(proof));
    memset(&pub, 0, sizeof(pub));
    memset(&pub_bad_pk_sig, 0, sizeof(pub_bad_pk_sig));
    memset(&wit, 0, sizeof(wit));
    memset(&wit_bad_m, 0, sizeof(wit_bad_m));
    memset(&wit_bad_r, 0, sizeof(wit_bad_r));
    memset(&wit_bad_sig, 0, sizeof(wit_bad_sig));
    memset(&wit_bad_omega2, 0, sizeof(wit_bad_omega2));
    memset(&wit_missing_omega2, 0, sizeof(wit_missing_omega2));
    memset(&pub_bad_sigma_c, 0, sizeof(pub_bad_sigma_c));
    memset(&pub_bad_pk_e, 0, sizeof(pub_bad_pk_e));
    memset(&pub_bad_m_pub, 0, sizeof(pub_bad_m_pub));

    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sigma_com, &sigma_len, com, SPX_N, sk) != 0 || sigma_len != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }
    randombytes(omega2, SPX_N);
    if (spx_p2_build_sigma_c_m20_pke(sigma_c, &sigma_c_len,
                                     com, sigma_com,
                                     pk, SPX_N,
                                     omega2, sizeof(omega2)) != 0 ||
        sigma_c_len != 2u * SPX_N)
    {
        fail("build_sigma_c");
        return 1;
    }

    proof_buf = (uint8_t *)malloc(1024u * 1024u);
    if (proof_buf == 0)
    {
        fail("alloc_proof_buf");
        return 1;
    }
    proof.data = proof_buf;
    proof.len = 0;
    proof.cap = 1024u * 1024u;

    pub.pk = pk;
    pub.pk_e = pk;
    pub.pk_e_len = SPX_N;
    pub.com = com;
    pub.sigma_c = sigma_c;
    pub.sigma_c_len = sigma_c_len;
    pub.m_pub = m;
    pub.m_pub_len = sizeof(m);
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = sizeof(public_ctx);

    wit.sigma_com = sigma_com;
    wit.m = m;
    wit.mlen = sizeof(m);
    wit.r = r;
    wit.rlen = sizeof(r);
    wit.omega2 = omega2;
    wit.omega2_len = sizeof(omega2);
    wit_bad_m = wit;
    wit_bad_r = wit;
    wit_missing_omega2 = wit;
    wit_missing_omega2.omega2 = 0;
    wit_missing_omega2.omega2_len = 0;

    pub_bad_pk_sig = pub;
    memcpy(pk_sig_bad, pk, sizeof(pk_sig_bad));
    pk_sig_bad[0] ^= 1u;
    pub_bad_pk_sig.pk = pk_sig_bad;

    memcpy(public_ctx_bad, public_ctx, sizeof(public_ctx_bad));
    public_ctx_bad[0] ^= 1u;
    pub_bad_public_ctx = pub;
    pub_bad_public_ctx.public_ctx = public_ctx_bad;

    pub_missing_m_pub = pub;
    pub_missing_m_pub.m_pub = 0;
    pub_missing_m_pub.m_pub_len = 0;

    memcpy(m_wit_bad, m, sizeof(m_wit_bad));
    m_wit_bad[0] ^= 1u;
    wit_bad_m.m = m_wit_bad;

    memcpy(r_bad, r, sizeof(r_bad));
    r_bad[0] ^= 1u;
    wit_bad_r.r = r_bad;

    if (spx_p2_relation_validate_strict_prove_inputs_v1(&pub, &wit) != SPX_P2_FFI_OK)
    {
        fail("strict_prove_inputs_baseline");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_relation_validate_strict_verify_inputs_v1(&pub) != SPX_P2_FFI_OK)
    {
        fail("strict_verify_inputs_baseline");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_relation_precheck_strict_prove_witness_v1(&pub, &wit) != SPX_P2_FFI_OK)
    {
        fail("strict_prove_witness_baseline");
        free(proof_buf);
        return 1;
    }

    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit);
    if (ret != SPX_P2_FFI_OK)
    {
        printf("INFO: generate ret=%d\n", ret);
        fail("generate_v1_with_strict_inputs");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub) != SPX_P2_FFI_OK)
    {
        fail("verify_v1_with_strict_inputs");
        free(proof_buf);
        return 1;
    }

    /* G1: Com(m_pub; r) must be bound to the prove witness. */
    if (spx_p2_relation_validate_strict_prove_inputs_v1(&pub, &wit_bad_m) == SPX_P2_FFI_OK)
    {
        fail("g1_bad_m_should_reject_prove_inputs");
        free(proof_buf);
        return 1;
    }
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit_bad_m);
    if (ret == SPX_P2_FFI_OK)
    {
        fail("g1_bad_m_should_reject_prove");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_relation_precheck_strict_prove_witness_v1(&pub, &wit_bad_r) == SPX_P2_FFI_OK)
    {
        fail("g1_bad_r_should_reject_witness");
        free(proof_buf);
        return 1;
    }
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit_bad_r);
    if (ret == SPX_P2_FFI_OK)
    {
        fail("g1_bad_r_should_reject_prove");
        free(proof_buf);
        return 1;
    }

    /* G2: Verify(pk, c, sigma') must stay bound to issuer public key and blind signature. */
    if (spx_p2_relation_precheck_strict_prove_witness_v1(&pub_bad_pk_sig, &wit) == SPX_P2_FFI_OK)
    {
        fail("g2_bad_pk_sig_should_reject_witness");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_pk_sig) == SPX_P2_FFI_OK)
    {
        fail("verify_tamper_pk_sig_should_reject");
        free(proof_buf);
        return 1;
    }
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub_bad_pk_sig, &wit);
    if (ret == SPX_P2_FFI_OK &&
        spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_pk_sig) == SPX_P2_FFI_OK)
    {
        fail("g2_bad_pk_sig_should_fail_prove_or_verify");
        free(proof_buf);
        return 1;
    }

    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit_missing_omega2);
    if (ret == SPX_P2_FFI_OK)
    {
        fail("generate_v1_without_omega2_should_reject");
        free(proof_buf);
        return 1;
    }

    /* G4: final public statement must stay explicit in public_ctx and m_pub. */
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_public_ctx) == SPX_P2_FFI_OK)
    {
        fail("verify_tamper_public_ctx_should_reject");
        free(proof_buf);
        return 1;
    }
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_missing_m_pub) == SPX_P2_FFI_OK)
    {
        fail("verify_missing_m_pub_should_reject");
        free(proof_buf);
        return 1;
    }
    pub_bad_sigma_c = pub;
    memcpy(sigma_c_bad, sigma_c, sizeof(sigma_c_bad));
    sigma_c_bad[SPX_N] ^= 1u;
    pub_bad_sigma_c.sigma_c = sigma_c_bad;
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_sigma_c) == SPX_P2_FFI_OK)
    {
        fail("verify_tamper_sigma_c_should_reject");
        free(proof_buf);
        return 1;
    }
    pub_bad_m_pub = pub;
    memcpy(m_pub_bad, m, sizeof(m_pub_bad));
    m_pub_bad[0] ^= 1u;
    pub_bad_m_pub.m_pub = m_pub_bad;
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_m_pub) == SPX_P2_FFI_OK)
    {
        fail("verify_tamper_m_pub_should_reject");
        free(proof_buf);
        return 1;
    }
    pub_bad_pk_e = pub;
    memcpy(pk_e_bad, pk, sizeof(pk_e_bad));
    pk_e_bad[0] ^= 1u;
    pub_bad_pk_e.pk_e = pk_e_bad;
    if (spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_pk_e) == SPX_P2_FFI_OK)
    {
        fail("verify_tamper_pk_e_should_reject");
        free(proof_buf);
        return 1;
    }

    wit_bad_sig = wit;
    memcpy(sigma_com_bad, sigma_com, sizeof(sigma_com_bad));
    sigma_com_bad[0] ^= 1u;
    wit_bad_sig.sigma_com = sigma_com_bad;
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit_bad_sig);
    if (ret == SPX_P2_FFI_OK &&
        spx_p2_ffi_verify_pi_f_v1(&proof, &pub) == SPX_P2_FFI_OK)
    {
        fail("tamper_sigma_com_should_fail_prove_or_verify");
        free(proof_buf);
        return 1;
    }

    wit_bad_omega2 = wit;
    memcpy(omega2_bad, omega2, sizeof(omega2_bad));
    omega2_bad[0] ^= 1u;
    wit_bad_omega2.omega2 = omega2_bad;
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub, &wit_bad_omega2);
    if (ret == SPX_P2_FFI_OK &&
        spx_p2_ffi_verify_pi_f_v1(&proof, &pub) == SPX_P2_FFI_OK)
    {
        fail("tamper_omega2_should_fail_prove_or_verify");
        free(proof_buf);
        return 1;
    }

    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub_bad_sigma_c, &wit);
    if (ret == SPX_P2_FFI_OK &&
        spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_sigma_c) == SPX_P2_FFI_OK)
    {
        fail("tamper_sigma_c_should_fail_prove_or_verify");
        free(proof_buf);
        return 1;
    }
    ret = spx_p2_ffi_generate_pi_f_v1(&proof, &pub_bad_pk_e, &wit);
    if (ret == SPX_P2_FFI_OK &&
        spx_p2_ffi_verify_pi_f_v1(&proof, &pub_bad_pk_e) == SPX_P2_FFI_OK)
    {
        fail("tamper_pk_e_should_fail_prove_or_verify");
        free(proof_buf);
        return 1;
    }

    printf("poseidon2_stark_strict_core_enforcement test: OK | pi_f_len=%llu\n",
           (unsigned long long)proof.len);
    free(proof_buf);
    return 0;
}
