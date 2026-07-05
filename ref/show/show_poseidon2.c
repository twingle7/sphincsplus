#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "show_poseidon2.h"

int spx_p2_show_extract_commitment(uint8_t out_com[SPX_N],
                                   const spx_p2_show *show)
{
    if (out_com == 0 || show == 0 || show->sigma_C_len < SPX_N)
    {
        return -1;
    }
    memcpy(out_com, show->sigma_C, SPX_N);
    return 0;
}

static int spx_p2_build_sigma_c_from_ciphertext_witness(uint8_t *out_sigma_c,
                                                        size_t *out_sigma_c_len,
                                                        const uint8_t *pk_e,
                                                        size_t pk_e_len,
                                                        const spx_p2_cred_internal *cred)
{
    if (out_sigma_c == 0 || out_sigma_c_len == 0 || pk_e == 0 || cred == 0)
    {
        return -1;
    }
    if (pk_e_len < SPX_N || cred->omega2_len != SPX_N)
    {
        return -1;
    }
    return spx_p2_build_sigma_c_ciphertext(out_sigma_c, out_sigma_c_len,
                                           cred->com, cred->sigma_com,
                                           pk_e, pk_e_len,
                                           cred->omega2, cred->omega2_len);
}

static int spx_p2_sigma_c_is_valid(const spx_p2_show *show)
{
    static const uint8_t zero[SPX_N] = {0};
    if (show == 0)
    {
        return 0;
    }
    if (show->sigma_C_len != (2u * SPX_N))
    {
        return 0;
    }
    if (memcmp(show->sigma_C, zero, SPX_N) == 0)
    {
        return 0;
    }
    return 1;
}

static int spx_p2_cred_opening_matches_com(const spx_p2_cred_internal *cred)
{
    uint8_t expected_com[SPX_N];
    if (cred == 0 || cred->mlen == 0 || cred->rlen == 0)
    {
        return 0;
    }
    spx_p2_commit(expected_com, cred->m, cred->mlen, cred->r, cred->rlen);
    return (memcmp(expected_com, cred->com, SPX_N) == 0) ? 1 : 0;
}

static int spx_p2_show_verify_shape(const spx_p2_show *show)
{
    static const uint8_t zero[SPX_N] = {0};

    if (show == 0)
    {
        return -1;
    }
    if (show->public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }
    if (show->m_pub_len > sizeof(show->m_pub))
    {
        return -1;
    }
    if (show->sigma_C_len != (2u * SPX_N))
    {
        return -1;
    }
    if (memcmp(show->sigma_C, zero, SPX_N) == 0)
    {
        return -1;
    }
    if (show->pi_f_len == 0 || show->pi_f_len > sizeof(show->pi_f))
    {
        return -1;
    }
    if (memcmp(show->pi_f, zero, SPX_N) == 0)
    {
        return -1;
    }
    return 0;
}

int spx_p2_show_prove(spx_p2_show *out,
                      const uint8_t *pk,
                      const spx_p2_cred_internal *cred,
                      const uint8_t *public_ctx,
                      size_t public_ctx_len)
{
    return spx_p2_show_prove_statement_bound(out, pk, pk, SPX_N, cred, public_ctx, public_ctx_len);
}

int spx_p2_show_prove_statement_bound(spx_p2_show *out,
                                      const uint8_t *pk_sig,
                                      const uint8_t *pk_e,
                                      size_t pk_e_len,
                                      const spx_p2_cred_internal *cred,
                                      const uint8_t *public_ctx,
                                      size_t public_ctx_len)
{
    spx_p2_ffi_blob proof_blob;
    spx_p2_ffi_public_inputs pub;
    spx_p2_ffi_private_witness wit;
    if (out == 0 || pk_sig == 0 || pk_e == 0 || pk_e_len < SPX_N || cred == 0)
    {
        return -1;
    }
    if (public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }
    if (cred->mlen == 0 || cred->rlen == 0 || cred->omega2_len != SPX_N || !spx_p2_cred_opening_matches_com(cred))
    {
        return -1;
    }
    if (cred->mlen > sizeof(out->m_pub))
    {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    if (spx_p2_build_sigma_c_from_ciphertext_witness(out->sigma_C, &out->sigma_C_len, pk_e, pk_e_len, cred) != 0)
    {
        return -1;
    }
    memcpy(out->m_pub, cred->m, cred->mlen);
    out->m_pub_len = cred->mlen;
    proof_blob.data = out->pi_f;
    proof_blob.len = 0;
    proof_blob.cap = sizeof(out->pi_f);
    pub.pk = pk_sig;
    pub.pk_e = pk_e;
    pub.pk_e_len = pk_e_len;
    pub.com = cred->com;
    pub.m_pub = cred->m;
    pub.m_pub_len = cred->mlen;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = public_ctx_len;
    pub.sigma_c = out->sigma_C;
    pub.sigma_c_len = out->sigma_C_len;
    wit.sigma_com = cred->sigma_com;
    wit.m = cred->m;
    wit.mlen = cred->mlen;
    wit.r = cred->r;
    wit.rlen = cred->rlen;
    wit.omega2 = cred->omega2;
    wit.omega2_len = cred->omega2_len;
    if (spx_p2_ffi_generate_pi_f(&proof_blob, &pub, &wit) != SPX_P2_FFI_STATUS_OK)
    {
        return -1;
    }
    out->pi_f_len = proof_blob.len;
    if (public_ctx_len > 0)
    {
        memcpy(out->public_ctx, public_ctx, public_ctx_len);
    }
    out->public_ctx_len = public_ctx_len;
    return 0;
}

int spx_p2_show_verify(const spx_p2_show *show,
                       const uint8_t *pk)
{
    if (show == 0 || show->m_pub_len == 0)
    {
        return -1;
    }
    return spx_p2_show_verify_statement_bound(show, pk, pk, SPX_N, show->m_pub, show->m_pub_len);
}

int spx_p2_show_verify_statement_bound(const spx_p2_show *show,
                                       const uint8_t *pk_sig,
                                       const uint8_t *pk_e,
                                       size_t pk_e_len,
                                       const uint8_t *m_pub,
                                       size_t m_pub_len)
{
    spx_p2_ffi_blob proof_blob;
    spx_p2_ffi_public_inputs pub;
    int ret;
    if (show == 0 || pk_sig == 0 || pk_e == 0 || m_pub == 0 || m_pub_len == 0 || pk_e_len < SPX_N)
    {
        return -1;
    }
    if (spx_p2_show_verify_shape(show) != 0 || !spx_p2_sigma_c_is_valid(show))
    {
        return -1;
    }
    proof_blob.data = (uint8_t *)show->pi_f;
    proof_blob.len = show->pi_f_len;
    proof_blob.cap = show->pi_f_len;
    pub.pk = pk_sig;
    pub.pk_e = pk_e;
    pub.pk_e_len = pk_e_len;
    pub.com = show->sigma_C;
    pub.m_pub = m_pub;
    pub.m_pub_len = m_pub_len;
    pub.public_ctx = show->public_ctx;
    pub.public_ctx_len = show->public_ctx_len;
    pub.sigma_c = show->sigma_C;
    pub.sigma_c_len = show->sigma_C_len;
    ret = spx_p2_ffi_verify_pi_f(&proof_blob, &pub);
    return (ret == SPX_P2_FFI_STATUS_OK) ? 0 : -1;
}
