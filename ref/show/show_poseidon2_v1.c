#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "show_poseidon2_v1.h"

static int spx_p2_debug_verify_enabled(void)
{
    return getenv("SPX_P2_DEBUG_VERIFY") != 0;
}

int spx_p2_show_from_internal_v1(spx_p2_show_v1 *out,
                                 const spx_p2_cred_v1_internal *cred,
                                 const uint8_t *public_ctx, size_t public_ctx_len)
{
    if (out == 0 || cred == 0)
    {
        return -1;
    }
    if (public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->com, cred->com, SPX_N);

    /*
     * M5 boundary freeze:
     * - pi_f is carried from private material placeholder
     * - real STARK proof object wiring is done in M10
     */
    memcpy(out->pi_f, cred->trace.lanes, (SPX_N <= sizeof(cred->trace.lanes)) ? SPX_N : sizeof(cred->trace.lanes));
    out->pi_f_len = SPX_N;

    if (public_ctx_len > 0)
    {
        memcpy(out->public_ctx, public_ctx, public_ctx_len);
    }
    out->public_ctx_len = public_ctx_len;
    return 0;
}

int spx_p2_show_verify_shape_v1(const spx_p2_show_v1 *show)
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
    if (memcmp(show->com, zero, SPX_N) == 0)
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

int spx_p2_show_prove_m10_skeleton_v1(spx_p2_show_v1 *out,
                                      const uint8_t *pk,
                                      const spx_p2_cred_v1_internal *cred,
                                      const uint8_t *public_ctx,
                                      size_t public_ctx_len)
{
    spx_p2_ffi_blob_v1 proof_blob;
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;
    if (out == 0 || pk == 0 || cred == 0)
    {
        return -1;
    }
    if (public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->com, cred->com, SPX_N);
    proof_blob.data = out->pi_f;
    proof_blob.len = 0;
    proof_blob.cap = sizeof(out->pi_f);
    pub.pk = pk;
    pub.com = cred->com;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = public_ctx_len;
    wit.sigma_com = cred->sigma_com;
    if (spx_p2_ffi_generate_pi_f_v1(&proof_blob, &pub, &wit) != SPX_P2_FFI_OK)
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

int spx_p2_show_verify_m10_skeleton_v1(const spx_p2_show_v1 *show,
                                       const uint8_t *pk)
{
    spx_p2_ffi_blob_v1 proof_blob;
    spx_p2_ffi_public_inputs_v1 pub;
    if (show == 0 || pk == 0)
    {
        return -1;
    }
    if (spx_p2_show_verify_shape_v1(show) != 0)
    {
        return -1;
    }
    proof_blob.data = (uint8_t *)show->pi_f;
    proof_blob.len = show->pi_f_len;
    proof_blob.cap = show->pi_f_len;
    pub.pk = pk;
    pub.com = show->com;
    pub.public_ctx = show->public_ctx;
    pub.public_ctx_len = show->public_ctx_len;
    return (spx_p2_ffi_verify_pi_f_v1(&proof_blob, &pub) == SPX_P2_FFI_OK) ? 0 : -1;
}

int spx_p2_show_prove_v2_strict(spx_p2_show_v1 *out,
                                const uint8_t *pk,
                                const spx_p2_cred_v1_internal *cred,
                                const uint8_t *public_ctx,
                                size_t public_ctx_len)
{
    spx_p2_ffi_blob_v1 proof_blob;
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;
    if (out == 0 || pk == 0 || cred == 0)
    {
        return -1;
    }
    if (public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->com, cred->com, SPX_N);
    proof_blob.data = out->pi_f;
    proof_blob.len = 0;
    proof_blob.cap = sizeof(out->pi_f);
    pub.pk = pk;
    pub.com = cred->com;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = public_ctx_len;
    wit.sigma_com = cred->sigma_com;
    if (spx_p2_ffi_generate_pi_f_v2_strict(&proof_blob, &pub, &wit) != SPX_P2_FFI_OK)
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

int spx_p2_show_verify_v2_strict(const spx_p2_show_v1 *show,
                                 const uint8_t *pk)
{
    spx_p2_ffi_blob_v1 proof_blob;
    spx_p2_ffi_public_inputs_v1 pub;
    int ret;
    if (show == 0 || pk == 0)
    {
        return -1;
    }
    if (spx_p2_show_verify_shape_v1(show) != 0)
    {
        return -1;
    }
    proof_blob.data = (uint8_t *)show->pi_f;
    proof_blob.len = show->pi_f_len;
    proof_blob.cap = show->pi_f_len;
    pub.pk = pk;
    pub.com = show->com;
    pub.public_ctx = show->public_ctx;
    pub.public_ctx_len = show->public_ctx_len;
    ret = spx_p2_ffi_verify_pi_f_v2_strict(&proof_blob, &pub);
    if (spx_p2_debug_verify_enabled())
    {
        fprintf(stderr,
                "[show_v2_strict] verify ret=%d pi_f_len=%llu ctx_len=%llu\n",
                ret,
                (unsigned long long)show->pi_f_len,
                (unsigned long long)show->public_ctx_len);
    }
    return (ret == SPX_P2_FFI_OK) ? 0 : -1;
}
