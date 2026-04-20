#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "ffi_v1.h"
#include "pi_f_format_v1.h"
#include "pi_f_format_v2.h"
#include "verifier_v1.h"

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_get_abi_version_v1(uint32_t *out_version);
extern int spx_p2_rust_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                        const spx_p2_ffi_public_inputs_v1 *pub,
                                        const spx_p2_ffi_private_witness_v1 *wit);
extern int spx_p2_rust_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                                      const spx_p2_ffi_public_inputs_v1 *pub);
#endif

static uint32_t spx_p2_load_u32_le(const uint8_t *in)
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static int spx_p2_detect_pi_f_version(const uint8_t *proof, size_t proof_len)
{
    uint32_t magic;
    if (proof == 0 || proof_len < 8u)
    {
        return 0;
    }
    magic = spx_p2_load_u32_le(proof);
    if (magic == SPX_P2_PI_F_V1_MAGIC)
    {
        return 1;
    }
    if (magic == SPX_P2_PI_F_V2_MAGIC)
    {
        return 2;
    }
    return 0;
}

int spx_p2_ffi_get_abi_version_v1(uint32_t *out_version)
{
#ifdef SPX_P2_USE_RUST_STARK
    return spx_p2_rust_get_abi_version_v1(out_version);
#else
    if (out_version == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    *out_version = SPX_P2_STARK_FFI_ABI_VERSION_V1;
    return SPX_P2_FFI_OK;
#endif
}

int spx_p2_ffi_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                const spx_p2_ffi_public_inputs_v1 *pub,
                                const spx_p2_ffi_private_witness_v1 *wit)
{
    if (out_proof == 0 || pub == 0 || wit == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    if (out_proof->data == 0 || pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0 ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0))
    {
        return SPX_P2_FFI_ERR_INPUT;
    }
#ifdef SPX_P2_USE_RUST_STARK
    {
        if (out_proof->cap == 0)
        {
            return SPX_P2_FFI_ERR_BUFFER_SMALL;
        }
        int ret = spx_p2_rust_generate_pi_f_v1(out_proof, pub, wit);
        return (ret == 0) ? SPX_P2_FFI_OK : SPX_P2_FFI_ERR_PROVE;
    }
#else
    if (out_proof->cap < SPX_P2_PI_F_V1_MAX_BYTES)
    {
        return SPX_P2_FFI_ERR_BUFFER_SMALL;
    }
    if (spx_p2_prover_generate_pi_f_v1(out_proof->data, &out_proof->len, out_proof->cap,
                                       pub->pk, pub->com, wit->sigma_com,
                                       pub->public_ctx, pub->public_ctx_len) != 0)
    {
        return SPX_P2_FFI_ERR_PROVE;
    }
    return SPX_P2_FFI_OK;
#endif
}

int spx_p2_ffi_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                              const spx_p2_ffi_public_inputs_v1 *pub)
{
    int pi_f_ver;
    if (proof == 0 || pub == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    if (proof->data == 0 || pub->pk == 0 || pub->com == 0 ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0))
    {
        return SPX_P2_FFI_ERR_INPUT;
    }
    pi_f_ver = spx_p2_detect_pi_f_version(proof->data, proof->len);
    if (pi_f_ver == 1)
    {
        if (spx_p2_verifier_verify_pi_f_v1(pub->pk, pub->com, proof->data, proof->len,
                                           pub->public_ctx, pub->public_ctx_len) != 0)
        {
            return SPX_P2_FFI_ERR_VERIFY;
        }
        return SPX_P2_FFI_OK;
    }
    if (pi_f_ver != 2)
    {
        return SPX_P2_FFI_ERR_VERIFY;
    }
#ifdef SPX_P2_USE_RUST_STARK
    {
        int ret = spx_p2_rust_verify_pi_f_v1(proof, pub);
        return (ret == 0) ? SPX_P2_FFI_OK : SPX_P2_FFI_ERR_VERIFY;
    }
#else
    return SPX_P2_FFI_ERR_VERIFY;
#endif
}

int spx_p2_ffi_generate_pi_f_v2_strict(spx_p2_ffi_blob_v1 *out_proof,
                                       const spx_p2_ffi_public_inputs_v1 *pub,
                                       const spx_p2_ffi_private_witness_v1 *wit)
{
    int ret;
    int ver;
    if (out_proof == 0 || pub == 0 || wit == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    if (pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0)
    {
        return SPX_P2_FFI_ERR_INPUT;
    }
    /* Strict mode must prove existence of a valid signature witness before STARK proving. */
    if (spx_p2_verify_com(pub->pk, pub->com, wit->sigma_com) != 0)
    {
        return SPX_P2_FFI_ERR_PROVE;
    }
    ret = spx_p2_ffi_generate_pi_f_v1(out_proof, pub, wit);
    if (ret != SPX_P2_FFI_OK)
    {
        return ret;
    }
    ver = spx_p2_detect_pi_f_version(out_proof->data, out_proof->len);
    if (ver != 2)
    {
        return SPX_P2_FFI_ERR_PROVE;
    }
    return SPX_P2_FFI_OK;
}

int spx_p2_ffi_verify_pi_f_v2_strict(const spx_p2_ffi_blob_v1 *proof,
                                     const spx_p2_ffi_public_inputs_v1 *pub)
{
    int ver;
    if (proof == 0 || proof->data == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    ver = spx_p2_detect_pi_f_version(proof->data, proof->len);
    if (ver != 2)
    {
        return SPX_P2_FFI_ERR_VERIFY;
    }
    return spx_p2_ffi_verify_pi_f_v1(proof, pub);
}
