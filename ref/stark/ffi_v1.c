#include <stddef.h>
#include <stdint.h>

#include "ffi_v1.h"
#include "verifier_v1.h"

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_get_abi_version_v1(uint32_t *out_version);
extern int spx_p2_rust_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                        const spx_p2_ffi_public_inputs_v1 *pub,
                                        const spx_p2_ffi_private_witness_v1 *wit);
extern int spx_p2_rust_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                                      const spx_p2_ffi_public_inputs_v1 *pub);
#endif

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
    if (proof == 0 || pub == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    if (proof->data == 0 || pub->pk == 0 || pub->com == 0 ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0))
    {
        return SPX_P2_FFI_ERR_INPUT;
    }
#ifdef SPX_P2_USE_RUST_STARK
    {
        int ret = spx_p2_rust_verify_pi_f_v1(proof, pub);
        return (ret == 0) ? SPX_P2_FFI_OK : SPX_P2_FFI_ERR_VERIFY;
    }
#else
    if (spx_p2_verifier_verify_pi_f_v1(pub->pk, pub->com, proof->data, proof->len,
                                       pub->public_ctx, pub->public_ctx_len) != 0)
    {
        return SPX_P2_FFI_ERR_VERIFY;
    }
    return SPX_P2_FFI_OK;
#endif
}
