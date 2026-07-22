#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "ffi.h"
#include "pi_f_format_v2.h"

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_get_abi_version_full_air(uint32_t *out_version);
extern int spx_p2_rust_generate_pi_f_full_air(spx_p2_ffi_blob *out_proof,
                                               const spx_p2_ffi_public_inputs *pub,
                                               const spx_p2_ffi_private_witness *wit);
extern int spx_p2_rust_verify_pi_f_full_air(const spx_p2_ffi_blob *proof,
                                             const spx_p2_ffi_public_inputs *pub);
#endif

int spx_p2_ffi_get_abi_version(uint32_t *out_version)
{
#ifdef SPX_P2_USE_RUST_STARK
    return spx_p2_rust_get_abi_version_full_air(out_version);
#else
    if (out_version == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    *out_version = SPX_P2_STARK_FFI_ABI_VERSION;
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_ffi_generate_pi_f(spx_p2_ffi_blob *out_proof,
                             const spx_p2_ffi_public_inputs *pub,
                             const spx_p2_ffi_private_witness *wit)
{
    if (out_proof == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    return spx_p2_ffi_generate_pi_f_full_air(out_proof, pub, wit);
}

int spx_p2_ffi_verify_pi_f(const spx_p2_ffi_blob *proof,
                           const spx_p2_ffi_public_inputs *pub)
{
    if (proof == 0 || proof->data == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    return spx_p2_ffi_verify_pi_f_full_air(proof, pub);
}

/* ── Full-AIR FFI (no external guards) ── */

int spx_p2_ffi_get_abi_version_full_air(uint32_t *out_version)
{
#ifdef SPX_P2_USE_RUST_STARK
    return spx_p2_rust_get_abi_version_full_air(out_version);
#else
    if (out_version == 0) return SPX_P2_FFI_STATUS_ERR_NULL;
    *out_version = SPX_P2_FULL_AIR_ABI_VERSION;
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_ffi_generate_pi_f_full_air(spx_p2_ffi_blob *out_proof,
                                       const spx_p2_ffi_public_inputs *pub,
                                       const spx_p2_ffi_private_witness *wit)
{
#ifdef SPX_P2_USE_RUST_STARK
    if (out_proof == 0 || pub == 0 || wit == 0) return SPX_P2_FFI_STATUS_ERR_NULL;
    if (out_proof->data == 0 || pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0)
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    return spx_p2_rust_generate_pi_f_full_air(out_proof, pub, wit);
#else
    (void)out_proof; (void)pub; (void)wit;
    return SPX_P2_FFI_STATUS_ERR_PROVE;
#endif
}

int spx_p2_ffi_verify_pi_f_full_air(const spx_p2_ffi_blob *proof,
                                     const spx_p2_ffi_public_inputs *pub)
{
#ifdef SPX_P2_USE_RUST_STARK
    if (proof == 0 || proof->data == 0) return SPX_P2_FFI_STATUS_ERR_NULL;
    return spx_p2_rust_verify_pi_f_full_air(proof, pub);
#else
    (void)proof; (void)pub;
    return SPX_P2_FFI_STATUS_ERR_VERIFY;
#endif
}
