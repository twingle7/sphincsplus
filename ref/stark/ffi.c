#include "ffi.h"

int spx_p2_ffi_get_abi_version(uint32_t *out_version)
{
    return spx_p2_ffi_get_abi_version_v1(out_version);
}

int spx_p2_ffi_generate_pi_f(spx_p2_ffi_blob *out_proof,
                             const spx_p2_ffi_public_inputs *pub,
                             const spx_p2_ffi_private_witness *wit)
{
#ifndef SPX_P2_USE_RUST_STARK
    (void)out_proof;
    (void)pub;
    (void)wit;
    /* Final API requires real STARK backend. */
    return SPX_P2_FFI_STATUS_ERR_PROVE;
#else
    return spx_p2_ffi_generate_pi_f_v2_strict(out_proof, pub, wit);
#endif
}

int spx_p2_ffi_verify_pi_f(const spx_p2_ffi_blob *proof,
                           const spx_p2_ffi_public_inputs *pub)
{
#ifndef SPX_P2_USE_RUST_STARK
    (void)proof;
    (void)pub;
    /* Final API requires real STARK backend. */
    return SPX_P2_FFI_STATUS_ERR_VERIFY;
#else
    return spx_p2_ffi_verify_pi_f_v2_strict(proof, pub);
#endif
}

int spx_p2_ffi_verify_pi_f_compat(const spx_p2_ffi_blob *proof,
                                  const spx_p2_ffi_public_inputs *pub)
{
    return spx_p2_ffi_verify_pi_f_v1(proof, pub);
}
