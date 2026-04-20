#ifndef SPX_STARK_FFI_H
#define SPX_STARK_FFI_H

#include <stddef.h>
#include <stdint.h>

#include "ffi_v1.h"

typedef spx_p2_ffi_status_v1 spx_p2_ffi_status;
typedef spx_p2_ffi_blob_v1 spx_p2_ffi_blob;
typedef spx_p2_ffi_public_inputs_v1 spx_p2_ffi_public_inputs;
typedef spx_p2_ffi_private_witness_v1 spx_p2_ffi_private_witness;

#define SPX_P2_STARK_FFI_ABI_VERSION SPX_P2_STARK_FFI_ABI_VERSION_V1
#define SPX_P2_FFI_STATUS_OK SPX_P2_FFI_OK
#define SPX_P2_FFI_STATUS_ERR_NULL SPX_P2_FFI_ERR_NULL
#define SPX_P2_FFI_STATUS_ERR_INPUT SPX_P2_FFI_ERR_INPUT
#define SPX_P2_FFI_STATUS_ERR_BUFFER_SMALL SPX_P2_FFI_ERR_BUFFER_SMALL
#define SPX_P2_FFI_STATUS_ERR_PROVE SPX_P2_FFI_ERR_PROVE
#define SPX_P2_FFI_STATUS_ERR_VERIFY SPX_P2_FFI_ERR_VERIFY

#define spx_p2_ffi_get_abi_version SPX_NAMESPACE(spx_p2_ffi_get_abi_version)
int spx_p2_ffi_get_abi_version(uint32_t *out_version);

/* Final default generation path is strict v2. */
#define spx_p2_ffi_generate_pi_f SPX_NAMESPACE(spx_p2_ffi_generate_pi_f)
int spx_p2_ffi_generate_pi_f(spx_p2_ffi_blob *out_proof,
                             const spx_p2_ffi_public_inputs *pub,
                             const spx_p2_ffi_private_witness *wit);

#define spx_p2_ffi_verify_pi_f SPX_NAMESPACE(spx_p2_ffi_verify_pi_f)
int spx_p2_ffi_verify_pi_f(const spx_p2_ffi_blob *proof,
                           const spx_p2_ffi_public_inputs *pub);

/* Compatibility path kept for legacy proof objects. */
#define spx_p2_ffi_verify_pi_f_compat SPX_NAMESPACE(spx_p2_ffi_verify_pi_f_compat)
int spx_p2_ffi_verify_pi_f_compat(const spx_p2_ffi_blob *proof,
                                  const spx_p2_ffi_public_inputs *pub);

#endif
