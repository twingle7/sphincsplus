#ifndef SPX_STARK_FFI_V1_H
#define SPX_STARK_FFI_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"
#include "prover_v1.h"

#define SPX_P2_STARK_FFI_ABI_VERSION_V1 1u

typedef enum {
    SPX_P2_FFI_OK = 0,
    SPX_P2_FFI_ERR_NULL = -1,
    SPX_P2_FFI_ERR_INPUT = -2,
    SPX_P2_FFI_ERR_BUFFER_SMALL = -3,
    SPX_P2_FFI_ERR_PROVE = -4,
    SPX_P2_FFI_ERR_VERIFY = -5
} spx_p2_ffi_status_v1;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} spx_p2_ffi_blob_v1;

typedef struct {
    const uint8_t *pk;
    const uint8_t *com;
    const uint8_t *public_ctx;
    size_t public_ctx_len;
} spx_p2_ffi_public_inputs_v1;

typedef struct {
    const uint8_t *sigma_com;
} spx_p2_ffi_private_witness_v1;

#define spx_p2_ffi_get_abi_version_v1 SPX_NAMESPACE(spx_p2_ffi_get_abi_version_v1)
int spx_p2_ffi_get_abi_version_v1(uint32_t *out_version);

#define spx_p2_ffi_generate_pi_f_v1 SPX_NAMESPACE(spx_p2_ffi_generate_pi_f_v1)
int spx_p2_ffi_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                const spx_p2_ffi_public_inputs_v1 *pub,
                                const spx_p2_ffi_private_witness_v1 *wit);

#define spx_p2_ffi_verify_pi_f_v1 SPX_NAMESPACE(spx_p2_ffi_verify_pi_f_v1)
int spx_p2_ffi_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                              const spx_p2_ffi_public_inputs_v1 *pub);

/*
 * Strict v2 path:
 * - generation must output pi_F_v2
 * - verification only accepts pi_F_v2
 */
#define spx_p2_ffi_generate_pi_f_v2_strict SPX_NAMESPACE(spx_p2_ffi_generate_pi_f_v2_strict)
int spx_p2_ffi_generate_pi_f_v2_strict(spx_p2_ffi_blob_v1 *out_proof,
                                       const spx_p2_ffi_public_inputs_v1 *pub,
                                       const spx_p2_ffi_private_witness_v1 *wit);

#define spx_p2_ffi_verify_pi_f_v2_strict SPX_NAMESPACE(spx_p2_ffi_verify_pi_f_v2_strict)
int spx_p2_ffi_verify_pi_f_v2_strict(const spx_p2_ffi_blob_v1 *proof,
                                     const spx_p2_ffi_public_inputs_v1 *pub);

#endif
