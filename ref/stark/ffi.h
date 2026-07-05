#ifndef SPX_STARK_FFI_H
#define SPX_STARK_FFI_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

#define SPX_P2_STARK_FFI_ABI_VERSION 1u

typedef enum
{
    SPX_P2_FFI_STATUS_OK = 0,
    SPX_P2_FFI_STATUS_ERR_NULL = -1,
    SPX_P2_FFI_STATUS_ERR_INPUT = -2,
    SPX_P2_FFI_STATUS_ERR_BUFFER_SMALL = -3,
    SPX_P2_FFI_STATUS_ERR_PROVE = -4,
    SPX_P2_FFI_STATUS_ERR_VERIFY = -5
} spx_p2_ffi_status;

typedef struct
{
    uint8_t *data;
    size_t len;
    size_t cap;
} spx_p2_ffi_blob;

typedef struct
{
    const uint8_t *pk;
    const uint8_t *pk_e;
    size_t pk_e_len;
    const uint8_t *com;
    const uint8_t *m_pub;
    size_t m_pub_len;
    const uint8_t *public_ctx;
    size_t public_ctx_len;
    const uint8_t *sigma_c;
    size_t sigma_c_len;
} spx_p2_ffi_public_inputs;

typedef struct
{
    const uint8_t *sigma_com;
    const uint8_t *m;
    size_t mlen;
    const uint8_t *r;
    size_t rlen;
    const uint8_t *omega2;
    size_t omega2_len;
} spx_p2_ffi_private_witness;

#define spx_p2_ffi_get_abi_version SPX_NAMESPACE(spx_p2_ffi_get_abi_version)
int spx_p2_ffi_get_abi_version(uint32_t *out_version);

#define spx_p2_ffi_generate_pi_f SPX_NAMESPACE(spx_p2_ffi_generate_pi_f)
int spx_p2_ffi_generate_pi_f(spx_p2_ffi_blob *out_proof,
                             const spx_p2_ffi_public_inputs *pub,
                             const spx_p2_ffi_private_witness *wit);

#define spx_p2_ffi_verify_pi_f SPX_NAMESPACE(spx_p2_ffi_verify_pi_f)
int spx_p2_ffi_verify_pi_f(const spx_p2_ffi_blob *proof,
                           const spx_p2_ffi_public_inputs *pub);

#endif
