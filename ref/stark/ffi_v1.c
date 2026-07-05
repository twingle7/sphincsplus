#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ffi.h"
#include "ffi_v1.h"
#include "pi_f_format_v1.h"
#include "pi_f_format_v2.h"
#include "relation_migration_v1.h"
#include "verifier_v1.h"

int spx_p2_ffi_detect_pi_f_version_internal(const uint8_t *proof, size_t proof_len);
int spx_p2_ffi_generate_pi_f_legacy_internal(spx_p2_ffi_blob *out_proof,
                                             const spx_p2_ffi_public_inputs *pub,
                                             const spx_p2_ffi_private_witness *wit);
int spx_p2_ffi_verify_pi_f_legacy_internal(const spx_p2_ffi_blob *proof,
                                           const spx_p2_ffi_public_inputs *pub);

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_get_abi_version_v1(uint32_t *out_version);
extern int spx_p2_rust_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                        const spx_p2_ffi_public_inputs_v1 *pub,
                                        const spx_p2_ffi_private_witness_v1 *wit);
extern int spx_p2_rust_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                                      const spx_p2_ffi_public_inputs_v1 *pub);

#define SPX_P2_RUST_OK 0
#define SPX_P2_RUST_ERR_NULL -1
#define SPX_P2_RUST_ERR_INPUT -2
#define SPX_P2_RUST_ERR_BUFFER_SMALL -3
#define SPX_P2_RUST_ERR_PROVE -4
#define SPX_P2_RUST_ERR_VERIFY -5
#define SPX_P2_RUST_ERR_FORMAT -6

static int spx_p2_map_rust_status_to_ffi(int rust_ret)
{
    if (rust_ret == SPX_P2_RUST_OK)
    {
        return SPX_P2_FFI_OK;
    }
    if (rust_ret == SPX_P2_RUST_ERR_NULL)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    if (rust_ret == SPX_P2_RUST_ERR_INPUT)
    {
        return SPX_P2_FFI_ERR_INPUT;
    }
    if (rust_ret == SPX_P2_RUST_ERR_BUFFER_SMALL)
    {
        return SPX_P2_FFI_ERR_BUFFER_SMALL;
    }
    if (rust_ret == SPX_P2_RUST_ERR_VERIFY || rust_ret == SPX_P2_RUST_ERR_FORMAT)
    {
        return SPX_P2_FFI_ERR_VERIFY;
    }
    if (rust_ret == SPX_P2_RUST_ERR_PROVE)
    {
        return SPX_P2_FFI_ERR_PROVE;
    }
    return SPX_P2_FFI_ERR_PROVE;
}
#endif

static int spx_p2_debug_verify_enabled(void)
{
    return getenv("SPX_P2_DEBUG_VERIFY") != 0;
}

int spx_p2_ffi_get_abi_version_v1(uint32_t *out_version)
{
    return spx_p2_ffi_get_abi_version(out_version);
}

int spx_p2_ffi_generate_pi_f_v1(spx_p2_ffi_blob_v1 *out_proof,
                                const spx_p2_ffi_public_inputs_v1 *pub,
                                const spx_p2_ffi_private_witness_v1 *wit)
{
    return spx_p2_ffi_generate_pi_f_legacy_internal((spx_p2_ffi_blob *)out_proof,
                                                    (const spx_p2_ffi_public_inputs *)pub,
                                                    (const spx_p2_ffi_private_witness *)wit);
}

int spx_p2_ffi_verify_pi_f_v1(const spx_p2_ffi_blob_v1 *proof,
                              const spx_p2_ffi_public_inputs_v1 *pub)
{
    return spx_p2_ffi_verify_pi_f_legacy_internal((const spx_p2_ffi_blob *)proof,
                                                  (const spx_p2_ffi_public_inputs *)pub);
}

int spx_p2_ffi_generate_pi_f_v2_strict(spx_p2_ffi_blob_v1 *out_proof,
                                       const spx_p2_ffi_public_inputs_v1 *pub,
                                       const spx_p2_ffi_private_witness_v1 *wit)
{
    int ret;
    int ver;
    if (out_proof == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    ret = spx_p2_relation_validate_strict_prove_inputs_v1(pub, wit);
    if (ret != SPX_P2_FFI_OK)
    {
        return ret;
    }
    ret = spx_p2_ffi_generate_pi_f_legacy_internal((spx_p2_ffi_blob *)out_proof,
                                                   (const spx_p2_ffi_public_inputs *)pub,
                                                   (const spx_p2_ffi_private_witness *)wit);
    if (ret != SPX_P2_FFI_OK)
    {
        return ret;
    }
    ver = spx_p2_ffi_detect_pi_f_version_internal(out_proof->data, out_proof->len);
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
    int ret;
    if (proof == 0 || proof->data == 0)
    {
        return SPX_P2_FFI_ERR_NULL;
    }
    ret = spx_p2_relation_validate_strict_verify_inputs_v1(pub);
    if (ret != SPX_P2_FFI_OK)
    {
        return ret;
    }
    ver = spx_p2_ffi_detect_pi_f_version_internal(proof->data, proof->len);
    if (ver != 2)
    {
        if (spx_p2_debug_verify_enabled())
        {
            fprintf(stderr, "[ffi_v1] verify_v2_strict rejected non-v2 proof: ver=%d len=%llu\n",
                    ver, (unsigned long long)proof->len);
        }
        return SPX_P2_FFI_ERR_VERIFY;
    }
    {
        int ret = spx_p2_ffi_verify_pi_f_legacy_internal((const spx_p2_ffi_blob *)proof,
                                                         (const spx_p2_ffi_public_inputs *)pub);
        if (spx_p2_debug_verify_enabled())
        {
            fprintf(stderr, "[ffi_v1] verify_v2_strict result=%d\n", ret);
        }
        return ret;
    }
}
