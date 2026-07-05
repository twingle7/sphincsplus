#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "ffi.h"
#include "pi_f_format_v1.h"
#include "pi_f_format_v2.h"
#include "prover_v1.h"
#include "relation_migration.h"
#include "verifier_v1.h"

int spx_p2_ffi_detect_pi_f_version_internal(const uint8_t *proof, size_t proof_len);
int spx_p2_ffi_generate_pi_f_legacy_internal(spx_p2_ffi_blob *out_proof,
                                             const spx_p2_ffi_public_inputs *pub,
                                             const spx_p2_ffi_private_witness *wit);
int spx_p2_ffi_verify_pi_f_legacy_internal(const spx_p2_ffi_blob *proof,
                                           const spx_p2_ffi_public_inputs *pub);

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_get_abi_version_v1(uint32_t *out_version);
extern int spx_p2_rust_generate_pi_f_v1(spx_p2_ffi_blob *out_proof,
                                        const spx_p2_ffi_public_inputs *pub,
                                        const spx_p2_ffi_private_witness *wit);
extern int spx_p2_rust_verify_pi_f_v1(const spx_p2_ffi_blob *proof,
                                      const spx_p2_ffi_public_inputs *pub);

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
        return SPX_P2_FFI_STATUS_OK;
    }
    if (rust_ret == SPX_P2_RUST_ERR_NULL)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (rust_ret == SPX_P2_RUST_ERR_INPUT)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (rust_ret == SPX_P2_RUST_ERR_BUFFER_SMALL)
    {
        return SPX_P2_FFI_STATUS_ERR_BUFFER_SMALL;
    }
    if (rust_ret == SPX_P2_RUST_ERR_VERIFY || rust_ret == SPX_P2_RUST_ERR_FORMAT)
    {
        return SPX_P2_FFI_STATUS_ERR_VERIFY;
    }
    if (rust_ret == SPX_P2_RUST_ERR_PROVE)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    return SPX_P2_FFI_STATUS_ERR_PROVE;
}
#endif

static uint32_t spx_p2_load_u32_le(const uint8_t *in)
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

int spx_p2_ffi_detect_pi_f_version_internal(const uint8_t *proof, size_t proof_len)
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

static int spx_p2_debug_verify_enabled(void)
{
    return getenv("SPX_P2_DEBUG_VERIFY") != 0;
}

int spx_p2_ffi_get_abi_version(uint32_t *out_version)
{
#ifdef SPX_P2_USE_RUST_STARK
    return spx_p2_rust_get_abi_version_v1(out_version);
#else
    if (out_version == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    *out_version = SPX_P2_STARK_FFI_ABI_VERSION;
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_ffi_generate_pi_f_legacy_internal(spx_p2_ffi_blob *out_proof,
                                             const spx_p2_ffi_public_inputs *pub,
                                             const spx_p2_ffi_private_witness *wit)
{
    if (out_proof == 0 || pub == 0 || wit == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (out_proof->data == 0 || pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0 ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if ((pub->pk_e_len > 0 && pub->pk_e == 0) ||
        (pub->pk_e != 0 && pub->pk_e_len == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if ((pub->sigma_c_len > 0 && pub->sigma_c == 0) ||
        (pub->sigma_c != 0 && pub->sigma_c_len == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if ((wit->omega2_len > 0 && wit->omega2 == 0) ||
        (wit->omega2 != 0 && wit->omega2_len == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
#ifdef SPX_P2_USE_RUST_STARK
    if (out_proof->cap == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_BUFFER_SMALL;
    }
    return spx_p2_map_rust_status_to_ffi(spx_p2_rust_generate_pi_f_v1(out_proof, pub, wit));
#else
    if (out_proof->cap < SPX_P2_PI_F_V1_MAX_BYTES)
    {
        return SPX_P2_FFI_STATUS_ERR_BUFFER_SMALL;
    }
    if (spx_p2_prover_generate_pi_f_v1(out_proof->data, &out_proof->len, out_proof->cap,
                                       pub->pk, pub->com, wit->sigma_com,
                                       pub->public_ctx, pub->public_ctx_len) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_ffi_verify_pi_f_legacy_internal(const spx_p2_ffi_blob *proof,
                                           const spx_p2_ffi_public_inputs *pub)
{
    int pi_f_ver;
    if (proof == 0 || pub == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (proof->data == 0 || pub->pk == 0 || pub->com == 0 ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if ((pub->pk_e_len > 0 && pub->pk_e == 0) ||
        (pub->pk_e != 0 && pub->pk_e_len == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if ((pub->sigma_c_len > 0 && pub->sigma_c == 0) ||
        (pub->sigma_c != 0 && pub->sigma_c_len == 0))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    pi_f_ver = spx_p2_ffi_detect_pi_f_version_internal(proof->data, proof->len);
    if (pi_f_ver == 1)
    {
        if (spx_p2_verifier_verify_pi_f_v1(pub->pk, pub->com, proof->data, proof->len,
                                           pub->public_ctx, pub->public_ctx_len) != 0)
        {
            return SPX_P2_FFI_STATUS_ERR_VERIFY;
        }
        return SPX_P2_FFI_STATUS_OK;
    }
    if (pi_f_ver != 2)
    {
        return SPX_P2_FFI_STATUS_ERR_VERIFY;
    }
#ifdef SPX_P2_USE_RUST_STARK
    {
        int rust_ret = spx_p2_rust_verify_pi_f_v1(proof, pub);
        int ffi_ret = spx_p2_map_rust_status_to_ffi(rust_ret);
        if (spx_p2_debug_verify_enabled())
        {
            fprintf(stderr,
                    "[ffi] verify v2 via rust: rust_ret=%d ffi_ret=%d proof_len=%llu ctx_len=%llu\n",
                    rust_ret, ffi_ret,
                    (unsigned long long)proof->len,
                    (unsigned long long)pub->public_ctx_len);
        }
        return ffi_ret;
    }
#else
    return SPX_P2_FFI_STATUS_ERR_VERIFY;
#endif
}

int spx_p2_ffi_generate_pi_f(spx_p2_ffi_blob *out_proof,
                             const spx_p2_ffi_public_inputs *pub,
                             const spx_p2_ffi_private_witness *wit)
{
    int ret;
    int ver;
    if (out_proof == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    ret = spx_p2_relation_validate_strict_prove_inputs(pub, wit);
    if (ret != SPX_P2_FFI_STATUS_OK)
    {
        return ret;
    }
    ret = spx_p2_ffi_generate_pi_f_legacy_internal(out_proof, pub, wit);
    if (ret != SPX_P2_FFI_STATUS_OK)
    {
        if (spx_p2_debug_verify_enabled())
        {
            fprintf(stderr, "[ffi] generate_pi_f legacy returned ret=%d len=%llu\n",
                    ret, (unsigned long long)out_proof->len);
        }
        return ret;
    }
    ver = spx_p2_ffi_detect_pi_f_version_internal(out_proof->data, out_proof->len);
    if (spx_p2_debug_verify_enabled())
    {
        fprintf(stderr, "[ffi] generate_pi_f post-check ver=%d len=%llu\n",
                ver, (unsigned long long)out_proof->len);
    }
    if (ver != 2)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    return SPX_P2_FFI_STATUS_OK;
}

int spx_p2_ffi_verify_pi_f(const spx_p2_ffi_blob *proof,
                           const spx_p2_ffi_public_inputs *pub)
{
    int ver;
    int ret;
    if (proof == 0 || proof->data == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    ret = spx_p2_relation_validate_strict_verify_inputs(pub);
    if (ret != SPX_P2_FFI_STATUS_OK)
    {
        return ret;
    }
    ver = spx_p2_ffi_detect_pi_f_version_internal(proof->data, proof->len);
    if (ver != 2)
    {
        if (spx_p2_debug_verify_enabled())
        {
            fprintf(stderr, "[ffi] verify strict rejected non-v2 proof: ver=%d len=%llu\n",
                    ver, (unsigned long long)proof->len);
        }
        return SPX_P2_FFI_STATUS_ERR_VERIFY;
    }
    ret = spx_p2_ffi_verify_pi_f_legacy_internal(proof, pub);
    if (spx_p2_debug_verify_enabled())
    {
        fprintf(stderr, "[ffi] verify strict result=%d\n", ret);
    }
    return ret;
}
