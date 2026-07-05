#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../hash_poseidon2_adapter.h"
#ifndef SPX_P2_USE_RUST_STARK
#include "air_verify_full.h"
#endif
#include "relation_migration.h"

#ifdef SPX_P2_USE_RUST_STARK
extern int spx_p2_rust_validate_strict_relation_inputs_v1(const spx_p2_ffi_public_inputs *pub,
                                                          const spx_p2_ffi_private_witness *wit,
                                                          int require_witness);
extern int spx_p2_rust_validate_strict_witness_relation_v1(const spx_p2_ffi_public_inputs *pub,
                                                           const spx_p2_ffi_private_witness *wit);
#define SPX_P2_RUST_OK 0
#define SPX_P2_RUST_ERR_NULL -1
#define SPX_P2_RUST_ERR_INPUT -2
#define SPX_P2_RUST_ERR_PROVE -4

static int spx_p2_map_rust_relation_status_to_ffi(int rust_ret)
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
    if (rust_ret == SPX_P2_RUST_ERR_PROVE)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    return SPX_P2_FFI_STATUS_ERR_INPUT;
}
#endif

#ifndef SPX_P2_USE_RUST_STARK
static int spx_p2_eval_verify_full_guard(const uint8_t *pk,
                                         const uint8_t *com,
                                         const uint8_t *sigma_com)
{
    spx_p2_trace replay;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    uint32_t constraints = 0;
    uint32_t violations = 0;
    int ret = -1;

    if (spx_p2_trace_verify_com(&replay, pk, com, sigma_com) != 0)
    {
        return -1;
    }
    if (spx_p2_witness_count_rows_v1(&replay, &row_count) != 0 || row_count == 0)
    {
        return -1;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(*rows));
    if (rows == 0)
    {
        return -1;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &replay) != 0)
    {
        goto done;
    }
    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sigma_com, &replay,
                                                   rows, row_count,
                                                   &constraints, &violations) != 0)
    {
        goto done;
    }
    ret = (violations == 0) ? 0 : -1;
done:
    free(rows);
    return ret;
}

static int spx_p2_relation_validate_sigma_c_local(const spx_p2_ffi_public_inputs *pub,
                                                  const spx_p2_ffi_private_witness *wit)
{
    uint8_t expected_sigma_c[2u * SPX_N];
    size_t expected_sigma_c_len = 0;

    if (pub == 0 || wit == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (pub->com == 0 || pub->pk_e == 0 || pub->sigma_c == 0 || wit->sigma_com == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->pk_e_len != SPX_N || pub->sigma_c_len != (2u * SPX_N))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (wit->omega2 == 0 || wit->omega2_len != SPX_N)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->m_pub == 0 || pub->m_pub_len == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (spx_p2_build_sigma_c_ciphertext(expected_sigma_c, &expected_sigma_c_len,
                                        pub->com, wit->sigma_com,
                                        pub->pk_e, pub->pk_e_len,
                                        wit->omega2, wit->omega2_len) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (expected_sigma_c_len != pub->sigma_c_len ||
        memcmp(expected_sigma_c, pub->sigma_c, pub->sigma_c_len) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    return SPX_P2_FFI_STATUS_OK;
}
#endif

int spx_p2_relation_validate_strict_prove_inputs(const spx_p2_ffi_public_inputs *pub,
                                                 const spx_p2_ffi_private_witness *wit)
{
#ifdef SPX_P2_USE_RUST_STARK
    {
        int rust_ret = spx_p2_rust_validate_strict_relation_inputs_v1(pub, wit, 1);
        return spx_p2_map_rust_relation_status_to_ffi(rust_ret);
    }
#else
    if (pub == 0 || wit == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->m_pub == 0 || pub->m_pub_len == 0 ||
        wit->m == 0 || wit->mlen == 0 ||
        wit->r == 0 || wit->rlen == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->m_pub_len != wit->mlen || memcmp(pub->m_pub, wit->m, wit->mlen) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->pk_e == 0 || pub->pk_e_len != SPX_N)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->sigma_c == 0 || pub->sigma_c_len != (2u * SPX_N))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (wit->omega2 == 0 || wit->omega2_len != SPX_N)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (memcmp(pub->sigma_c, pub->com, SPX_N) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_relation_validate_strict_verify_inputs(const spx_p2_ffi_public_inputs *pub)
{
#ifdef SPX_P2_USE_RUST_STARK
    {
        int rust_ret = spx_p2_rust_validate_strict_relation_inputs_v1(pub, 0, 0);
        return spx_p2_map_rust_relation_status_to_ffi(rust_ret);
    }
#else
    if (pub == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_NULL;
    }
    if (pub->pk == 0 || pub->pk_e == 0 || pub->pk_e_len != SPX_N ||
        pub->com == 0 || pub->sigma_c == 0 || pub->sigma_c_len != (2u * SPX_N))
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (pub->m_pub == 0 || pub->m_pub_len == 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    if (memcmp(pub->sigma_c, pub->com, SPX_N) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_INPUT;
    }
    return SPX_P2_FFI_STATUS_OK;
#endif
}

int spx_p2_relation_precheck_strict_prove_witness(const spx_p2_ffi_public_inputs *pub,
                                                  const spx_p2_ffi_private_witness *wit)
{
#ifdef SPX_P2_USE_RUST_STARK
    {
        int rust_ret = spx_p2_rust_validate_strict_witness_relation_v1(pub, wit);
        return spx_p2_map_rust_relation_status_to_ffi(rust_ret);
    }
#else
    {
        uint8_t expected_com[SPX_N];
        spx_p2_commit(expected_com, wit->m, wit->mlen, wit->r, wit->rlen);
        if (memcmp(expected_com, pub->com, SPX_N) != 0)
        {
            return SPX_P2_FFI_STATUS_ERR_PROVE;
        }
    }
    {
        int ret = spx_p2_relation_validate_sigma_c_local(pub, wit);
        if (ret != SPX_P2_FFI_STATUS_OK)
        {
            return ret;
        }
    }
    if (spx_p2_verify_com(pub->pk, pub->com, wit->sigma_com) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    if (spx_p2_eval_verify_full_guard(pub->pk, pub->com, wit->sigma_com) != 0)
    {
        return SPX_P2_FFI_STATUS_ERR_PROVE;
    }
    return SPX_P2_FFI_STATUS_OK;
#endif
}
