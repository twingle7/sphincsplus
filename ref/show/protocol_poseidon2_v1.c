#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol_poseidon2_v1.h"
#include "../hash_poseidon2_adapter.h"
#include "../randombytes.h"

static int spx_p2_all_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        if (buf[i] != 0)
        {
            return 0;
        }
    }
    return 1;
}

static int spx_p2_protocol_verify_shape_guard(const spx_p2_show *show)
{
    if (show->public_ctx_len > SPX_P2_PUBLIC_CTX_MAX)
    {
        return -1;
    }
    if (show->pi_f_len == 0 || show->pi_f_len > sizeof(show->pi_f))
    {
        return -1;
    }
    if (show->sigma_C_len != (2u * SPX_N))
    {
        return -1;
    }
    if (show->m_pub_len > sizeof(show->m_pub))
    {
        return -1;
    }
    if (memcmp(show->sigma_C, show->com, SPX_N) != 0)
    {
        return -1;
    }
    if (spx_p2_all_zero(show->com, SPX_N))
    {
        return -1;
    }
    return 0;
}

int spx_p2_protocol_has_rust_backend_v1(void)
{
#ifdef SPX_P2_USE_RUST_STARK
    return 1;
#else
    return 0;
#endif
}

const char *spx_p2_protocol_backend_mode_v1(void)
{
    return spx_p2_protocol_has_rust_backend_v1() ? "rust" : "stub";
}

const char *spx_p2_flow_status_to_string_v1(int status)
{
    switch (status)
    {
    case SPX_P2_FLOW_OK:
        return "ok";
    case SPX_P2_FLOW_ERR_NULL:
        return "null";
    case SPX_P2_FLOW_ERR_INPUT:
        return "input";
    case SPX_P2_FLOW_ERR_SIGN:
        return "sign";
    case SPX_P2_FLOW_ERR_PROVE:
        return "prove";
    case SPX_P2_FLOW_ERR_VERIFY:
        return "verify";
    case SPX_P2_FLOW_ERR_BACKEND:
        return "backend";
    default:
        return "unknown";
    }
}

int spx_p2_issue_request_v1(uint8_t out_com[SPX_N],
                            const uint8_t *m, size_t mlen,
                            const uint8_t *r, size_t rlen)
{
    if (out_com == 0 || m == 0 || r == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (mlen == 0 || rlen == 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    spx_p2_commit(out_com, m, mlen, r, rlen);
    return SPX_P2_FLOW_OK;
}

int spx_p2_issue_sign_v1(uint8_t out_sigma_blind[SPX_BYTES], size_t *out_sigma_blind_len,
                         const uint8_t *issuer_sk,
                         const uint8_t com[SPX_N])
{
    if (out_sigma_blind == 0 || out_sigma_blind_len == 0 || issuer_sk == 0 || com == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (crypto_sign_signature(out_sigma_blind, out_sigma_blind_len, com, SPX_N, issuer_sk) != 0 ||
        *out_sigma_blind_len != SPX_BYTES)
    {
        return SPX_P2_FLOW_ERR_SIGN;
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_unblind_v1(spx_p2_cred_internal *out_cred,
                      const uint8_t com[SPX_N],
                      const uint8_t sigma_blind[SPX_BYTES], size_t sigma_blind_len,
                      const uint8_t *omega2, size_t omega2_len)
{
    if (out_cred == 0 || com == 0 || sigma_blind == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (sigma_blind_len != SPX_BYTES)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if ((omega2 != 0 && omega2_len == 0) || (omega2 == 0 && omega2_len > 0) || omega2_len > SPX_N)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    memset(out_cred, 0, sizeof(*out_cred));
    memcpy(out_cred->com, com, SPX_N);
    memcpy(out_cred->sigma_com, sigma_blind, SPX_BYTES);
    if (omega2_len > 0)
    {
        memcpy(out_cred->omega2, omega2, omega2_len);
        out_cred->omega2_len = omega2_len;
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_issue_unblind_v1(spx_p2_cred_internal *out_cred,
                            uint8_t out_com[SPX_N],
                            const uint8_t *issuer_sk,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *r, size_t rlen,
                            const uint8_t *omega2, size_t omega2_len)
{
    uint8_t sigma_blind[SPX_BYTES];
    size_t sigma_blind_len = 0;
    uint8_t omega2_fallback[SPX_N];
    const uint8_t *omega2_used = omega2;
    size_t omega2_used_len = omega2_len;
    int ret = spx_p2_issue_request_v1(out_com, m, mlen, r, rlen);
    if (ret != SPX_P2_FLOW_OK)
    {
        return ret;
    }
    ret = spx_p2_issue_sign_v1(sigma_blind, &sigma_blind_len, issuer_sk, out_com);
    if (ret != SPX_P2_FLOW_OK)
    {
        return ret;
    }
    if (omega2_used == 0 || omega2_used_len == 0)
    {
        /* Fischlin-style randomness: omega2 is sampled independently when caller does not provide it. */
        randombytes(omega2_fallback, SPX_N);
        omega2_used = omega2_fallback;
        omega2_used_len = SPX_N;
    }
    else if (omega2_used_len != SPX_N)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    ret = spx_p2_unblind_v1(out_cred, out_com, sigma_blind, sigma_blind_len, omega2_used, omega2_used_len);
    if (ret != SPX_P2_FLOW_OK)
    {
        return ret;
    }
    if (mlen == 0 || mlen > sizeof(out_cred->m) || rlen == 0 || rlen > sizeof(out_cred->r))
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    memcpy(out_cred->m, m, mlen);
    out_cred->mlen = mlen;
    memcpy(out_cred->r, r, rlen);
    out_cred->rlen = rlen;
    return SPX_P2_FLOW_OK;
}

int spx_p2_protocol_show_v1(spx_p2_show *out_show,
                            const uint8_t *pk_sig,
                            const uint8_t *pk_e, size_t pk_e_len,
                            const spx_p2_cred_internal *cred,
                            const uint8_t *public_ctx, size_t public_ctx_len)
{
    if (out_show == 0 || pk_sig == 0 || pk_e == 0 || cred == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (pk_e_len < SPX_N || cred->omega2_len != SPX_N || cred->mlen == 0 || cred->rlen == 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_show_prove_m20(out_show, pk_sig, pk_e, pk_e_len, cred, public_ctx, public_ctx_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_PROVE;
#endif
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_protocol_show_m20_v1(spx_p2_show *out_show,
                                const uint8_t *pk_sig,
                                const uint8_t *pk_e,
                                size_t pk_e_len,
                                const spx_p2_cred_internal *cred,
                                const uint8_t *public_ctx,
                                size_t public_ctx_len)
{
    if (out_show == 0 || pk_sig == 0 || pk_e == 0 || cred == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (pk_e_len < SPX_N || cred->omega2_len != SPX_N || cred->mlen == 0 || cred->rlen == 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_show_prove_m20(out_show, pk_sig, pk_e, pk_e_len, cred, public_ctx, public_ctx_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_PROVE;
#endif
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_protocol_verify_v1(const spx_p2_show *show,
                              const uint8_t *pk_sig,
                              const uint8_t *pk_e, size_t pk_e_len)
{
    if (show == 0 || pk_sig == 0 || pk_e == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (pk_e_len < SPX_N)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_protocol_verify_shape_guard(show) != 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (show->m_pub_len > 0)
    {
        /* M20 final statement is x=(pk_sig, pk_E, m_pub, ctx_pub). */
        /* Generic verify_v1 has no explicit m_pub input, so callers must use verify_m20_v1. */
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_show_verify_m19(show, pk_sig, pk_e, pk_e_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_VERIFY;
#endif
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_protocol_verify_m20_v1(const spx_p2_show *show,
                                  const uint8_t *pk_sig,
                                  const uint8_t *pk_e,
                                  size_t pk_e_len,
                                  const uint8_t *m_pub,
                                  size_t m_pub_len)
{
    if (show == 0 || pk_sig == 0 || pk_e == 0 || m_pub == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (pk_e_len < SPX_N || m_pub_len == 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_protocol_verify_shape_guard(show) != 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (spx_p2_show_verify_m20(show, pk_sig, pk_e, pk_e_len, m_pub, m_pub_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_VERIFY;
#endif
    }
    return SPX_P2_FLOW_OK;
}
