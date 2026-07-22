#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "protocol_poseidon2.h"
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
    if (spx_p2_all_zero(show->sigma_C, SPX_N))
    {
        return -1;
    }
    return 0;
}

int spx_p2_protocol_has_rust_backend(void)
{
#ifdef SPX_P2_USE_RUST_STARK
    return 1;
#else
    return 0;
#endif
}

const char *spx_p2_protocol_backend_mode(void)
{
    return spx_p2_protocol_has_rust_backend() ? "rust" : "stub";
}

const char *spx_p2_flow_status_to_string(int status)
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

int spx_p2_issue_request(uint8_t out_com[SPX_N],
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

int spx_p2_prepare_issue_request(spx_p2_issue_request_obj *out_req,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *r, size_t rlen)
{
    if (out_req == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    memset(out_req, 0, sizeof(*out_req));
    return spx_p2_issue_request(out_req->c, m, mlen, r, rlen);
}

int spx_p2_issue_sign(uint8_t out_sigma_blind[SPX_BYTES], size_t *out_sigma_blind_len,
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

int spx_p2_issue_respond(spx_p2_issue_response_obj *out_resp,
                         const uint8_t *issuer_sk,
                         const spx_p2_issue_request_obj *req)
{
    int ret;
    if (out_resp == 0 || req == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    memset(out_resp, 0, sizeof(*out_resp));
    memcpy(out_resp->c, req->c, SPX_N);
    ret = spx_p2_issue_sign(out_resp->sigma_prime, &out_resp->sigma_prime_len, issuer_sk, req->c);
    return ret;
}

/*
 * spx_p2_finalize_credential — Fischlin credential-finalization step.
 *
 * Packages the issuer's blinded signature (sigma_prime on commitment c)
 * together with the message m, randomness r, and binding factor omega2
 * into the holder's internal credential witness.
 *
 * IMPORTANT: there is NO mathematical "unblinding" of the signature.
 * In the Fischlin framework the signer signs the commitment c, and the
 * credential stores sigma_com = sigma_prime verbatim.  The ZK proof later
 * attests knowledge of (m, r) such that c = Commit(m; r), NOT that a
 * transformed "unblinded" signature exists.
 *
 * The legacy spx_p2_unblind() wrapper (removed) was a thin compatibility
 * shim that did exactly the same packaging — the name was misleading.
 */
int spx_p2_finalize_credential(spx_p2_cred_internal *out_cred,
                               const spx_p2_issue_request_obj *req,
                               const spx_p2_issue_response_obj *resp,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *r, size_t rlen,
                               const uint8_t *omega2, size_t omega2_len)
{
    if (out_cred == 0 || req == 0 || resp == 0 || m == 0 || r == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    if (memcmp(req->c, resp->c, SPX_N) != 0)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (resp->sigma_prime_len != SPX_BYTES)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if ((omega2 != 0 && omega2_len == 0) || (omega2 == 0 && omega2_len > 0) || omega2_len > SPX_N)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    if (mlen == 0 || mlen > sizeof(out_cred->m) || rlen == 0 || rlen > sizeof(out_cred->r))
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }

    /* Package credential witness: sigma_com = sigma_prime (verbatim). */
    memset(out_cred, 0, sizeof(*out_cred));
    memcpy(out_cred->com, req->c, SPX_N);
    memcpy(out_cred->sigma_com, resp->sigma_prime, SPX_BYTES);
    if (omega2_len > 0)
    {
        memcpy(out_cred->omega2, omega2, omega2_len);
        out_cred->omega2_len = omega2_len;
    }
    memcpy(out_cred->m, m, mlen);
    out_cred->mlen = mlen;
    memcpy(out_cred->r, r, rlen);
    out_cred->rlen = rlen;
    return SPX_P2_FLOW_OK;
}

/*
 * spx_p2_issue_finalize — full Issue path (prepare + sign + finalize).
 *
 * This is the recommended entry point for the Issuer side when the
 * Issuer holds the signing key and wants to produce a credential in
 * one call.  The legacy spx_p2_issue_unblind() wrapper (removed) was
 * a thin alias for this function.
 */
int spx_p2_issue_finalize(spx_p2_cred_internal *out_cred,
                          spx_p2_issue_request_obj *out_req,
                          spx_p2_issue_response_obj *out_resp,
                          const uint8_t *issuer_sk,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *r, size_t rlen,
                          const uint8_t *omega2, size_t omega2_len)
{
    uint8_t omega2_fallback[SPX_N];
    const uint8_t *omega2_used = omega2;
    size_t omega2_used_len = omega2_len;
    int ret;
    if (out_cred == 0 || out_req == 0 || out_resp == 0)
    {
        return SPX_P2_FLOW_ERR_NULL;
    }
    ret = spx_p2_prepare_issue_request(out_req, m, mlen, r, rlen);
    if (ret != SPX_P2_FLOW_OK)
    {
        return ret;
    }
    ret = spx_p2_issue_respond(out_resp, issuer_sk, out_req);
    if (ret != SPX_P2_FLOW_OK)
    {
        return ret;
    }
    if (omega2_used == 0 || omega2_used_len == 0)
    {
        randombytes(omega2_fallback, SPX_N);
        omega2_used = omega2_fallback;
        omega2_used_len = SPX_N;
    }
    else if (omega2_used_len != SPX_N)
    {
        return SPX_P2_FLOW_ERR_INPUT;
    }
    return spx_p2_finalize_credential(out_cred, out_req, out_resp, m, mlen, r, rlen, omega2_used, omega2_used_len);
}

int spx_p2_protocol_show(spx_p2_show *out_show,
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
    if (spx_p2_show_prove_statement_bound(out_show, pk_sig, pk_e, pk_e_len, cred, public_ctx, public_ctx_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_PROVE;
#endif
    }
    return SPX_P2_FLOW_OK;
}

int spx_p2_protocol_verify(const spx_p2_show *show,
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
    if (spx_p2_show_verify_statement_bound(show, pk_sig, pk_e, pk_e_len, m_pub, m_pub_len) != 0)
    {
#ifndef SPX_P2_USE_RUST_STARK
        return SPX_P2_FLOW_ERR_BACKEND;
#else
        return SPX_P2_FLOW_ERR_VERIFY;
#endif
    }
    return SPX_P2_FLOW_OK;
}
