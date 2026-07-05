#ifndef SPX_SHOW_POSEIDON2_H
#define SPX_SHOW_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "../stark/ffi.h"

#define SPX_P2_SHOW_PUBLIC_CTX_MAX 64
#define SPX_P2_PUBLIC_CTX_MAX SPX_P2_SHOW_PUBLIC_CTX_MAX
#define SPX_P2_SIGMA_C_MAX_BYTES (2u * SPX_N)
#define SPX_P2_SHOW_PI_F_MAX_BYTES (128u * 1024u)

/*
 * Final public Fischlin object Sigma = (C, pi) plus the explicit public
 * statement carried by the verifier: m_pub and public_ctx.
 */
typedef struct
{
    uint8_t sigma_C[SPX_P2_SIGMA_C_MAX_BYTES];
    size_t sigma_C_len;
    uint8_t m_pub[SPX_BYTES];
    size_t m_pub_len;
    uint8_t pi_f[SPX_P2_SHOW_PI_F_MAX_BYTES];
    size_t pi_f_len;
    uint8_t public_ctx[SPX_P2_SHOW_PUBLIC_CTX_MAX];
    size_t public_ctx_len;
} spx_p2_show;

#define spx_p2_show_extract_commitment SPX_NAMESPACE(spx_p2_show_extract_commitment)
int spx_p2_show_extract_commitment(uint8_t out_com[SPX_N],
                                   const spx_p2_show *show);

/*
 * Holder-side private witness used to prove existence of a valid opening,
 * issuer signature and encryption randomness for the final Fischlin statement.
 */
typedef struct
{
    uint8_t m[SPX_BYTES];
    size_t mlen;
    uint8_t r[SPX_BYTES];
    size_t rlen;
    uint8_t omega2[SPX_N];
    size_t omega2_len;
    uint8_t com[SPX_N];
    uint8_t sigma_com[SPX_BYTES];
    spx_p2_trace trace;
} spx_p2_cred_internal;

#define spx_p2_show_prove SPX_NAMESPACE(spx_p2_show_prove)
int spx_p2_show_prove(spx_p2_show *out,
                      const uint8_t *pk_sig,
                      const spx_p2_cred_internal *cred,
                      const uint8_t *public_ctx,
                      size_t public_ctx_len);

#define spx_p2_show_verify SPX_NAMESPACE(spx_p2_show_verify)
int spx_p2_show_verify(const spx_p2_show *show,
                       const uint8_t *pk_sig);

#define spx_p2_show_prove_statement_bound SPX_NAMESPACE(spx_p2_show_prove_statement_bound)
int spx_p2_show_prove_statement_bound(spx_p2_show *out,
                                      const uint8_t *pk_sig,
                                      const uint8_t *pk_e,
                                      size_t pk_e_len,
                                      const spx_p2_cred_internal *cred,
                                      const uint8_t *public_ctx,
                                      size_t public_ctx_len);

#define spx_p2_show_verify_statement_bound SPX_NAMESPACE(spx_p2_show_verify_statement_bound)
int spx_p2_show_verify_statement_bound(const spx_p2_show *show,
                                       const uint8_t *pk_sig,
                                       const uint8_t *pk_e,
                                       size_t pk_e_len,
                                       const uint8_t *m_pub,
                                       size_t m_pub_len);

#endif
