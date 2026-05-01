#ifndef SPX_SHOW_POSEIDON2_H
#define SPX_SHOW_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "show_poseidon2_v1.h"

/*
 * Public show/prove/verify entrypoints.
 * New code should include this header; the `_v1` header is retained only for
 * internal maintenance and phase-specific compatibility tests.
 */

typedef spx_p2_show_v1 spx_p2_show;
typedef spx_p2_cred_v1_internal spx_p2_cred_internal;

#define SPX_P2_SHOW_PUBLIC_CTX_MAX SPX_P2_PUBLIC_CTX_MAX

#define spx_p2_show_prove SPX_NAMESPACE(spx_p2_show_prove)
int spx_p2_show_prove(spx_p2_show *out,
                      const uint8_t *pk,
                      const spx_p2_cred_internal *cred,
                      const uint8_t *public_ctx,
                      size_t public_ctx_len);

#define spx_p2_show_verify SPX_NAMESPACE(spx_p2_show_verify)
int spx_p2_show_verify(const spx_p2_show *show,
                       const uint8_t *pk);

/*
 * Public semantic variants:
 * - encryption_bound: binds the encryption public key separately
 * - statement_bound: final path with explicit public statement inputs
 */
#define spx_p2_show_prove_encryption_bound SPX_NAMESPACE(spx_p2_show_prove_encryption_bound)
int spx_p2_show_prove_encryption_bound(spx_p2_show *out,
                                       const uint8_t *pk_sig,
                                       const uint8_t *pk_e,
                                       size_t pk_e_len,
                                       const spx_p2_cred_internal *cred,
                                       const uint8_t *public_ctx,
                                       size_t public_ctx_len);

#define spx_p2_show_verify_encryption_bound SPX_NAMESPACE(spx_p2_show_verify_encryption_bound)
int spx_p2_show_verify_encryption_bound(const spx_p2_show *show,
                                        const uint8_t *pk_sig,
                                        const uint8_t *pk_e,
                                        size_t pk_e_len);

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

/* Compatibility aliases kept for already migrated external callers. */
#define spx_p2_show_prove_explicit_pk_e spx_p2_show_prove_encryption_bound
#define spx_p2_show_verify_explicit_pk_e spx_p2_show_verify_encryption_bound
#define spx_p2_show_prove_strict_public spx_p2_show_prove_statement_bound
#define spx_p2_show_verify_strict_public spx_p2_show_verify_statement_bound

/* Compatibility verification path kept for legacy proof objects. */
#define spx_p2_show_verify_compat SPX_NAMESPACE(spx_p2_show_verify_compat)
int spx_p2_show_verify_compat(const spx_p2_show *show,
                              const uint8_t *pk);

#endif
