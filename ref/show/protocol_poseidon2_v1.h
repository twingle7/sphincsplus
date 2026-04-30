#ifndef SPX_SHOW_PROTOCOL_POSEIDON2_V1_H
#define SPX_SHOW_PROTOCOL_POSEIDON2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../api.h"
#include "show_poseidon2.h"

/*
 * Historical versioned protocol header.
 * Prefer `protocol_poseidon2.h` in new code; this file remains as the stable
 * backing definition for legacy names and older focused tests.
 */

typedef enum
{
    SPX_P2_FLOW_OK = 0,
    SPX_P2_FLOW_ERR_NULL = -1,
    SPX_P2_FLOW_ERR_INPUT = -2,
    SPX_P2_FLOW_ERR_SIGN = -3,
    SPX_P2_FLOW_ERR_PROVE = -4,
    SPX_P2_FLOW_ERR_VERIFY = -5,
    SPX_P2_FLOW_ERR_BACKEND = -6
} spx_p2_flow_status_v1;

#define spx_p2_flow_status_to_string_v1 SPX_NAMESPACE(spx_p2_flow_status_to_string_v1)
const char *spx_p2_flow_status_to_string_v1(int status);

#define spx_p2_protocol_has_rust_backend_v1 SPX_NAMESPACE(spx_p2_protocol_has_rust_backend_v1)
int spx_p2_protocol_has_rust_backend_v1(void);

#define spx_p2_protocol_backend_mode_v1 SPX_NAMESPACE(spx_p2_protocol_backend_mode_v1)
const char *spx_p2_protocol_backend_mode_v1(void);

/* Holder side: request = Commit(m, r). */
#define spx_p2_issue_request_v1 SPX_NAMESPACE(spx_p2_issue_request_v1)
int spx_p2_issue_request_v1(uint8_t out_com[SPX_N],
                            const uint8_t *m, size_t mlen,
                            const uint8_t *r, size_t rlen);

/* Issuer side: sign request com. */
#define spx_p2_issue_sign_v1 SPX_NAMESPACE(spx_p2_issue_sign_v1)
int spx_p2_issue_sign_v1(uint8_t out_sigma_blind[SPX_BYTES], size_t *out_sigma_blind_len,
                         const uint8_t *issuer_sk,
                         const uint8_t com[SPX_N]);

/* Holder side: unblind stage (omega2 is explicit randomness; auto-sampled if omitted). */
#define spx_p2_unblind_v1 SPX_NAMESPACE(spx_p2_unblind_v1)
int spx_p2_unblind_v1(spx_p2_cred_internal *out_cred,
                      const uint8_t com[SPX_N],
                      const uint8_t sigma_blind[SPX_BYTES], size_t sigma_blind_len,
                      const uint8_t *omega2, size_t omega2_len);

/* Convenience orchestration for full issue+unblind flow. */
#define spx_p2_issue_unblind_v1 SPX_NAMESPACE(spx_p2_issue_unblind_v1)
int spx_p2_issue_unblind_v1(spx_p2_cred_internal *out_cred,
                            uint8_t out_com[SPX_N],
                            const uint8_t *issuer_sk,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *r, size_t rlen,
                            const uint8_t *omega2, size_t omega2_len);

/* Show stage wrappers with unified flow status code. */
#define spx_p2_protocol_show_v1 SPX_NAMESPACE(spx_p2_protocol_show_v1)
int spx_p2_protocol_show_v1(spx_p2_show *out_show,
                            const uint8_t *pk_sig,
                            const uint8_t *pk_e, size_t pk_e_len,
                            const spx_p2_cred_internal *cred,
                            const uint8_t *public_ctx, size_t public_ctx_len);

/* Descriptive alias: strict show path with explicit public statement fields. */
#define spx_p2_protocol_show_strict_public_v1 SPX_NAMESPACE(spx_p2_protocol_show_strict_public_v1)
int spx_p2_protocol_show_strict_public_v1(spx_p2_show *out_show,
                                          const uint8_t *pk_sig,
                                          const uint8_t *pk_e,
                                          size_t pk_e_len,
                                          const spx_p2_cred_internal *cred,
                                          const uint8_t *public_ctx,
                                          size_t public_ctx_len);

#define spx_p2_protocol_show_m20_v1 SPX_NAMESPACE(spx_p2_protocol_show_m20_v1)
int spx_p2_protocol_show_m20_v1(spx_p2_show *out_show,
                                const uint8_t *pk_sig,
                                const uint8_t *pk_e,
                                size_t pk_e_len,
                                const spx_p2_cred_internal *cred,
                                const uint8_t *public_ctx,
                                size_t public_ctx_len);

#define spx_p2_protocol_verify_v1 SPX_NAMESPACE(spx_p2_protocol_verify_v1)
int spx_p2_protocol_verify_v1(const spx_p2_show *show,
                              const uint8_t *pk_sig,
                              const uint8_t *pk_e, size_t pk_e_len);

/* Strict verify with explicit m_pub as public input. */
#define spx_p2_protocol_verify_strict_public_v1 SPX_NAMESPACE(spx_p2_protocol_verify_strict_public_v1)
int spx_p2_protocol_verify_strict_public_v1(const spx_p2_show *show,
                                            const uint8_t *pk_sig,
                                            const uint8_t *pk_e,
                                            size_t pk_e_len,
                                            const uint8_t *m_pub,
                                            size_t m_pub_len);

#define spx_p2_protocol_verify_m20_v1 SPX_NAMESPACE(spx_p2_protocol_verify_m20_v1)
int spx_p2_protocol_verify_m20_v1(const spx_p2_show *show,
                                  const uint8_t *pk_sig,
                                  const uint8_t *pk_e,
                                  size_t pk_e_len,
                                  const uint8_t *m_pub,
                                  size_t m_pub_len);

#endif
