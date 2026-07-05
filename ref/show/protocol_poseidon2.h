#ifndef SPX_SHOW_PROTOCOL_POSEIDON2_H
#define SPX_SHOW_PROTOCOL_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "../api.h"
#include "show_poseidon2.h"

typedef enum
{
    SPX_P2_FLOW_OK = 0,
    SPX_P2_FLOW_ERR_NULL = -1,
    SPX_P2_FLOW_ERR_INPUT = -2,
    SPX_P2_FLOW_ERR_SIGN = -3,
    SPX_P2_FLOW_ERR_PROVE = -4,
    SPX_P2_FLOW_ERR_VERIFY = -5,
    SPX_P2_FLOW_ERR_BACKEND = -6
} spx_p2_flow_status;

typedef struct
{
    uint8_t c[SPX_N];
} spx_p2_issue_request_obj;

typedef struct
{
    uint8_t c[SPX_N];
    uint8_t sigma_prime[SPX_BYTES];
    size_t sigma_prime_len;
} spx_p2_issue_response_obj;

#define spx_p2_flow_status_to_string SPX_NAMESPACE(spx_p2_flow_status_to_string)
const char *spx_p2_flow_status_to_string(int status);

#define spx_p2_protocol_has_rust_backend SPX_NAMESPACE(spx_p2_protocol_has_rust_backend)
int spx_p2_protocol_has_rust_backend(void);

#define spx_p2_protocol_backend_mode SPX_NAMESPACE(spx_p2_protocol_backend_mode)
const char *spx_p2_protocol_backend_mode(void);

#define spx_p2_issue_request SPX_NAMESPACE(spx_p2_issue_request)
int spx_p2_issue_request(uint8_t out_com[SPX_N],
                         const uint8_t *m,
                         size_t mlen,
                         const uint8_t *r,
                         size_t rlen);

#define spx_p2_prepare_issue_request SPX_NAMESPACE(spx_p2_prepare_issue_request)
int spx_p2_prepare_issue_request(spx_p2_issue_request_obj *out_req,
                                 const uint8_t *m,
                                 size_t mlen,
                                 const uint8_t *r,
                                 size_t rlen);

#define spx_p2_issue_sign SPX_NAMESPACE(spx_p2_issue_sign)
int spx_p2_issue_sign(uint8_t out_sigma_blind[SPX_BYTES],
                      size_t *out_sigma_blind_len,
                      const uint8_t *issuer_sk,
                      const uint8_t com[SPX_N]);

#define spx_p2_issue_respond SPX_NAMESPACE(spx_p2_issue_respond)
int spx_p2_issue_respond(spx_p2_issue_response_obj *out_resp,
                         const uint8_t *issuer_sk,
                         const spx_p2_issue_request_obj *req);

#define spx_p2_unblind SPX_NAMESPACE(spx_p2_unblind)
/* Legacy compatibility alias. Fischlin final path should prefer finalize_credential(). */
int spx_p2_unblind(spx_p2_cred_internal *out_cred,
                   const uint8_t com[SPX_N],
                   const uint8_t sigma_blind[SPX_BYTES],
                   size_t sigma_blind_len,
                   const uint8_t *omega2,
                   size_t omega2_len);

#define spx_p2_finalize_credential SPX_NAMESPACE(spx_p2_finalize_credential)
int spx_p2_finalize_credential(spx_p2_cred_internal *out_cred,
                               const spx_p2_issue_request_obj *req,
                               const spx_p2_issue_response_obj *resp,
                               const uint8_t *m,
                               size_t mlen,
                               const uint8_t *r,
                               size_t rlen,
                               const uint8_t *omega2,
                               size_t omega2_len);

#define spx_p2_issue_unblind SPX_NAMESPACE(spx_p2_issue_unblind)
/* Legacy compatibility alias. Fischlin final path should prefer issue_finalize(). */
int spx_p2_issue_unblind(spx_p2_cred_internal *out_cred,
                         uint8_t out_com[SPX_N],
                         const uint8_t *issuer_sk,
                         const uint8_t *m,
                         size_t mlen,
                         const uint8_t *r,
                         size_t rlen,
                         const uint8_t *omega2,
                         size_t omega2_len);

#define spx_p2_issue_finalize SPX_NAMESPACE(spx_p2_issue_finalize)
int spx_p2_issue_finalize(spx_p2_cred_internal *out_cred,
                          spx_p2_issue_request_obj *out_req,
                          spx_p2_issue_response_obj *out_resp,
                          const uint8_t *issuer_sk,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *r,
                          size_t rlen,
                          const uint8_t *omega2,
                          size_t omega2_len);

#define spx_p2_protocol_show SPX_NAMESPACE(spx_p2_protocol_show)
int spx_p2_protocol_show(spx_p2_show *out_show,
                         const uint8_t *pk_sig,
                         const uint8_t *pk_e,
                         size_t pk_e_len,
                         const spx_p2_cred_internal *cred,
                         const uint8_t *public_ctx,
                         size_t public_ctx_len);

#define spx_p2_protocol_verify SPX_NAMESPACE(spx_p2_protocol_verify)
int spx_p2_protocol_verify(const spx_p2_show *show,
                           const uint8_t *pk_sig,
                           const uint8_t *pk_e,
                           size_t pk_e_len,
                           const uint8_t *m_pub,
                           size_t m_pub_len);

#endif
