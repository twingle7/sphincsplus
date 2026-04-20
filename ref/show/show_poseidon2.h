#ifndef SPX_SHOW_POSEIDON2_H
#define SPX_SHOW_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "show_poseidon2_v1.h"

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

/* Compatibility verification path kept for legacy proof objects. */
#define spx_p2_show_verify_compat SPX_NAMESPACE(spx_p2_show_verify_compat)
int spx_p2_show_verify_compat(const spx_p2_show *show,
                              const uint8_t *pk);

#endif
