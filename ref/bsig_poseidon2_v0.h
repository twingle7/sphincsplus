#ifndef SPX_BSIG_POSEIDON2_V0_H
#define SPX_BSIG_POSEIDON2_V0_H

#include <stddef.h>
#include <stdint.h>

#include "hash_poseidon2_adapter.h"
#include "params.h"

typedef struct {
    uint8_t com[SPX_N];
    uint8_t sigma_com[SPX_BYTES];
    uint8_t pi_f[SPX_N];
} spx_p2_bsig_public;

typedef struct {
    spx_p2_bsig_public pub;
    spx_p2_trace trace;
} spx_p2_bsig_ctx;

#define spx_p2_bsig_issue SPX_NAMESPACE(spx_p2_bsig_issue)
int spx_p2_bsig_issue(spx_p2_bsig_ctx *ctx,
                      const uint8_t *sk,
                      const uint8_t *m, size_t mlen,
                      const uint8_t *r, size_t rlen);

#define spx_p2_bsig_prove SPX_NAMESPACE(spx_p2_bsig_prove)
int spx_p2_bsig_prove(spx_p2_bsig_ctx *ctx, const uint8_t *pk);

#define spx_p2_bsig_verify SPX_NAMESPACE(spx_p2_bsig_verify)
int spx_p2_bsig_verify(const spx_p2_bsig_public *pub, const uint8_t *pk);

#endif
