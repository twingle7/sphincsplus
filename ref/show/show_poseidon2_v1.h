#ifndef SPX_SHOW_POSEIDON2_V1_H
#define SPX_SHOW_POSEIDON2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"

#define SPX_P2_PUBLIC_CTX_MAX 64

/*
 * v1 external object (M5 freeze):
 * - contains no sigma_com
 * - pi_f is placeholder in M5, will be replaced by real STARK proof object in M10
 */
typedef struct {
    uint8_t com[SPX_N];
    uint8_t pi_f[SPX_N];
    uint8_t public_ctx[SPX_P2_PUBLIC_CTX_MAX];
    size_t public_ctx_len;
} spx_p2_show_v1;

/*
 * v1 private holder/prover material (M5 freeze).
 * sigma_com remains private witness-side data.
 */
typedef struct {
    uint8_t m[SPX_BYTES];
    size_t mlen;
    uint8_t r[SPX_BYTES];
    size_t rlen;
    uint8_t com[SPX_N];
    uint8_t sigma_com[SPX_BYTES];
    spx_p2_trace trace;
} spx_p2_cred_v1_internal;

#define spx_p2_show_from_internal_v1 SPX_NAMESPACE(spx_p2_show_from_internal_v1)
int spx_p2_show_from_internal_v1(spx_p2_show_v1 *out,
                                 const spx_p2_cred_v1_internal *cred,
                                 const uint8_t *public_ctx, size_t public_ctx_len);

#define spx_p2_show_verify_shape_v1 SPX_NAMESPACE(spx_p2_show_verify_shape_v1)
int spx_p2_show_verify_shape_v1(const spx_p2_show_v1 *show);

#endif
