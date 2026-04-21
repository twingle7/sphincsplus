#ifndef SPX_SHOW_POSEIDON2_V1_H
#define SPX_SHOW_POSEIDON2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "../stark/ffi_v1.h"
#include "../stark/prover_v1.h"

#define SPX_P2_PUBLIC_CTX_MAX 64
/*
 * Final path uses Rust STARK pi_F_v2 whose proof bytes can be larger than legacy v1 upper bound.
 * Keep an explicit show-side cap to avoid BUFFER_SMALL on valid contexts.
 */
#define SPX_P2_SHOW_PI_F_MAX_BYTES (64u * 1024u)

/*
 * v1 external object:
 * - contains no sigma_com
 * - carries proof blob pi_f (v1 compat or v2 strict depending on API path)
 */
typedef struct
{
    uint8_t com[SPX_N];
    uint8_t pi_f[SPX_P2_SHOW_PI_F_MAX_BYTES];
    size_t pi_f_len;
    uint8_t public_ctx[SPX_P2_PUBLIC_CTX_MAX];
    size_t public_ctx_len;
} spx_p2_show_v1;

/*
 * v1 private holder/prover material (M5 freeze).
 * sigma_com remains private witness-side data.
 */
typedef struct
{
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

#define spx_p2_show_prove_m10_skeleton_v1 SPX_NAMESPACE(spx_p2_show_prove_m10_skeleton_v1)
int spx_p2_show_prove_m10_skeleton_v1(spx_p2_show_v1 *out,
                                      const uint8_t *pk,
                                      const spx_p2_cred_v1_internal *cred,
                                      const uint8_t *public_ctx,
                                      size_t public_ctx_len);

#define spx_p2_show_verify_m10_skeleton_v1 SPX_NAMESPACE(spx_p2_show_verify_m10_skeleton_v1)
int spx_p2_show_verify_m10_skeleton_v1(const spx_p2_show_v1 *show,
                                       const uint8_t *pk);

/*
 * Strict v2 APIs: require true STARK pi_F_v2 path.
 * These reject legacy v1 proof objects.
 */
#define spx_p2_show_prove_v2_strict SPX_NAMESPACE(spx_p2_show_prove_v2_strict)
int spx_p2_show_prove_v2_strict(spx_p2_show_v1 *out,
                                const uint8_t *pk,
                                const spx_p2_cred_v1_internal *cred,
                                const uint8_t *public_ctx,
                                size_t public_ctx_len);

#define spx_p2_show_verify_v2_strict SPX_NAMESPACE(spx_p2_show_verify_v2_strict)
int spx_p2_show_verify_v2_strict(const spx_p2_show_v1 *show,
                                 const uint8_t *pk);

#endif
