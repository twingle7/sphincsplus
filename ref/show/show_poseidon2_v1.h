#ifndef SPX_SHOW_POSEIDON2_V1_H
#define SPX_SHOW_POSEIDON2_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "../stark/ffi_v1.h"
#include "../stark/prover_v1.h"

#define SPX_P2_PUBLIC_CTX_MAX 64
#define SPX_P2_SIGMA_C_MAX_BYTES (2u * SPX_N)
/*
 * Final path uses Rust STARK pi_F_v2 whose proof bytes can be larger than legacy v1 upper bound.
 * Keep an explicit show-side cap to avoid BUFFER_SMALL on valid contexts.
 */
#define SPX_P2_SHOW_PI_F_MAX_BYTES (64u * 1024u)

/*
 * External show object (transition shape for M18):
 * - final semantic object is Sigma = (C, pi), where C is carried by sigma_C.
 * - legacy com is kept only for compat path migration; strict path uses sigma_C.
 * - object contains no sigma_com.
 */
typedef struct
{
    /* Final-path public object field: C. M18/M19 use a transitional carrier with fixed len=2*SPX_N. */
    uint8_t sigma_C[SPX_P2_SIGMA_C_MAX_BYTES];
    size_t sigma_C_len;
    /* Legacy compat field. To be removed after compat deprecation window. */
    uint8_t com[SPX_N];
    /* M20 main-path public message binding carrier. */
    uint8_t m_pub[SPX_BYTES];
    size_t m_pub_len;
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
    /* M19 witness extension: encryption randomness placeholder omega2. */
    uint8_t omega2[SPX_N];
    size_t omega2_len;
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

/* M19 explicit-input APIs: bind pk_sig and pk_E separately. */
#define spx_p2_show_prove_v2_strict_m19 SPX_NAMESPACE(spx_p2_show_prove_v2_strict_m19)
int spx_p2_show_prove_v2_strict_m19(spx_p2_show_v1 *out,
                                    const uint8_t *pk_sig,
                                    const uint8_t *pk_e,
                                    size_t pk_e_len,
                                    const spx_p2_cred_v1_internal *cred,
                                    const uint8_t *public_ctx,
                                    size_t public_ctx_len);

/* M20-6 strict prove path with explicit m_pub statement binding. */
#define spx_p2_show_prove_v2_strict_m20 SPX_NAMESPACE(spx_p2_show_prove_v2_strict_m20)
int spx_p2_show_prove_v2_strict_m20(spx_p2_show_v1 *out,
                                    const uint8_t *pk_sig,
                                    const uint8_t *pk_e,
                                    size_t pk_e_len,
                                    const spx_p2_cred_v1_internal *cred,
                                    const uint8_t *public_ctx,
                                    size_t public_ctx_len);

#define spx_p2_show_verify_v2_strict_m19 SPX_NAMESPACE(spx_p2_show_verify_v2_strict_m19)
int spx_p2_show_verify_v2_strict_m19(const spx_p2_show_v1 *show,
                                     const uint8_t *pk_sig,
                                     const uint8_t *pk_e,
                                     size_t pk_e_len);

/* M20-6 strict verify path with explicit public message binding. */
#define spx_p2_show_verify_v2_strict_m20 SPX_NAMESPACE(spx_p2_show_verify_v2_strict_m20)
int spx_p2_show_verify_v2_strict_m20(const spx_p2_show_v1 *show,
                                     const uint8_t *pk_sig,
                                     const uint8_t *pk_e,
                                     size_t pk_e_len,
                                     const uint8_t *m_pub,
                                     size_t m_pub_len);

#endif
