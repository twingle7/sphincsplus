#ifndef SPX_STARK_PI_F_FORMAT_V1_H
#define SPX_STARK_PI_F_FORMAT_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

#define SPX_P2_PI_F_V1_MAGIC 0x31504650u /* "PFP1" */
#define SPX_P2_PI_F_V1_VERSION 1u
#define SPX_P2_PI_F_V1_FLAG_NONZK_SKELETON 0x00000001u

#define SPX_P2_PI_F_V1_PROOF_SYSTEM_ID_SKELETON 1u

/* Fixed header fields are all u32 values. */
#define SPX_P2_PI_F_V1_FIXED_HEADER_U32 6u
#define SPX_P2_PI_F_V1_RESERVED_U32 2u
#define SPX_P2_PI_F_V1_FIXED_HEADER_BYTES (SPX_P2_PI_F_V1_FIXED_HEADER_U32 * 4u)
#define SPX_P2_PI_F_V1_RESERVED_BYTES (SPX_P2_PI_F_V1_RESERVED_U32 * 4u)
#define SPX_P2_PI_F_V1_MAX_BYTES_FOR_SIGMA(sigma_len) \
    (SPX_P2_PI_F_V1_FIXED_HEADER_BYTES + SPX_N + (sigma_len) + SPX_N + 8u + SPX_P2_PI_F_V1_RESERVED_BYTES)

typedef struct
{
    uint32_t flags;
    uint32_t proof_system_id;
    uint8_t ctx_binding[SPX_N];
    const uint8_t *sigma_com;
    uint32_t sigma_len;
    uint8_t commitment[SPX_N];
    uint32_t constraint_count;
    uint32_t violation_count;
} spx_p2_pi_f_v1_view;

#define spx_p2_pi_f_v1_encoded_len SPX_NAMESPACE(spx_p2_pi_f_v1_encoded_len)
size_t spx_p2_pi_f_v1_encoded_len(uint32_t sigma_len);

#define spx_p2_pi_f_v1_encode SPX_NAMESPACE(spx_p2_pi_f_v1_encode)
int spx_p2_pi_f_v1_encode(uint8_t *out, size_t *out_len, size_t max_out_len,
                          const spx_p2_pi_f_v1_view *view);

#define spx_p2_pi_f_v1_decode SPX_NAMESPACE(spx_p2_pi_f_v1_decode)
int spx_p2_pi_f_v1_decode(spx_p2_pi_f_v1_view *out_view,
                          const uint8_t *in, size_t in_len);

#endif
