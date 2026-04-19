#ifndef SPX_STARK_PI_F_FORMAT_V2_H
#define SPX_STARK_PI_F_FORMAT_V2_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

#define SPX_P2_PI_F_V2_MAGIC 0x32504650u /* "PFP2" */
#define SPX_P2_PI_F_V2_VERSION 2u
#define SPX_P2_PI_F_V2_FLAG_STARK_PROOF 0x00000001u
#define SPX_P2_PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1 1u
#define SPX_P2_PI_F_V2_PROOF_SYSTEM_ID_STARK 2u

#define SPX_P2_PI_F_V2_FIXED_HEADER_U32 7u
#define SPX_P2_PI_F_V2_RESERVED_U32 2u
#define SPX_P2_PI_F_V2_FIXED_HEADER_BYTES (SPX_P2_PI_F_V2_FIXED_HEADER_U32 * 4u)
#define SPX_P2_PI_F_V2_RESERVED_BYTES (SPX_P2_PI_F_V2_RESERVED_U32 * 4u)
#define SPX_P2_PI_F_V2_MAX_BYTES_FOR_PROOF(proof_len) \
    (SPX_P2_PI_F_V2_FIXED_HEADER_BYTES + SPX_N + SPX_N + SPX_N + 4u + (proof_len) + SPX_P2_PI_F_V2_RESERVED_BYTES)

typedef struct
{
    uint32_t flags;
    uint32_t proof_system_id;
    uint32_t statement_version;
    uint8_t public_input_digest[SPX_N];
    uint8_t ctx_binding[SPX_N];
    uint8_t commitment[SPX_N];
    const uint8_t *proof_bytes;
    uint32_t proof_len;
} spx_p2_pi_f_v2_view;

#define spx_p2_pi_f_v2_encoded_len SPX_NAMESPACE(spx_p2_pi_f_v2_encoded_len)
size_t spx_p2_pi_f_v2_encoded_len(uint32_t proof_len);

#define spx_p2_pi_f_v2_encode SPX_NAMESPACE(spx_p2_pi_f_v2_encode)
int spx_p2_pi_f_v2_encode(uint8_t *out, size_t *out_len, size_t max_out_len,
                          const spx_p2_pi_f_v2_view *view);

#define spx_p2_pi_f_v2_decode SPX_NAMESPACE(spx_p2_pi_f_v2_decode)
int spx_p2_pi_f_v2_decode(spx_p2_pi_f_v2_view *out_view,
                          const uint8_t *in, size_t in_len);

#endif
