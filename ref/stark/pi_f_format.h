#ifndef SPX_STARK_PI_F_FORMAT_H
#define SPX_STARK_PI_F_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "pi_f_format_v2.h"

typedef spx_p2_pi_f_v2_view spx_p2_pi_f_view;

#define SPX_P2_PI_F_MAGIC SPX_P2_PI_F_V2_MAGIC
#define SPX_P2_PI_F_VERSION SPX_P2_PI_F_V2_VERSION
#define SPX_P2_PI_F_FLAG_STARK_PROOF SPX_P2_PI_F_V2_FLAG_STARK_PROOF
#define SPX_P2_PI_F_STATEMENT_VERSION_VERIFY_FULL SPX_P2_PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1
#define SPX_P2_PI_F_PROOF_SYSTEM_ID_STARK SPX_P2_PI_F_V2_PROOF_SYSTEM_ID_STARK
#define SPX_P2_PI_F_FIXED_HEADER_BYTES SPX_P2_PI_F_V2_FIXED_HEADER_BYTES
#define SPX_P2_PI_F_RESERVED_BYTES SPX_P2_PI_F_V2_RESERVED_BYTES
#define SPX_P2_PI_F_MAX_BYTES_FOR_PROOF(proof_len) SPX_P2_PI_F_V2_MAX_BYTES_FOR_PROOF(proof_len)

#define spx_p2_pi_f_encoded_len SPX_NAMESPACE(spx_p2_pi_f_encoded_len)
size_t spx_p2_pi_f_encoded_len(uint32_t proof_len);

#define spx_p2_pi_f_encode SPX_NAMESPACE(spx_p2_pi_f_encode)
int spx_p2_pi_f_encode(uint8_t *out, size_t *out_len, size_t max_out_len,
                       const spx_p2_pi_f_view *view);

#define spx_p2_pi_f_decode SPX_NAMESPACE(spx_p2_pi_f_decode)
int spx_p2_pi_f_decode(spx_p2_pi_f_view *out_view,
                       const uint8_t *in, size_t in_len);

#endif
