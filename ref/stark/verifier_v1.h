#ifndef SPX_STARK_VERIFIER_V1_H
#define SPX_STARK_VERIFIER_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

#define spx_p2_verifier_verify_pi_f_v1 SPX_NAMESPACE(spx_p2_verifier_verify_pi_f_v1)
int spx_p2_verifier_verify_pi_f_v1(const uint8_t *pk, const uint8_t *com,
                                   const uint8_t *pi_f, size_t pi_f_len,
                                   const uint8_t *public_ctx, size_t public_ctx_len);

#endif
