#ifndef SPX_STARK_PROVER_V1_H
#define SPX_STARK_PROVER_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "air_verify_full.h"
#include "pi_f_format_v1.h"

#define SPX_P2_PI_F_V1_MAX_BYTES SPX_P2_PI_F_V1_MAX_BYTES_FOR_SIGMA(SPX_BYTES)

#define spx_p2_prover_generate_pi_f_v1 SPX_NAMESPACE(spx_p2_prover_generate_pi_f_v1)
int spx_p2_prover_generate_pi_f_v1(uint8_t *out_pi_f, size_t *out_pi_f_len,
                                   size_t max_pi_f_len,
                                   const uint8_t *pk, const uint8_t *com,
                                   const uint8_t *sigma_com,
                                   const uint8_t *public_ctx,
                                   size_t public_ctx_len);

#endif
