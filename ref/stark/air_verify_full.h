#ifndef SPX_STARK_AIR_VERIFY_FULL_H
#define SPX_STARK_AIR_VERIFY_FULL_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"
#include "../params.h"
#include "witness_format.h"

typedef struct
{
    uint8_t commitment[SPX_N];
    uint32_t constraint_count;
    uint32_t violation_count;
} spx_p2_verify_full_proof_v1;

#define spx_p2_verify_full_air_eval_module_constraints_v1 SPX_NAMESPACE(spx_p2_verify_full_air_eval_module_constraints_v1)
int spx_p2_verify_full_air_eval_module_constraints_v1(const spx_p2_trace *trace,
                                                      uint32_t *out_constraint_count,
                                                      uint32_t *out_violation_count);

#define spx_p2_verify_full_air_eval_constraints_v1 SPX_NAMESPACE(spx_p2_verify_full_air_eval_constraints_v1)
int spx_p2_verify_full_air_eval_constraints_v1(const uint8_t *pk,
                                               const uint8_t *com,
                                               const uint8_t *sigma_com,
                                               const spx_p2_trace *trace,
                                               const spx_p2_witness_row_v1 *rows,
                                               size_t row_count,
                                               uint32_t *out_constraint_count,
                                               uint32_t *out_violation_count);

#define spx_p2_verify_full_air_prove_v1 SPX_NAMESPACE(spx_p2_verify_full_air_prove_v1)
int spx_p2_verify_full_air_prove_v1(spx_p2_verify_full_proof_v1 *proof,
                                    const uint8_t *pk, const uint8_t *com,
                                    const uint8_t *sigma_com,
                                    const spx_p2_trace *trace,
                                    const spx_p2_witness_row_v1 *rows,
                                    size_t row_count);

#define spx_p2_verify_full_air_verify_v1 SPX_NAMESPACE(spx_p2_verify_full_air_verify_v1)
int spx_p2_verify_full_air_verify_v1(const spx_p2_verify_full_proof_v1 *proof,
                                     const uint8_t *pk, const uint8_t *com,
                                     const uint8_t *sigma_com,
                                     const spx_p2_trace *trace,
                                     const spx_p2_witness_row_v1 *rows,
                                     size_t row_count);

#endif
