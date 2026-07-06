#ifndef SPX_STARK_RELATION_MIGRATION_H
#define SPX_STARK_RELATION_MIGRATION_H

#include <stddef.h>
#include <stdint.h>

#include "ffi.h"

#define spx_p2_relation_validate_strict_prove_inputs SPX_NAMESPACE(spx_p2_relation_validate_strict_prove_inputs)
int spx_p2_relation_validate_strict_prove_inputs(const spx_p2_ffi_public_inputs *pub,
                                                 const spx_p2_ffi_private_witness *wit);

#define spx_p2_relation_validate_strict_verify_inputs SPX_NAMESPACE(spx_p2_relation_validate_strict_verify_inputs)
int spx_p2_relation_validate_strict_verify_inputs(const spx_p2_ffi_public_inputs *pub);

#define spx_p2_relation_precheck_strict_prove_witness SPX_NAMESPACE(spx_p2_relation_precheck_strict_prove_witness)
int spx_p2_relation_precheck_strict_prove_witness(const spx_p2_ffi_public_inputs *pub,
                                                  const spx_p2_ffi_private_witness *wit);

#define spx_p2_relation_eval_verify_full_guard SPX_NAMESPACE(spx_p2_relation_eval_verify_full_guard)
int spx_p2_relation_eval_verify_full_guard(const uint8_t *pk,
                                           const uint8_t *com,
                                           const uint8_t *sigma_com);

#endif
