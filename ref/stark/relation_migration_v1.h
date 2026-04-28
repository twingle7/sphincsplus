#ifndef SPX_STARK_RELATION_MIGRATION_V1_H
#define SPX_STARK_RELATION_MIGRATION_V1_H

#include <stddef.h>
#include <stdint.h>

#include "ffi_v1.h"

/*
 * M20-3 migration layer:
 * centralize strict relation prechecks behind stable interfaces so later
 * iterations can move checks from C guards into native STARK constraints.
 */

#define spx_p2_relation_validate_strict_prove_inputs_v1 SPX_NAMESPACE(spx_p2_relation_validate_strict_prove_inputs_v1)
int spx_p2_relation_validate_strict_prove_inputs_v1(const spx_p2_ffi_public_inputs_v1 *pub,
                                                    const spx_p2_ffi_private_witness_v1 *wit);

#define spx_p2_relation_validate_strict_verify_inputs_v1 SPX_NAMESPACE(spx_p2_relation_validate_strict_verify_inputs_v1)
int spx_p2_relation_validate_strict_verify_inputs_v1(const spx_p2_ffi_public_inputs_v1 *pub);

#define spx_p2_relation_precheck_strict_prove_witness_v1 SPX_NAMESPACE(spx_p2_relation_precheck_strict_prove_witness_v1)
int spx_p2_relation_precheck_strict_prove_witness_v1(const spx_p2_ffi_public_inputs_v1 *pub,
                                                     const spx_p2_ffi_private_witness_v1 *wit);

#endif
