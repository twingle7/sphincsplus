#ifndef SPX_STARK_STATS_V1_H
#define SPX_STARK_STATS_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"
#include "ffi_v1.h"

typedef struct
{
    uint32_t trace_calls;
    uint32_t trace_lanes;
    uint32_t proof_magic;
    uint32_t proof_version;
    uint32_t transition_constraints;
    uint32_t boundary_assertions;
    uint32_t constraint_eval_total;
    uint32_t constraint_violations;
    size_t witness_rows;
    size_t witness_row_bytes;
    size_t trace_width;
    size_t trace_length;
    size_t proof_bytes;
    size_t rss_before_kb;
    size_t rss_after_prove_kb;
    size_t rss_after_verify_kb;
    size_t peak_rss_kb;
    double trace_replay_ms;
    double witness_count_ms;
    double witness_build_ms;
    double constraint_eval_ms;
    double preprocess_ms;
    double prove_core_ms;
    double prove_e2e_ms;
    double prove_ms;
    double verify_ms;
} spx_p2_stark_stats_v1;

#define spx_p2_stark_collect_ffi_stats_v1 SPX_NAMESPACE(spx_p2_stark_collect_ffi_stats_v1)
int spx_p2_stark_collect_ffi_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                      const spx_p2_ffi_public_inputs_v1 *pub,
                                      const spx_p2_ffi_private_witness_v1 *wit);

#define spx_p2_stark_collect_stats_v1 SPX_NAMESPACE(spx_p2_stark_collect_stats_v1)
int spx_p2_stark_collect_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                  const uint8_t *pk,
                                  const uint8_t *com,
                                  const uint8_t *sigma_com,
                                  const uint8_t *public_ctx,
                                  size_t public_ctx_len);

#endif
