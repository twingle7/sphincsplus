#ifndef SPX_STARK_STATS_V1_H
#define SPX_STARK_STATS_V1_H

#include <stddef.h>
#include <stdint.h>

#include "../params.h"

typedef struct
{
    uint32_t trace_calls;
    uint32_t trace_lanes;
    size_t witness_rows;
    size_t proof_bytes;
    double prove_ms;
    double verify_ms;
} spx_p2_stark_stats_v1;

#define spx_p2_stark_collect_stats_v1 SPX_NAMESPACE(spx_p2_stark_collect_stats_v1)
int spx_p2_stark_collect_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                  const uint8_t *pk,
                                  const uint8_t *com,
                                  const uint8_t *sigma_com,
                                  const uint8_t *public_ctx,
                                  size_t public_ctx_len);

#endif
