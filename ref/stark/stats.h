#ifndef SPX_STARK_STATS_H
#define SPX_STARK_STATS_H

#include <stddef.h>
#include <stdint.h>

#include "stats_v1.h"

typedef spx_p2_stark_stats_v1 spx_p2_stark_stats;

#define spx_p2_stark_collect_stats SPX_NAMESPACE(spx_p2_stark_collect_stats)
int spx_p2_stark_collect_stats(spx_p2_stark_stats *out_stats,
                               const uint8_t *pk,
                               const uint8_t *com,
                               const uint8_t *sigma_com,
                               const uint8_t *public_ctx,
                               size_t public_ctx_len);

#endif
