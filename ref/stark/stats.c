#include "stats.h"
#include "pi_f_format.h"

int spx_p2_stark_collect_stats(spx_p2_stark_stats *out_stats,
                               const uint8_t *pk,
                               const uint8_t *com,
                               const uint8_t *sigma_com,
                               const uint8_t *public_ctx,
                               size_t public_ctx_len)
{
    int ret = spx_p2_stark_collect_stats_v1(out_stats, pk, com, sigma_com, public_ctx, public_ctx_len);
    if (ret != 0)
    {
        return ret;
    }
    /* Final stats API requires v2 proof path. */
    if (out_stats->proof_magic != SPX_P2_PI_F_MAGIC || out_stats->proof_version != SPX_P2_PI_F_VERSION)
    {
        return -2;
    }
    return 0;
}
