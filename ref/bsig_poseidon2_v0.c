#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "bsig_poseidon2_v0.h"
#include "poseidon2.h"

static void store_u32_le(uint8_t out[4], uint32_t x)
{
    out[0] = (uint8_t)(x & 0xffu);
    out[1] = (uint8_t)((x >> 8) & 0xffu);
    out[2] = (uint8_t)((x >> 16) & 0xffu);
    out[3] = (uint8_t)((x >> 24) & 0xffu);
}

static void compute_pi_f(uint8_t out[SPX_N], const spx_p2_bsig_ctx *ctx)
{
    uint8_t meta[16];
    spx_poseidon2_inc_ctx hctx;

    store_u32_le(meta + 0, ctx->trace.call_count);
    store_u32_le(meta + 4, ctx->trace.lane_count);
    store_u32_le(meta + 8, ctx->trace.dropped_calls);
    store_u32_le(meta + 12, ctx->trace.dropped_lanes);

    poseidon2_inc_init(&hctx, SPX_P2_DOMAIN_CUSTOM);
    poseidon2_inc_absorb(&hctx, ctx->pub.com, SPX_N);
    poseidon2_inc_absorb(&hctx, ctx->pub.sigma_com, SPX_BYTES);
    poseidon2_inc_absorb(&hctx, meta, sizeof(meta));
    poseidon2_inc_finalize(&hctx);
    poseidon2_inc_squeeze(out, SPX_N, &hctx);
}

int spx_p2_bsig_issue(spx_p2_bsig_ctx *ctx,
                      const uint8_t *sk,
                      const uint8_t *m, size_t mlen,
                      const uint8_t *r, size_t rlen)
{
    size_t siglen = 0;
    spx_p2_trace_reset(&ctx->trace);
    memset(ctx->pub.pi_f, 0, sizeof(ctx->pub.pi_f));
    spx_p2_commit(ctx->pub.com, m, mlen, r, rlen);
    if (crypto_sign_signature(ctx->pub.sigma_com, &siglen, ctx->pub.com, SPX_N, sk) != 0)
    {
        return -1;
    }
    if (siglen != SPX_BYTES)
    {
        return -1;
    }
    return 0;
}

int spx_p2_bsig_prove(spx_p2_bsig_ctx *ctx, const uint8_t *pk)
{
    if (spx_p2_trace_verify_com(&ctx->trace, pk, ctx->pub.com, ctx->pub.sigma_com) != 0)
    {
        return -1;
    }
    compute_pi_f(ctx->pub.pi_f, ctx);
    return 0;
}

int spx_p2_bsig_verify(const spx_p2_bsig_public *pub, const uint8_t *pk)
{
    int verify_ret = spx_p2_verify_com(pk, pub->com, pub->sigma_com);
    if (verify_ret != 0)
    {
        return -1;
    }
    /* v0: pi_F is checked as non-empty placeholder commitment. */
    if (memcmp(pub->pi_f, (const uint8_t[SPX_N]){0}, SPX_N) == 0)
    {
        return -1;
    }
    return 0;
}
