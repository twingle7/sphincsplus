#include <stdint.h>
#include <string.h>

#include "poseidon2.h"
#include "fips202.h"
#include "utils.h"

/*
 * Placeholder backend for build plumbing:
 * - keeps a stable Poseidon2-facing API in this codebase
 * - currently backed by SHAKE256 until Poseidon2 permutation/encoding is fixed
 */
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx,
                        spx_poseidon2_domain domain_tag)
{
    shake256_inc_init(ctx->state_inc);
    ctx->domain_tag = (uint8_t)domain_tag;
    ctx->finalized = 0;
    shake256_inc_absorb(ctx->state_inc, &ctx->domain_tag, 1);
}

void poseidon2_inc_absorb(spx_poseidon2_inc_ctx *ctx,
                          const uint8_t *input, size_t inlen)
{
    if (ctx->finalized != 0 || inlen == 0)
    {
        return;
    }
    shake256_inc_absorb(ctx->state_inc, input, inlen);
}

void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx)
{
    if (ctx->finalized != 0)
    {
        return;
    }
    shake256_inc_finalize(ctx->state_inc);
    ctx->finalized = 1;
}

void poseidon2_inc_squeeze(uint8_t *output, size_t outlen,
                           spx_poseidon2_inc_ctx *ctx)
{
    if (ctx->finalized == 0)
    {
        poseidon2_inc_finalize(ctx);
    }
    shake256_inc_squeeze(output, outlen, ctx->state_inc);
}

void poseidon2_permute(uint64_t state[SPX_POSEIDON2_T])
{
    /*
     * Draft API stub.
     * We intentionally keep this symbol now so call sites and tests can be
     * wired before the real Poseidon2 round function lands.
     */
    (void)state;
}

void poseidon2_hash_bytes_domain(uint8_t *output, size_t outlen,
                                 spx_poseidon2_domain domain_tag,
                                 const uint8_t *input, size_t inlen)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, domain_tag);
    poseidon2_inc_absorb(&ctx, input, inlen);
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(output, outlen, &ctx);
}

void poseidon2_hash_bytes(uint8_t *output, size_t outlen,
                          const uint8_t *domain, size_t domainlen,
                          const uint8_t *input, size_t inlen)
{
    size_t total = domainlen + inlen;
    uint8_t empty = 0;

    if (total == 0)
    {
        poseidon2_hash_bytes_domain(output, outlen, SPX_P2_DOMAIN_CUSTOM, &empty, 0);
        return;
    }

    SPX_VLA(uint8_t, buf, total);
    if (domainlen > 0)
    {
        memcpy(buf, domain, domainlen);
    }
    if (inlen > 0)
    {
        memcpy(buf + domainlen, input, inlen);
    }
    poseidon2_hash_bytes_domain(output, outlen, SPX_P2_DOMAIN_CUSTOM, buf, total);
}
