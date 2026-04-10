#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "poseidon2.h"
#include "utils.h"

#define P2_GOLDILOCKS_PRIME UINT64_C(0xFFFFFFFF00000001)

static uint64_t p2_round_constants[SPX_POSEIDON2_RF + SPX_POSEIDON2_RP][SPX_POSEIDON2_T];
static int p2_constants_initialized = 0;

static uint64_t p2_mod_reduce_u64(uint64_t x)
{
    if (x >= P2_GOLDILOCKS_PRIME)
    {
        return x - P2_GOLDILOCKS_PRIME;
    }
    return x;
}

static uint64_t p2_add(uint64_t a, uint64_t b)
{
    uint64_t sum = a + b;
    if (sum < a || sum >= P2_GOLDILOCKS_PRIME)
    {
        sum -= P2_GOLDILOCKS_PRIME;
    }
    return sum;
}

static uint64_t p2_sub(uint64_t a, uint64_t b)
{
    if (a >= b)
    {
        return a - b;
    }
    return P2_GOLDILOCKS_PRIME - (b - a);
}

static uint64_t p2_mul(uint64_t a, uint64_t b)
{
    __uint128_t prod = ((__uint128_t)a) * ((__uint128_t)b);
    uint64_t lo = (uint64_t)prod;
    uint64_t hi = (uint64_t)(prod >> 64);

    /* 2^64 == 2^32 - 1 mod p */
    uint64_t hi_shift = (hi << 32);
    uint64_t hi_fold = p2_sub(hi_shift, hi);
    uint64_t acc = p2_add(lo, hi_fold);
    return p2_mod_reduce_u64(acc);
}

static uint64_t p2_pow7(uint64_t x)
{
    uint64_t x2 = p2_mul(x, x);
    uint64_t x4 = p2_mul(x2, x2);
    return p2_mul(p2_mul(x4, x2), x);
}

static uint64_t p2_splitmix64_next(uint64_t *x)
{
    uint64_t z;
    *x += UINT64_C(0x9e3779b97f4a7c15);
    z = *x;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    z ^= (z >> 31);
    return z;
}

static void p2_init_constants(void)
{
    size_t r, i;
    uint64_t seed = UINT64_C(0x5350585f50325f31); /* "SPX_P2_1" */

    if (p2_constants_initialized != 0)
    {
        return;
    }

    for (r = 0; r < SPX_POSEIDON2_RF + SPX_POSEIDON2_RP; r++)
    {
        for (i = 0; i < SPX_POSEIDON2_T; i++)
        {
            p2_round_constants[r][i] = p2_mod_reduce_u64(p2_splitmix64_next(&seed));
        }
    }
    p2_constants_initialized = 1;
}

static uint64_t p2_load_lane_le(const uint8_t *src, size_t len)
{
    uint64_t x = 0;
    size_t i;
    for (i = 0; i < len; i++)
    {
        x |= ((uint64_t)src[i]) << (8 * i);
    }
    return p2_mod_reduce_u64(x);
}

static void p2_store_lane_le(uint8_t *dst, uint64_t x)
{
    size_t i;
    for (i = 0; i < sizeof(uint64_t); i++)
    {
        dst[i] = (uint8_t)(x & 0xffu);
        x >>= 8;
    }
}

static void p2_mix_external(uint64_t state[SPX_POSEIDON2_T])
{
    uint64_t sum = 0;
    uint64_t old[SPX_POSEIDON2_T];
    size_t i;

    memcpy(old, state, sizeof(old));
    for (i = 0; i < SPX_POSEIDON2_T; i++)
    {
        sum = p2_add(sum, old[i]);
    }
    for (i = 0; i < SPX_POSEIDON2_T; i++)
    {
        state[i] = p2_add(sum, old[i]);
    }
}

static void p2_mix_internal(uint64_t state[SPX_POSEIDON2_T])
{
    static const uint64_t diag[SPX_POSEIDON2_T] = {
        UINT64_C(2), UINT64_C(3), UINT64_C(4), UINT64_C(5),
        UINT64_C(6), UINT64_C(7), UINT64_C(8), UINT64_C(9),
        UINT64_C(10), UINT64_C(11), UINT64_C(12), UINT64_C(13)};
    uint64_t sum = 0;
    size_t i;

    for (i = 0; i < SPX_POSEIDON2_T; i++)
    {
        sum = p2_add(sum, state[i]);
    }
    for (i = 0; i < SPX_POSEIDON2_T; i++)
    {
        state[i] = p2_add(sum, p2_mul(diag[i], state[i]));
    }
}

void poseidon2_permute(uint64_t state[SPX_POSEIDON2_T])
{
    size_t r, i;
    const size_t rf_half = SPX_POSEIDON2_RF / 2;

    p2_init_constants();

    for (r = 0; r < rf_half; r++)
    {
        for (i = 0; i < SPX_POSEIDON2_T; i++)
        {
            state[i] = p2_add(state[i], p2_round_constants[r][i]);
            state[i] = p2_pow7(state[i]);
        }
        p2_mix_external(state);
    }

    for (r = 0; r < SPX_POSEIDON2_RP; r++)
    {
        size_t rr = rf_half + r;
        for (i = 0; i < SPX_POSEIDON2_T; i++)
        {
            state[i] = p2_add(state[i], p2_round_constants[rr][i]);
        }
        state[0] = p2_pow7(state[0]);
        p2_mix_internal(state);
    }

    for (r = 0; r < rf_half; r++)
    {
        size_t rr = rf_half + SPX_POSEIDON2_RP + r;
        for (i = 0; i < SPX_POSEIDON2_T; i++)
        {
            state[i] = p2_add(state[i], p2_round_constants[rr][i]);
            state[i] = p2_pow7(state[i]);
        }
        p2_mix_external(state);
    }
}

static void p2_absorb_block(spx_poseidon2_inc_ctx *ctx, const uint8_t *block)
{
    size_t i;
    for (i = 0; i < SPX_POSEIDON2_RATE_WORDS; i++)
    {
        uint64_t lane = p2_load_lane_le(block + i * sizeof(uint64_t), sizeof(uint64_t));
        ctx->state[i] = p2_add(ctx->state[i], lane);
    }
    poseidon2_permute(ctx->state);
}

static void p2_refill_squeeze(spx_poseidon2_inc_ctx *ctx)
{
    size_t i;
    for (i = 0; i < SPX_POSEIDON2_RATE_WORDS; i++)
    {
        p2_store_lane_le(ctx->squeeze_buf + i * sizeof(uint64_t), ctx->state[i]);
    }
    ctx->squeeze_pos = 0;
    ctx->squeeze_avail = SPX_POSEIDON2_RATE_BYTES;
}

void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx,
                        spx_poseidon2_domain domain_tag)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->domain_tag = (uint8_t)domain_tag;
    poseidon2_inc_absorb(ctx, &ctx->domain_tag, 1);
}

void poseidon2_inc_absorb(spx_poseidon2_inc_ctx *ctx,
                          const uint8_t *input, size_t inlen)
{
    size_t take;

    if (ctx->finalized != 0 || ctx->squeezing != 0 || inlen == 0)
    {
        return;
    }

    while (inlen > 0)
    {
        take = SPX_POSEIDON2_RATE_BYTES - ctx->absorb_pos;
        if (take > inlen)
        {
            take = inlen;
        }
        memcpy(ctx->absorb_buf + ctx->absorb_pos, input, take);
        ctx->absorb_pos += take;
        input += take;
        inlen -= take;

        if (ctx->absorb_pos == SPX_POSEIDON2_RATE_BYTES)
        {
            p2_absorb_block(ctx, ctx->absorb_buf);
            ctx->absorb_pos = 0;
            memset(ctx->absorb_buf, 0, sizeof(ctx->absorb_buf));
        }
    }
}

void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx)
{
    if (ctx->finalized != 0)
    {
        return;
    }

    /*
     * pad10*1 style padding over byte stream:
     *   message || 0x01 || 0* || 0x80(at last rate byte)
     */
    ctx->absorb_buf[ctx->absorb_pos] ^= 0x01u;
    ctx->absorb_buf[SPX_POSEIDON2_RATE_BYTES - 1] ^= 0x80u;
    p2_absorb_block(ctx, ctx->absorb_buf);

    ctx->absorb_pos = 0;
    memset(ctx->absorb_buf, 0, sizeof(ctx->absorb_buf));
    ctx->finalized = 1;
    ctx->squeezing = 0;
    ctx->squeeze_pos = 0;
    ctx->squeeze_avail = 0;
}

void poseidon2_inc_squeeze(uint8_t *output, size_t outlen,
                           spx_poseidon2_inc_ctx *ctx)
{
    size_t take;

    if (ctx->finalized == 0)
    {
        poseidon2_inc_finalize(ctx);
    }

    while (outlen > 0)
    {
        if (ctx->squeeze_avail == 0)
        {
            if (ctx->squeezing != 0)
            {
                poseidon2_permute(ctx->state);
            }
            else
            {
                ctx->squeezing = 1;
            }
            p2_refill_squeeze(ctx);
        }

        take = ctx->squeeze_avail;
        if (take > outlen)
        {
            take = outlen;
        }
        memcpy(output, ctx->squeeze_buf + ctx->squeeze_pos, take);
        output += take;
        outlen -= take;
        ctx->squeeze_pos += take;
        ctx->squeeze_avail -= take;
    }
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

void poseidon2_hash_thash_f(uint8_t *output, size_t outlen,
                            const uint8_t *input, size_t inlen)
{
    poseidon2_hash_bytes_domain(output, outlen, SPX_P2_DOMAIN_THASH_F, input, inlen);
}

void poseidon2_hash_thash_h(uint8_t *output, size_t outlen,
                            const uint8_t *input, size_t inlen)
{
    poseidon2_hash_bytes_domain(output, outlen, SPX_P2_DOMAIN_THASH_H, input, inlen);
}

void poseidon2_hash_thash_tl(uint8_t *output, size_t outlen,
                             const uint8_t *input, size_t inlen)
{
    poseidon2_hash_bytes_domain(output, outlen, SPX_P2_DOMAIN_THASH_TL, input, inlen);
}

void poseidon2_hash_thash_by_inblocks(uint8_t *output, size_t outlen,
                                      const uint8_t *input, size_t inlen,
                                      unsigned int inblocks)
{
    if (inblocks == 1)
    {
        poseidon2_hash_thash_f(output, outlen, input, inlen);
        return;
    }
    if (inblocks == 2)
    {
        poseidon2_hash_thash_h(output, outlen, input, inlen);
        return;
    }
    poseidon2_hash_thash_tl(output, outlen, input, inlen);
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
