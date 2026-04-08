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
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx)
{
    shake256_inc_init(ctx->state_inc);
}

void poseidon2_inc_absorb(spx_poseidon2_inc_ctx *ctx,
                          const uint8_t *input, size_t inlen)
{
    shake256_inc_absorb(ctx->state_inc, input, inlen);
}

void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx)
{
    shake256_inc_finalize(ctx->state_inc);
}

void poseidon2_inc_squeeze(uint8_t *output, size_t outlen,
                           spx_poseidon2_inc_ctx *ctx)
{
    shake256_inc_squeeze(output, outlen, ctx->state_inc);
}

void poseidon2_hash_bytes(uint8_t *output, size_t outlen,
                          const uint8_t *domain, size_t domainlen,
                          const uint8_t *input, size_t inlen)
{
    size_t total = domainlen + inlen;
    uint8_t empty = 0;

    if (total == 0) {
        shake256(output, outlen, &empty, 0);
        return;
    }

    SPX_VLA(uint8_t, buf, total);
    if (domainlen > 0) {
        memcpy(buf, domain, domainlen);
    }
    if (inlen > 0) {
        memcpy(buf + domainlen, input, inlen);
    }
    shake256(output, outlen, buf, total);
}
