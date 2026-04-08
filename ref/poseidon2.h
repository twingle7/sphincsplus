#ifndef SPX_POSEIDON2_H
#define SPX_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

typedef struct
{
    uint64_t state_inc[26];
} spx_poseidon2_inc_ctx;

#define poseidon2_inc_init SPX_NAMESPACE(poseidon2_inc_init)
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx);

#define poseidon2_inc_absorb SPX_NAMESPACE(poseidon2_inc_absorb)
void poseidon2_inc_absorb(spx_poseidon2_inc_ctx *ctx,
                          const uint8_t *input, size_t inlen);

#define poseidon2_inc_finalize SPX_NAMESPACE(poseidon2_inc_finalize)
void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx);

#define poseidon2_inc_squeeze SPX_NAMESPACE(poseidon2_inc_squeeze)
void poseidon2_inc_squeeze(uint8_t *output, size_t outlen,
                           spx_poseidon2_inc_ctx *ctx);

#define poseidon2_hash_bytes SPX_NAMESPACE(poseidon2_hash_bytes)
void poseidon2_hash_bytes(uint8_t *output, size_t outlen,
                          const uint8_t *domain, size_t domainlen,
                          const uint8_t *input, size_t inlen);

#endif
