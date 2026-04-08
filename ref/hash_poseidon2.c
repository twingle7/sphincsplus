#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "poseidon2.h"

void initialize_hash_function(spx_ctx *ctx)
{
    (void)ctx;
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2 * SPX_N + SPX_ADDR_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, ctx->sk_seed, SPX_N);

    poseidon2_hash_bytes(out, SPX_N,
                         (const uint8_t *)"SPX_PRF_ADDR", 12,
                         buf, sizeof(buf));
}

/**
 * Computes message-dependent randomness R.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    spx_poseidon2_inc_ctx p2ctx;
    (void)ctx;

    poseidon2_inc_init(&p2ctx);
    poseidon2_inc_absorb(&p2ctx, (const uint8_t *)"SPX_GEN_MESSAGE_RANDOM", 22);
    poseidon2_inc_absorb(&p2ctx, sk_prf, SPX_N);
    poseidon2_inc_absorb(&p2ctx, optrand, SPX_N);
    poseidon2_inc_absorb(&p2ctx, m, (size_t)mlen);
    poseidon2_inc_finalize(&p2ctx);
    poseidon2_inc_squeeze(R, SPX_N, &p2ctx);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs digest, tree index and leaf index.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    spx_poseidon2_inc_ctx p2ctx;

    poseidon2_inc_init(&p2ctx);
    poseidon2_inc_absorb(&p2ctx, (const uint8_t *)"SPX_HASH_MESSAGE", 16);
    poseidon2_inc_absorb(&p2ctx, R, SPX_N);
    poseidon2_inc_absorb(&p2ctx, pk, SPX_PK_BYTES);
    poseidon2_inc_absorb(&p2ctx, m, (size_t)mlen);
    poseidon2_inc_finalize(&p2ctx);
    poseidon2_inc_squeeze(buf, SPX_DGST_BYTES, &p2ctx);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1) {
        *tree = 0;
    } else {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
