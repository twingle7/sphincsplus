#ifndef SPX_POSEIDON2_H
#define SPX_POSEIDON2_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

/* Draft parameter profile for the upcoming Goldilocks + sponge-first backend. */
#define SPX_POSEIDON2_FIELD_BITS 64
#define SPX_POSEIDON2_T 12
#define SPX_POSEIDON2_CAPACITY_WORDS 6
#define SPX_POSEIDON2_RATE_WORDS (SPX_POSEIDON2_T - SPX_POSEIDON2_CAPACITY_WORDS)
#define SPX_POSEIDON2_RATE_BYTES (SPX_POSEIDON2_RATE_WORDS * sizeof(uint64_t))
#define SPX_POSEIDON2_RF 8
#define SPX_POSEIDON2_RP 22

typedef enum
{
    /* PRF(pk_seed || ADRS || sk_seed) */
    SPX_P2_DOMAIN_PRF_ADDR = 0x01,
    /* PRF_msg(sk_prf || optrand || m) */
    SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM = 0x02,
    /* H_msg(R || pk || m) */
    SPX_P2_DOMAIN_HASH_MESSAGE = 0x03,
    SPX_P2_DOMAIN_THASH_SIMPLE = 0x10,
    /* THASH F/H/T_l share encoding but use distinct domains. */
    SPX_P2_DOMAIN_THASH_F = 0x11,
    SPX_P2_DOMAIN_THASH_H = 0x12,
    SPX_P2_DOMAIN_THASH_TL = 0x13,
    /* Commit(m || r) */
    SPX_P2_DOMAIN_COMMIT = 0x20,
    SPX_P2_DOMAIN_CUSTOM = 0xff
} spx_poseidon2_domain;

/* M1: fixed encoding sizes for SPHINCS+ Poseidon2 simple instantiation. */
#define SPX_P2_ENCODED_PRF_ADDR_BYTES (2 * SPX_N + SPX_ADDR_BYTES)
#define SPX_P2_ENCODED_THASH_BYTES(inblocks) (SPX_N + SPX_ADDR_BYTES + (inblocks) * SPX_N)
#define SPX_P2_HMSG_PREFIX_BYTES (SPX_N + SPX_PK_BYTES)

typedef struct
{
    uint64_t state[SPX_POSEIDON2_T];
    uint8_t absorb_buf[SPX_POSEIDON2_RATE_BYTES];
    uint8_t squeeze_buf[SPX_POSEIDON2_RATE_BYTES];
    size_t absorb_pos;
    size_t squeeze_pos;
    size_t squeeze_avail;
    uint8_t domain_tag;
    uint8_t finalized;
    uint8_t squeezing;
} spx_poseidon2_inc_ctx;

#define poseidon2_inc_init SPX_NAMESPACE(poseidon2_inc_init)
void poseidon2_inc_init(spx_poseidon2_inc_ctx *ctx,
                        spx_poseidon2_domain domain_tag);

#define poseidon2_inc_absorb SPX_NAMESPACE(poseidon2_inc_absorb)
void poseidon2_inc_absorb(spx_poseidon2_inc_ctx *ctx,
                          const uint8_t *input, size_t inlen);

#define poseidon2_inc_finalize SPX_NAMESPACE(poseidon2_inc_finalize)
void poseidon2_inc_finalize(spx_poseidon2_inc_ctx *ctx);

#define poseidon2_inc_squeeze SPX_NAMESPACE(poseidon2_inc_squeeze)
void poseidon2_inc_squeeze(uint8_t *output, size_t outlen,
                           spx_poseidon2_inc_ctx *ctx);

/*
 * Low-level permutation API (Goldilocks profile).
 * The implementation is now permutation-backed and no longer uses SHAKE.
 */
#define poseidon2_permute SPX_NAMESPACE(poseidon2_permute)
void poseidon2_permute(uint64_t state[SPX_POSEIDON2_T]);

#define poseidon2_hash_bytes_domain SPX_NAMESPACE(poseidon2_hash_bytes_domain)
void poseidon2_hash_bytes_domain(uint8_t *output, size_t outlen,
                                 spx_poseidon2_domain domain_tag,
                                 const uint8_t *input, size_t inlen);

typedef void (*spx_poseidon2_trace_callback)(
    void *user,
    uint8_t domain_tag,
    const uint8_t *input, size_t input_len,
    const uint8_t *output, size_t output_len);

#define poseidon2_set_trace_callback SPX_NAMESPACE(poseidon2_set_trace_callback)
void poseidon2_set_trace_callback(spx_poseidon2_trace_callback cb, void *user);

/* Formal THASH semantic-domain entry points. */
#define poseidon2_hash_thash_f SPX_NAMESPACE(poseidon2_hash_thash_f)
void poseidon2_hash_thash_f(uint8_t *output, size_t outlen,
                            const uint8_t *input, size_t inlen);

#define poseidon2_hash_thash_h SPX_NAMESPACE(poseidon2_hash_thash_h)
void poseidon2_hash_thash_h(uint8_t *output, size_t outlen,
                            const uint8_t *input, size_t inlen);

#define poseidon2_hash_thash_tl SPX_NAMESPACE(poseidon2_hash_thash_tl)
void poseidon2_hash_thash_tl(uint8_t *output, size_t outlen,
                             const uint8_t *input, size_t inlen);

/*
 * THASH helper that maps inblocks to semantic domains:
 * - 1 block -> F
 * - 2 blocks -> H
 * - >=3 blocks -> T_l
 */
#define poseidon2_hash_thash_by_inblocks SPX_NAMESPACE(poseidon2_hash_thash_by_inblocks)
void poseidon2_hash_thash_by_inblocks(uint8_t *output, size_t outlen,
                                      const uint8_t *input, size_t inlen,
                                      unsigned int inblocks);

/*
 * Transitional helper for older call sites only.
 * New code should use poseidon2_hash_bytes_domain() or the THASH semantic APIs.
 * Domain bytes are absorbed as payload under SPX_P2_DOMAIN_CUSTOM.
 */
#define poseidon2_hash_bytes SPX_NAMESPACE(poseidon2_hash_bytes)
void poseidon2_hash_bytes(uint8_t *output, size_t outlen,
                          const uint8_t *domain, size_t domainlen,
                          const uint8_t *input, size_t inlen);

#endif
