#ifndef SPX_HASH_PROFILE_H
#define SPX_HASH_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_HASH_PROFILE_MAX_INBLOCKS 64u

typedef struct {
    uint64_t thash_calls;
    uint64_t thash_simple_calls;
    uint64_t thash_robust_calls;
    uint64_t prf_addr_calls;
    uint64_t hash_message_calls;
    uint64_t gen_message_random_calls;
    uint64_t thash_input_bytes;
    uint64_t prf_addr_input_bytes;
    uint64_t hash_message_input_bytes;
    uint64_t gen_message_random_input_bytes;
    uint64_t hash_message_output_bytes;
    uint64_t gen_message_random_output_bytes;
    uint64_t thash_inblocks[SPX_HASH_PROFILE_MAX_INBLOCKS + 1u];
} spx_hash_profile_stats;

typedef struct {
    uint64_t sha256_compression_cost;
    uint64_t sha512_compression_cost;
    uint64_t shake256_permutation_cost;
    uint64_t poseidon2_permutation_cost;
    uint64_t haraka512_cost;
    uint64_t haraka256_cost;
    uint64_t haraka_s_cost;
} spx_hash_profile_cost_model;

typedef struct {
    spx_hash_profile_stats exact;
    char backend[16];
    char thash_mode[8];
    uint64_t estimated_sha256_compressions;
    uint64_t estimated_sha512_compressions;
    uint64_t estimated_shake256_permutations;
    uint64_t estimated_poseidon2_permutations;
    uint64_t estimated_haraka512_calls;
    uint64_t estimated_haraka256_calls;
    uint64_t estimated_haraka_s_calls;
    uint64_t estimated_constraints;
} spx_hash_profile_report;

#define spx_hash_profile_reset SPX_NAMESPACE(spx_hash_profile_reset)
void spx_hash_profile_reset(void);

#define spx_hash_profile_set_enabled SPX_NAMESPACE(spx_hash_profile_set_enabled)
void spx_hash_profile_set_enabled(int enabled);

#define spx_hash_profile_get_enabled SPX_NAMESPACE(spx_hash_profile_get_enabled)
int spx_hash_profile_get_enabled(void);

#define spx_hash_profile_note_thash SPX_NAMESPACE(spx_hash_profile_note_thash)
void spx_hash_profile_note_thash(unsigned int inblocks, size_t input_bytes,
                                 int is_robust);

#define spx_hash_profile_note_prf_addr SPX_NAMESPACE(spx_hash_profile_note_prf_addr)
void spx_hash_profile_note_prf_addr(size_t input_bytes);

#define spx_hash_profile_note_hash_message SPX_NAMESPACE(spx_hash_profile_note_hash_message)
void spx_hash_profile_note_hash_message(size_t input_bytes, size_t output_bytes);

#define spx_hash_profile_note_gen_message_random SPX_NAMESPACE(spx_hash_profile_note_gen_message_random)
void spx_hash_profile_note_gen_message_random(size_t input_bytes, size_t output_bytes);

#define spx_hash_profile_snapshot SPX_NAMESPACE(spx_hash_profile_snapshot)
void spx_hash_profile_snapshot(spx_hash_profile_stats *out_stats);

#define spx_hash_profile_default_cost_model SPX_NAMESPACE(spx_hash_profile_default_cost_model)
void spx_hash_profile_default_cost_model(spx_hash_profile_cost_model *out_model);

#define spx_hash_profile_build_report SPX_NAMESPACE(spx_hash_profile_build_report)
void spx_hash_profile_build_report(spx_hash_profile_report *out_report,
                                   const spx_hash_profile_cost_model *model);

#endif
