#ifndef SPX_HASH_POSEIDON2_ADAPTER_H
#define SPX_HASH_POSEIDON2_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define SPX_P2_TRACE_MAX_CALLS 4096
#define SPX_P2_TRACE_MAX_LANES 262144

typedef struct {
    uint8_t domain_tag;
    uint32_t addr_words[8];
    uint32_t input_real_len;
    uint32_t input_lane_count;
    uint32_t input_lane_offset;
    uint32_t output_real_len;
    uint32_t output_lane_count;
    uint32_t output_lane_offset;
} spx_p2_hash_call;

typedef struct {
    uint32_t call_count;
    uint32_t dropped_calls;
    uint32_t lane_count;
    uint32_t dropped_lanes;
    spx_p2_hash_call calls[SPX_P2_TRACE_MAX_CALLS];
    uint64_t lanes[SPX_P2_TRACE_MAX_LANES];
} spx_p2_trace;

#define spx_p2_trace_reset SPX_NAMESPACE(spx_p2_trace_reset)
void spx_p2_trace_reset(spx_p2_trace *trace);

#define spx_p2_encode_bytes_to_lanes SPX_NAMESPACE(spx_p2_encode_bytes_to_lanes)
int spx_p2_encode_bytes_to_lanes(uint64_t *out_lanes, size_t *out_count,
                                 const uint8_t *in_bytes, size_t in_len);

#define spx_p2_commit SPX_NAMESPACE(spx_p2_commit)
void spx_p2_commit(uint8_t *com,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *r, size_t rlen);

#define spx_p2_verify_com SPX_NAMESPACE(spx_p2_verify_com)
int spx_p2_verify_com(const uint8_t *pk, const uint8_t *com, const uint8_t *sigma_com);

#define spx_p2_trace_verify_com SPX_NAMESPACE(spx_p2_trace_verify_com)
int spx_p2_trace_verify_com(spx_p2_trace *trace,
                            const uint8_t *pk, const uint8_t *com,
                            const uint8_t *sigma_com);

#endif
