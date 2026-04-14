#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "hash_poseidon2_adapter.h"
#include "poseidon2.h"

static uint32_t load_u32_le(const uint8_t *in)
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

void spx_p2_trace_reset(spx_p2_trace *trace)
{
    memset(trace, 0, sizeof(*trace));
}

int spx_p2_encode_bytes_to_lanes(uint64_t *out_lanes, size_t *out_count,
                                 const uint8_t *in_bytes, size_t in_len)
{
    size_t i;
    size_t lanes = (in_len + 7u) / 8u;

    if (out_count == 0)
    {
        return -1;
    }
    *out_count = lanes;
    if (out_lanes == 0)
    {
        return 0;
    }

    for (i = 0; i < lanes; i++)
    {
        size_t j;
        size_t base = i * 8u;
        uint64_t x = 0;
        size_t remaining = (in_len > base) ? (in_len - base) : 0;
        size_t chunk = (remaining >= 8u) ? 8u : remaining;
        for (j = 0; j < chunk; j++)
        {
            x |= ((uint64_t)in_bytes[base + j]) << (8u * j);
        }
        out_lanes[i] = x;
    }
    return 0;
}

static void fill_addr_words(uint32_t addr_words[8], uint8_t domain_tag,
                            const uint8_t *input, size_t inlen)
{
    size_t i;
    size_t addr_off = SPX_N;

    memset(addr_words, 0, 8u * sizeof(uint32_t));

    if (!(domain_tag == SPX_P2_DOMAIN_THASH_F ||
          domain_tag == SPX_P2_DOMAIN_THASH_H ||
          domain_tag == SPX_P2_DOMAIN_THASH_TL ||
          domain_tag == SPX_P2_DOMAIN_PRF_ADDR))
    {
        return;
    }

    if (inlen < addr_off + SPX_ADDR_BYTES)
    {
        return;
    }

    for (i = 0; i < 8u; i++)
    {
        addr_words[i] = load_u32_le(input + addr_off + 4u * i);
    }
}

static void trace_cb(void *user,
                     uint8_t domain_tag,
                     const uint8_t *input, size_t input_len,
                     const uint8_t *output, size_t output_len)
{
    spx_p2_trace *trace = (spx_p2_trace *)user;
    spx_p2_hash_call *call;
    size_t in_lanes = 0;
    size_t out_lanes = 0;

    if (trace == 0)
    {
        return;
    }
    if (trace->call_count >= SPX_P2_TRACE_MAX_CALLS)
    {
        trace->dropped_calls++;
        return;
    }

    call = &trace->calls[trace->call_count];
    call->domain_tag = domain_tag;
    fill_addr_words(call->addr_words, domain_tag, input, input_len);
    call->input_real_len = (uint32_t)input_len;
    call->output_real_len = (uint32_t)output_len;

    spx_p2_encode_bytes_to_lanes(0, &in_lanes, input, input_len);
    spx_p2_encode_bytes_to_lanes(0, &out_lanes, output, output_len);
    call->input_lane_count = (uint32_t)in_lanes;
    call->output_lane_count = (uint32_t)out_lanes;

    if (trace->lane_count + in_lanes + out_lanes > SPX_P2_TRACE_MAX_LANES)
    {
        trace->dropped_lanes += (uint32_t)(in_lanes + out_lanes);
        trace->dropped_calls++;
        return;
    }

    call->input_lane_offset = trace->lane_count;
    spx_p2_encode_bytes_to_lanes(trace->lanes + trace->lane_count, &in_lanes, input, input_len);
    trace->lane_count += (uint32_t)in_lanes;

    call->output_lane_offset = trace->lane_count;
    spx_p2_encode_bytes_to_lanes(trace->lanes + trace->lane_count, &out_lanes, output, output_len);
    trace->lane_count += (uint32_t)out_lanes;

    trace->call_count++;
}

void spx_p2_commit(uint8_t *com,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *r, size_t rlen)
{
    spx_poseidon2_inc_ctx ctx;
    poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_COMMIT);
    poseidon2_inc_absorb(&ctx, m, mlen);
    poseidon2_inc_absorb(&ctx, r, rlen);
    poseidon2_inc_finalize(&ctx);
    poseidon2_inc_squeeze(com, SPX_N, &ctx);
}

int spx_p2_verify_com(const uint8_t *pk, const uint8_t *com, const uint8_t *sigma_com)
{
    return crypto_sign_verify(sigma_com, SPX_BYTES, com, SPX_N, pk);
}

int spx_p2_trace_verify_com(spx_p2_trace *trace,
                            const uint8_t *pk, const uint8_t *com,
                            const uint8_t *sigma_com)
{
    int ret;
    spx_p2_trace_reset(trace);
    poseidon2_set_trace_callback(trace_cb, trace);
    ret = spx_p2_verify_com(pk, com, sigma_com);
    poseidon2_set_trace_callback(0, 0);
    return ret;
}
