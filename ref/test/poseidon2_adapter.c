#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "poseidon2_test_utils.h"

static spx_p2_trace g_trace;

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(int argc, char **argv)
{
    static const size_t lens[] = {0, 1, 7, 8, 9, 47, 48, 49};
    uint8_t msg[49];
    uint8_t r[16];
    uint8_t com[SPX_N];
    uint8_t com2[SPX_N];
    uint8_t com3[SPX_N];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    int verify_ret;
    int trace_verify_ret;
    int verbose = spx_test_is_verbose(argc, argv);
    size_t encode_checks = 0;
    size_t trace_checks = 0;
    double t0 = spx_test_now_seconds();
    size_t i;

    for (i = 0; i < sizeof(msg); i++)
    {
        msg[i] = (uint8_t)i;
    }
    for (i = 0; i < sizeof(r); i++)
    {
        r[i] = (uint8_t)(0x80u + i);
    }

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++)
    {
        size_t n = lens[i];
        size_t lane_count = 0;
        uint64_t lanes[8];
        if (spx_p2_encode_bytes_to_lanes(lanes, &lane_count, msg, n) != 0)
        {
            fail("encode_return");
            return 1;
        }
        if (lane_count != (n + 7u) / 8u)
        {
            fail("encode_lane_count");
            return 1;
        }
        encode_checks++;
        if (verbose) {
            printf("[adapter] encode len=%llu lanes=%llu\n",
                   (unsigned long long)n, (unsigned long long)lane_count);
        }
    }

    spx_p2_commit(com, msg, 32, r, sizeof(r));
    spx_p2_commit(com2, msg, 32, r, sizeof(r));
    if (memcmp(com, com2, SPX_N) != 0)
    {
        fail("commit_deterministic");
        return 1;
    }
    msg[0] ^= 1u;
    spx_p2_commit(com3, msg, 32, r, sizeof(r));
    msg[0] ^= 1u;
    if (memcmp(com, com3, SPX_N) == 0)
    {
        fail("commit_message_binding");
        return 1;
    }

    memset(pk, 0x42, sizeof(pk));
    memset(sig, 0x24, sizeof(sig));
    verify_ret = spx_p2_verify_com(pk, com, sig);
    trace_verify_ret = spx_p2_trace_verify_com(&g_trace, pk, com, sig);
    if (verify_ret != trace_verify_ret)
    {
        fail("verify_path_consistency");
        return 1;
    }
    if (g_trace.call_count == 0)
    {
        fail("trace_nonempty");
        return 1;
    }
    if (g_trace.dropped_calls != 0 || g_trace.dropped_lanes != 0)
    {
        fail("trace_capacity");
        return 1;
    }

    for (i = 0; i < g_trace.call_count; i++)
    {
        const spx_p2_hash_call *c = &g_trace.calls[i];
        if (c->input_lane_count != (c->input_real_len + 7u) / 8u)
        {
            fail("trace_input_lane_len");
            return 1;
        }
        if (c->output_lane_count != (c->output_real_len + 7u) / 8u)
        {
            fail("trace_output_lane_len");
            return 1;
        }
        trace_checks++;
    }

    printf("poseidon2_adapter test: OK | encode_checks=%llu trace_calls=%llu trace_lane_checks=%llu elapsed=%.6f s\n",
           (unsigned long long)encode_checks,
           (unsigned long long)g_trace.call_count,
           (unsigned long long)trace_checks,
           spx_test_now_seconds() - t0);
    if (verbose) {
        spx_test_print_hex_prefix("commit", com, SPX_N, SPX_N);
        printf("[adapter] dropped_calls=%u dropped_lanes=%u total_lanes=%u\n",
               g_trace.dropped_calls, g_trace.dropped_lanes, g_trace.lane_count);
    }
    return 0;
}
