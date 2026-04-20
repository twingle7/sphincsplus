#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "../hash_poseidon2_adapter.h"
#include "ffi_v1.h"
#include "pi_f_format_v1.h"
#include "pi_f_format_v2.h"
#include "stats_v1.h"
#include "witness_format.h"

static double elapsed_ms(clock_t begin, clock_t end)
{
    return (double)(end - begin) * 1000.0 / (double)CLOCKS_PER_SEC;
}

static uint32_t load_u32_le(const uint8_t in[4])
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

int spx_p2_stark_collect_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                  const uint8_t *pk,
                                  const uint8_t *com,
                                  const uint8_t *sigma_com,
                                  const uint8_t *public_ctx,
                                  size_t public_ctx_len)
{
    uint8_t proof_buf[SPX_P2_PI_F_V1_MAX_BYTES];
    spx_p2_trace trace;
    spx_p2_ffi_blob_v1 blob;
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;
    size_t rows = 0;
    clock_t t0;
    clock_t t1;
    int ret;

    if (out_stats == 0 || pk == 0 || com == 0 || sigma_com == 0 ||
        (public_ctx_len > 0 && public_ctx == 0))
    {
        return -1;
    }

    memset(out_stats, 0, sizeof(*out_stats));
    if (spx_p2_trace_verify_com(&trace, pk, com, sigma_com) != 0)
    {
        return -1;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &rows) != 0)
    {
        return -1;
    }

    blob.data = proof_buf;
    blob.len = 0;
    blob.cap = sizeof(proof_buf);
    pub.pk = pk;
    pub.com = com;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = public_ctx_len;
    wit.sigma_com = sigma_com;

    t0 = clock();
    ret = spx_p2_ffi_generate_pi_f_v1(&blob, &pub, &wit);
    t1 = clock();
    if (ret != SPX_P2_FFI_OK)
    {
        return -1;
    }
    out_stats->prove_ms = elapsed_ms(t0, t1);

    t0 = clock();
    ret = spx_p2_ffi_verify_pi_f_v1(&blob, &pub);
    t1 = clock();
    if (ret != SPX_P2_FFI_OK)
    {
        return -1;
    }
    out_stats->verify_ms = elapsed_ms(t0, t1);

    out_stats->trace_calls = trace.call_count;
    out_stats->trace_lanes = trace.lane_count;
    if (blob.len >= 8u)
    {
        out_stats->proof_magic = load_u32_le(blob.data);
        out_stats->proof_version = load_u32_le(blob.data + 4u);
    }
    else
    {
        out_stats->proof_magic = 0u;
        out_stats->proof_version = 0u;
    }
    out_stats->witness_rows = rows;
    out_stats->proof_bytes = blob.len;
    return 0;
}
