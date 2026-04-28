#define _POSIX_C_SOURCE 199309L

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <sys/resource.h>
#include <unistd.h>
#endif

#include "../hash_poseidon2_adapter.h"
#include "air_verify_full.h"
#include "ffi_v1.h"
#include "pi_f_format_v1.h"
#include "pi_f_format_v2.h"
#include "stats_v1.h"
#include "witness_format.h"

#define SPX_P2_STATS_PI_F_MAX_BYTES (64u * 1024u)

#ifdef SPX_P2_USE_RUST_STARK
#define SPX_P2_RUST_TRACE_WIDTH 52u
#define SPX_P2_RUST_TRACE_LENGTH 64u
#define SPX_P2_RUST_TRANSITION_CONSTRAINTS 76u
#define SPX_P2_RUST_BOUNDARY_ASSERTIONS 80u
#endif

static uint32_t load_u32_le(const uint8_t in[4])
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static double monotonic_ms(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (freq.QuadPart == 0)
    {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#endif
}

static size_t current_rss_kb(void)
{
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX counters;
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS *)&counters,
                             sizeof(counters)) == 0)
    {
        return 0;
    }
    return (size_t)(counters.WorkingSetSize / 1024u);
#elif defined(__linux__)
    FILE *fp = fopen("/proc/self/statm", "r");
    long pages = 0;
    long page_size;
    if (fp == 0)
    {
        return 0;
    }
    if (fscanf(fp, "%*s %ld", &pages) != 1)
    {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        return 0;
    }
    return (size_t)(((uint64_t)pages * (uint64_t)page_size) / 1024u);
#else
    return 0;
#endif
}

static size_t peak_rss_kb(void)
{
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX counters;
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             (PROCESS_MEMORY_COUNTERS *)&counters,
                             sizeof(counters)) == 0)
    {
        return 0;
    }
    return (size_t)(counters.PeakWorkingSetSize / 1024u);
#elif defined(__linux__)
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0)
    {
        return 0;
    }
    return (size_t)usage.ru_maxrss;
#else
    return 0;
#endif
}

static void fill_air_metadata(spx_p2_stark_stats_v1 *out_stats)
{
    out_stats->witness_row_bytes = sizeof(spx_p2_witness_row_v1);
#ifdef SPX_P2_USE_RUST_STARK
    out_stats->trace_width = SPX_P2_RUST_TRACE_WIDTH;
    out_stats->trace_length = SPX_P2_RUST_TRACE_LENGTH;
    out_stats->transition_constraints = SPX_P2_RUST_TRANSITION_CONSTRAINTS;
    out_stats->boundary_assertions = SPX_P2_RUST_BOUNDARY_ASSERTIONS;
    out_stats->constraint_eval_total =
        SPX_P2_RUST_TRANSITION_CONSTRAINTS * (SPX_P2_RUST_TRACE_LENGTH - 1u) +
        SPX_P2_RUST_BOUNDARY_ASSERTIONS;
    out_stats->constraint_violations = 0;
#else
    out_stats->trace_width = 0;
    out_stats->trace_length = out_stats->witness_rows;
    out_stats->transition_constraints = 0;
    out_stats->boundary_assertions = 0;
#endif
}

int spx_p2_stark_collect_ffi_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                      const spx_p2_ffi_public_inputs_v1 *pub,
                                      const spx_p2_ffi_private_witness_v1 *wit)
{
    uint8_t proof_buf[SPX_P2_STATS_PI_F_MAX_BYTES];
    spx_p2_trace trace;
    spx_p2_ffi_blob_v1 blob;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    double pre_begin;
    double t0;
    double t1;
    int ret;

    if (out_stats == 0 || pub == 0 || wit == 0)
    {
        return -1;
    }
    if (pub->pk == 0 || pub->com == 0 || wit->sigma_com == 0 ||
        (pub->pk_e_len > 0 && pub->pk_e == 0) ||
        (pub->m_pub_len > 0 && pub->m_pub == 0) ||
        (pub->public_ctx_len > 0 && pub->public_ctx == 0) ||
        (pub->sigma_c_len > 0 && pub->sigma_c == 0) ||
        (wit->mlen > 0 && wit->m == 0) ||
        (wit->rlen > 0 && wit->r == 0) ||
        (wit->omega2_len > 0 && wit->omega2 == 0))
    {
        return -1;
    }

    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->rss_before_kb = current_rss_kb();
    pre_begin = monotonic_ms();

    t0 = monotonic_ms();
    if (spx_p2_trace_verify_com(&trace, pub->pk, pub->com, wit->sigma_com) != 0)
    {
        return -1;
    }
    t1 = monotonic_ms();
    out_stats->trace_replay_ms = t1 - t0;
    out_stats->trace_calls = trace.call_count;
    out_stats->trace_lanes = trace.lane_count;

    t0 = monotonic_ms();
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0)
    {
        return -1;
    }
    t1 = monotonic_ms();
    out_stats->witness_count_ms = t1 - t0;
    out_stats->witness_rows = row_count;
    fill_air_metadata(out_stats);

    if (row_count > 0)
    {
        rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(*rows));
        if (rows == 0)
        {
            return -1;
        }
        t0 = monotonic_ms();
        if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
        {
            free(rows);
            return -1;
        }
        t1 = monotonic_ms();
        out_stats->witness_build_ms = t1 - t0;
        out_stats->witness_rows = row_count;
#ifndef SPX_P2_USE_RUST_STARK
        out_stats->trace_length = row_count;
#endif
    }

#ifndef SPX_P2_USE_RUST_STARK
    if (rows != 0)
    {
        t0 = monotonic_ms();
        if (spx_p2_verify_full_air_eval_constraints_v1(pub->pk, pub->com, wit->sigma_com,
                                                       &trace, rows, row_count,
                                                       &out_stats->constraint_eval_total,
                                                       &out_stats->constraint_violations) != 0)
        {
            free(rows);
            return -1;
        }
        t1 = monotonic_ms();
        out_stats->constraint_eval_ms = t1 - t0;
    }
#endif

    out_stats->preprocess_ms = out_stats->trace_replay_ms +
                               out_stats->witness_count_ms +
                               out_stats->witness_build_ms +
                               out_stats->constraint_eval_ms;

    blob.data = proof_buf;
    blob.len = 0;
    blob.cap = sizeof(proof_buf);

    t0 = monotonic_ms();
    ret = spx_p2_ffi_generate_pi_f_v1(&blob, pub, wit);
    t1 = monotonic_ms();
    if (ret != SPX_P2_FFI_OK)
    {
        free(rows);
        return -1;
    }
    out_stats->prove_core_ms = t1 - t0;
    out_stats->prove_e2e_ms = t1 - pre_begin;
    out_stats->prove_ms = out_stats->prove_core_ms;
    out_stats->rss_after_prove_kb = current_rss_kb();
    out_stats->peak_rss_kb = peak_rss_kb();

    t0 = monotonic_ms();
    ret = spx_p2_ffi_verify_pi_f_v1(&blob, pub);
    t1 = monotonic_ms();
    if (ret != SPX_P2_FFI_OK)
    {
        free(rows);
        return -1;
    }
    out_stats->verify_ms = t1 - t0;
    out_stats->rss_after_verify_kb = current_rss_kb();
    if (out_stats->peak_rss_kb < peak_rss_kb())
    {
        out_stats->peak_rss_kb = peak_rss_kb();
    }

    if (blob.len >= 8u)
    {
        out_stats->proof_magic = load_u32_le(blob.data);
        out_stats->proof_version = load_u32_le(blob.data + 4u);
    }
    out_stats->proof_bytes = blob.len;

    free(rows);
    return 0;
}

int spx_p2_stark_collect_stats_v1(spx_p2_stark_stats_v1 *out_stats,
                                  const uint8_t *pk,
                                  const uint8_t *com,
                                  const uint8_t *sigma_com,
                                  const uint8_t *public_ctx,
                                  size_t public_ctx_len)
{
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;

    if (out_stats == 0 || pk == 0 || com == 0 || sigma_com == 0 ||
        (public_ctx_len > 0 && public_ctx == 0))
    {
        return -1;
    }

    memset(&pub, 0, sizeof(pub));
    memset(&wit, 0, sizeof(wit));
    pub.pk = pk;
    pub.com = com;
    pub.public_ctx = public_ctx;
    pub.public_ctx_len = public_ctx_len;
    wit.sigma_com = sigma_com;

    return spx_p2_stark_collect_ffi_stats_v1(out_stats, &pub, &wit);
}
