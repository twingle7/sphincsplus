#define _POSIX_C_SOURCE 199309L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <sys/resource.h>
#include <time.h>
#endif

#include "../api.h"
#include "../show/protocol_poseidon2_v1.h"
#include "../stark/ffi_v1.h"
#include "../stark/stats_v1.h"

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
#elif defined(__linux__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#else
    return 0.0;
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

static void fill_seq(uint8_t *buf, size_t len, uint8_t base)
{
    size_t i;
    for (i = 0; i < len; i++)
    {
        buf[i] = (uint8_t)(base + (uint8_t)i);
    }
}

static void print_header(void)
{
    printf("backend,flow,m_len,r_len,public_ctx_len,omega2_len,sigma_c_len,pi_f_len,");
    printf("trace_calls,trace_lanes,witness_rows,row_bytes,trace_width,trace_length,");
    printf("transition_constraints,boundary_assertions,constraint_eval_total,constraint_violations,");
    printf("keygen_ms,commit_ms,issue_ms,unblind_ms,show_total_ms,verify_total_ms,negative_verify_ms,");
    printf("trace_replay_ms,witness_count_ms,witness_build_ms,constraint_eval_ms,preprocess_ms,");
    printf("prove_ms,prove_e2e_ms,verify_ms,");
    printf("rss_before_kb,rss_after_prove_kb,rss_after_verify_kb,peak_rss_kb,");
    printf("proof_bytes,proof_magic,proof_version,negative_reject_ok\n");
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    spx_p2_stark_stats_v1 stats;
    spx_p2_ffi_public_inputs_v1 pub;
    spx_p2_ffi_private_witness_v1 wit;
    uint8_t issuer_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t issuer_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t pk_e[SPX_N];
    uint8_t com[SPX_N];
    uint8_t sigma_blind[SPX_BYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t omega2[SPX_N];
    uint8_t public_ctx[16] = {
        'F', 'I', 'S', 'C', 'H', 'L', 'I', 'N',
        '-', 'B', 'E', 'N', 'C', 'H', '2', '0'};
    uint8_t m_pub_bad[24];
    size_t sigma_blind_len = 0;
    double t0;
    double keygen_ms;
    double commit_ms;
    double issue_ms;
    double unblind_ms;
    double show_total_ms;
    double verify_total_ms;
    double negative_verify_ms;
    int ret;
    int neg_ok;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(&stats, 0, sizeof(stats));
    memset(&pub, 0, sizeof(pub));
    memset(&wit, 0, sizeof(wit));

    fill_seq(m, sizeof(m), 0x30u);
    fill_seq(r, sizeof(r), 0x80u);
    fill_seq(pk_e, sizeof(pk_e), 0xa0u);
    fill_seq(omega2, sizeof(omega2), 0xc0u);

    t0 = monotonic_ms();
    if (crypto_sign_keypair(issuer_pk, issuer_sk) != 0)
    {
        printf("FAIL:keygen\n");
        return 1;
    }
    keygen_ms = monotonic_ms() - t0;

    t0 = monotonic_ms();
    ret = spx_p2_issue_request_v1(com, m, sizeof(m), r, sizeof(r));
    commit_ms = monotonic_ms() - t0;
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL:commit\n");
        return 1;
    }

    t0 = monotonic_ms();
    ret = spx_p2_issue_sign_v1(sigma_blind, &sigma_blind_len, issuer_sk, com);
    issue_ms = monotonic_ms() - t0;
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL:issue\n");
        return 1;
    }

    t0 = monotonic_ms();
    ret = spx_p2_unblind_v1(&cred, com, sigma_blind, sigma_blind_len, omega2, sizeof(omega2));
    unblind_ms = monotonic_ms() - t0;
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL:unblind\n");
        return 1;
    }
    memcpy(cred.m, m, sizeof(m));
    cred.mlen = sizeof(m);
    memcpy(cred.r, r, sizeof(r));
    cred.rlen = sizeof(r);

    t0 = monotonic_ms();
    ret = spx_p2_protocol_show_m20_v1(&show_obj, issuer_pk, pk_e, sizeof(pk_e),
                                      &cred, public_ctx, sizeof(public_ctx));
    show_total_ms = monotonic_ms() - t0;
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL:show\n");
        return 1;
    }

    t0 = monotonic_ms();
    ret = spx_p2_protocol_verify_m20_v1(&show_obj, issuer_pk, pk_e, sizeof(pk_e), m, sizeof(m));
    verify_total_ms = monotonic_ms() - t0;
    if (ret != SPX_P2_FLOW_OK)
    {
        printf("FAIL:verify\n");
        return 1;
    }

    memcpy(m_pub_bad, m, sizeof(m_pub_bad));
    m_pub_bad[0] ^= 1u;
    t0 = monotonic_ms();
    ret = spx_p2_protocol_verify_m20_v1(&show_obj, issuer_pk, pk_e, sizeof(pk_e),
                                        m_pub_bad, sizeof(m_pub_bad));
    negative_verify_ms = monotonic_ms() - t0;
    neg_ok = (ret != SPX_P2_FLOW_OK) ? 1 : 0;

    pub.pk = issuer_pk;
    pub.pk_e = pk_e;
    pub.pk_e_len = sizeof(pk_e);
    pub.com = show_obj.com;
    pub.m_pub = show_obj.m_pub;
    pub.m_pub_len = show_obj.m_pub_len;
    pub.public_ctx = show_obj.public_ctx;
    pub.public_ctx_len = show_obj.public_ctx_len;
    pub.sigma_c = show_obj.sigma_C;
    pub.sigma_c_len = show_obj.sigma_C_len;
    wit.sigma_com = cred.sigma_com;
    wit.m = cred.m;
    wit.mlen = cred.mlen;
    wit.r = cred.r;
    wit.rlen = cred.rlen;
    wit.omega2 = cred.omega2;
    wit.omega2_len = cred.omega2_len;

    if (spx_p2_stark_collect_ffi_stats_v1(&stats, &pub, &wit) != 0)
    {
        printf("FAIL:stats\n");
        return 1;
    }

    print_header();
    printf("%s,M20,%llu,%llu,%llu,%llu,%llu,%llu,",
           spx_p2_protocol_backend_mode_v1(),
           (unsigned long long)sizeof(m),
           (unsigned long long)sizeof(r),
           (unsigned long long)sizeof(public_ctx),
           (unsigned long long)cred.omega2_len,
           (unsigned long long)show_obj.sigma_C_len,
           (unsigned long long)show_obj.pi_f_len);
    printf("%u,%u,%llu,%llu,%llu,%llu,",
           stats.trace_calls,
           stats.trace_lanes,
           (unsigned long long)stats.witness_rows,
           (unsigned long long)stats.witness_row_bytes,
           (unsigned long long)stats.trace_width,
           (unsigned long long)stats.trace_length);
    printf("%u,%u,%u,%u,",
           stats.transition_constraints,
           stats.boundary_assertions,
           stats.constraint_eval_total,
           stats.constraint_violations);
    printf("%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,",
           keygen_ms,
           commit_ms,
           issue_ms,
           unblind_ms,
           show_total_ms,
           verify_total_ms,
           negative_verify_ms);
    printf("%.3f,%.3f,%.3f,%.3f,%.3f,",
           stats.trace_replay_ms,
           stats.witness_count_ms,
           stats.witness_build_ms,
           stats.constraint_eval_ms,
           stats.preprocess_ms);
    printf("%.3f,%.3f,%.3f,",
           stats.prove_ms,
           stats.prove_e2e_ms,
           stats.verify_ms);
    printf("%llu,%llu,%llu,%llu,",
           (unsigned long long)stats.rss_before_kb,
           (unsigned long long)stats.rss_after_prove_kb,
           (unsigned long long)stats.rss_after_verify_kb,
           (unsigned long long)((peak_rss_kb() > stats.peak_rss_kb) ? peak_rss_kb() : stats.peak_rss_kb));
    printf("%llu,0x%08x,%u,%d\n",
           (unsigned long long)stats.proof_bytes,
           stats.proof_magic,
           stats.proof_version,
           neg_ok);
    return 0;
}
