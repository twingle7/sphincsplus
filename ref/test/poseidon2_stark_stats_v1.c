#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/pi_f_format_v1.h"
#include "../stark/pi_f_format_v2.h"
#include "../stark/stats_v1.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t com[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t public_ctx[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t siglen = 0;
    spx_p2_stark_stats_v1 stats;

    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));
    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sig, &siglen, com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }
    if (spx_p2_stark_collect_stats_v1(&stats, pk, com, sig, public_ctx, sizeof(public_ctx)) != 0)
    {
        fail("collect_stats");
        return 1;
    }
    if (stats.trace_calls == 0 || stats.trace_lanes == 0 || stats.witness_rows == 0 || stats.proof_bytes == 0)
    {
        fail("stats_zero");
        return 1;
    }
    if (stats.witness_row_bytes == 0)
    {
        fail("witness_row_bytes");
        return 1;
    }
    if (!((stats.proof_magic == SPX_P2_PI_F_V1_MAGIC && stats.proof_version == SPX_P2_PI_F_V1_VERSION) ||
          (stats.proof_magic == SPX_P2_PI_F_V2_MAGIC && stats.proof_version == SPX_P2_PI_F_V2_VERSION)))
    {
        fail("proof_version_unknown");
        return 1;
    }
    if (stats.prove_e2e_ms < stats.prove_core_ms)
    {
        fail("prove_e2e_lt_core");
        return 1;
    }

    printf("poseidon2_stark_stats_v1:\n");
    printf("  trace: calls=%u lanes=%u rows=%llu row_bytes=%llu width=%llu length=%llu\n",
           stats.trace_calls, stats.trace_lanes,
           (unsigned long long)stats.witness_rows,
           (unsigned long long)stats.witness_row_bytes,
           (unsigned long long)stats.trace_width,
           (unsigned long long)stats.trace_length);
    printf("  air: transition=%u assertions=%u eval_total=%u violations=%u\n",
           stats.transition_constraints,
           stats.boundary_assertions,
           stats.constraint_eval_total,
           stats.constraint_violations);
    printf("  proof: bytes=%llu magic=0x%08x ver=%u\n",
           (unsigned long long)stats.proof_bytes,
           stats.proof_magic, stats.proof_version);
    printf("  time_ms: replay=%.3f count=%.3f build=%.3f eval=%.3f preprocess=%.3f prove=%.3f prove_e2e=%.3f verify=%.3f\n",
           stats.trace_replay_ms,
           stats.witness_count_ms,
           stats.witness_build_ms,
           stats.constraint_eval_ms,
           stats.preprocess_ms,
           stats.prove_ms,
           stats.prove_e2e_ms,
           stats.verify_ms);
    printf("  rss_kb: before=%llu after_prove=%llu after_verify=%llu peak=%llu\n",
           (unsigned long long)stats.rss_before_kb,
           (unsigned long long)stats.rss_after_prove_kb,
           (unsigned long long)stats.rss_after_verify_kb,
           (unsigned long long)stats.peak_rss_kb);
    return 0;
}
