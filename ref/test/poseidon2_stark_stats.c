#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/pi_f_format.h"
#include "../stark/stats.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t com[SPX_N];
    uint8_t sig[SPX_BYTES];
    uint8_t public_ctx[6] = {7, 7, 7, 1, 2, 3};
    size_t siglen = 0;
    spx_p2_stark_stats stats;

    memset(m, 0x13, sizeof(m));
    memset(r, 0x31, sizeof(r));
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
    if (spx_p2_stark_collect_stats(&stats, pk, com, sig, public_ctx, sizeof(public_ctx)) != 0)
    {
        fail("collect_stats_final_requires_v2");
        return 1;
    }
    if (stats.trace_calls == 0 || stats.trace_lanes == 0 || stats.witness_rows == 0 || stats.proof_bytes == 0)
    {
        fail("stats_zero");
        return 1;
    }
    if (stats.proof_magic != SPX_P2_PI_F_MAGIC || stats.proof_version != SPX_P2_PI_F_VERSION)
    {
        fail("proof_not_final_v2");
        return 1;
    }
    printf("poseidon2_stark_stats: calls=%u lanes=%u rows=%llu proof=%llu magic=0x%08x ver=%u prove_ms=%.3f verify_ms=%.3f\n",
           stats.trace_calls, stats.trace_lanes,
           (unsigned long long)stats.witness_rows,
           (unsigned long long)stats.proof_bytes,
           stats.proof_magic, stats.proof_version,
           stats.prove_ms, stats.verify_ms);
    return 0;
}
