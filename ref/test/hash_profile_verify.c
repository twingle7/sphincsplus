#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"
#include "../hash_profile.h"
#include "../params.h"
#include "../randombytes.h"

static uint64_t env_u64(const char *name, uint64_t default_value)
{
    const char *value = getenv(name);
    char *end = 0;
    unsigned long long parsed;

    if (value == 0 || *value == '\0') {
        return default_value;
    }
    parsed = strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return default_value;
    }
    return (uint64_t)parsed;
}

static void print_histogram(const spx_hash_profile_stats *stats)
{
    unsigned int i;
    int first = 1;

    printf("thash_hist=");
    for (i = 0; i <= SPX_HASH_PROFILE_MAX_INBLOCKS; i++) {
        if (stats->thash_inblocks[i] == 0u) {
            continue;
        }
        if (!first) {
            printf(",");
        }
        printf("%u:%llu", i, (unsigned long long)stats->thash_inblocks[i]);
        first = 0;
    }
    if (first) {
        printf("none");
    }
}

int main(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t msg[SPX_N];
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen = 0;
    spx_hash_profile_cost_model model;
    spx_hash_profile_report report;

    randombytes(msg, sizeof(msg));

    if (crypto_sign_keypair(pk, sk) != 0) {
        printf("hash_profile_verify: status=FAIL step=keypair\n");
        return 1;
    }
    if (crypto_sign_signature(sig, &siglen, msg, sizeof(msg), sk) != 0) {
        printf("hash_profile_verify: status=FAIL step=sign\n");
        return 1;
    }

    spx_hash_profile_default_cost_model(&model);
    model.sha256_compression_cost = env_u64("SPX_PROFILE_SHA256_COST", model.sha256_compression_cost);
    model.sha512_compression_cost = env_u64("SPX_PROFILE_SHA512_COST", model.sha512_compression_cost);
    model.shake256_permutation_cost = env_u64("SPX_PROFILE_SHAKE256_COST", model.shake256_permutation_cost);
    model.poseidon2_permutation_cost = env_u64("SPX_PROFILE_POSEIDON2_COST", model.poseidon2_permutation_cost);
    model.haraka512_cost = env_u64("SPX_PROFILE_HARAKA512_COST", model.haraka512_cost);
    model.haraka256_cost = env_u64("SPX_PROFILE_HARAKA256_COST", model.haraka256_cost);
    model.haraka_s_cost = env_u64("SPX_PROFILE_HARAKAS_COST", model.haraka_s_cost);

    spx_hash_profile_reset();
    spx_hash_profile_set_enabled(1);
    if (crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk) != 0) {
        spx_hash_profile_set_enabled(0);
        printf("hash_profile_verify: status=FAIL step=verify\n");
        return 1;
    }
    spx_hash_profile_set_enabled(0);
    spx_hash_profile_build_report(&report, &model);

    printf("hash_profile_verify: status=OK backend=%s thash_mode=%s msg_len=%u ",
           report.backend, report.thash_mode, (unsigned)sizeof(msg));
    printf("thash_calls=%llu prf_addr_calls=%llu hash_message_calls=%llu ",
           (unsigned long long)report.exact.thash_calls,
           (unsigned long long)report.exact.prf_addr_calls,
           (unsigned long long)report.exact.hash_message_calls);
    printf("sha256_comp=%llu sha512_comp=%llu shake256_perm=%llu poseidon2_perm=%llu ",
           (unsigned long long)report.estimated_sha256_compressions,
           (unsigned long long)report.estimated_sha512_compressions,
           (unsigned long long)report.estimated_shake256_permutations,
           (unsigned long long)report.estimated_poseidon2_permutations);
    printf("haraka512=%llu haraka256=%llu haraka_s=%llu estimated_constraints=%llu ",
           (unsigned long long)report.estimated_haraka512_calls,
           (unsigned long long)report.estimated_haraka256_calls,
           (unsigned long long)report.estimated_haraka_s_calls,
           (unsigned long long)report.estimated_constraints);
    printf("model_sha256=%llu model_sha512=%llu model_shake256=%llu model_poseidon2=%llu ",
           (unsigned long long)model.sha256_compression_cost,
           (unsigned long long)model.sha512_compression_cost,
           (unsigned long long)model.shake256_permutation_cost,
           (unsigned long long)model.poseidon2_permutation_cost);
    printf("model_haraka512=%llu model_haraka256=%llu model_haraka_s=%llu ",
           (unsigned long long)model.haraka512_cost,
           (unsigned long long)model.haraka256_cost,
           (unsigned long long)model.haraka_s_cost);
    print_histogram(&report.exact);
    printf("\n");

    return 0;
}
