#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../poseidon2.h"
#include "poseidon2_test_utils.h"

static int check_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

static int check_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) != 0;
}

int main(int argc, char **argv)
{
    static const size_t lens[] = {0, 1, 7, 8, 9, 47, 48, 49};
    uint8_t input[64];
    uint8_t out_one_shot[64];
    uint8_t out_inc[64];
    uint8_t out_f[64];
    uint8_t out_h[64];
    uint8_t out_tl[64];
    int verbose = spx_test_is_verbose(argc, argv);
    size_t oneshot_inc_checks = 0;
    size_t boundary_checks = 0;
    double t0 = spx_test_now_seconds();
    size_t i;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i + 1);
    }

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        size_t len = lens[i];
        spx_poseidon2_inc_ctx ctx;

        poseidon2_hash_bytes_domain(out_one_shot, sizeof(out_one_shot),
                                    SPX_P2_DOMAIN_HASH_MESSAGE, input, len);

        poseidon2_inc_init(&ctx, SPX_P2_DOMAIN_HASH_MESSAGE);
        poseidon2_inc_absorb(&ctx, input, len);
        poseidon2_inc_finalize(&ctx);
        poseidon2_inc_squeeze(out_inc, sizeof(out_inc), &ctx);

        if (!check_equal(out_one_shot, out_inc, sizeof(out_one_shot))) {
            printf("FAIL: oneshot/inc mismatch at len=%llu\n",
                   (unsigned long long)len);
            return 1;
        }
        oneshot_inc_checks++;
        if (verbose) {
            printf("[api] oneshot/inc len=%llu ok\n", (unsigned long long)len);
        }
    }

    for (i = 0; i + 1 < sizeof(lens) / sizeof(lens[0]); i++) {
        uint8_t out_a[64];
        uint8_t out_b[64];
        size_t len_a = lens[i];
        size_t len_b = lens[i + 1];

        poseidon2_hash_bytes_domain(out_a, sizeof(out_a),
                                    SPX_P2_DOMAIN_HASH_MESSAGE, input, len_a);
        poseidon2_hash_bytes_domain(out_b, sizeof(out_b),
                                    SPX_P2_DOMAIN_HASH_MESSAGE, input, len_b);

        if (!check_diff(out_a, out_b, sizeof(out_a))) {
            printf("FAIL: boundary differential collision at len=%llu/%llu\n",
                   (unsigned long long)len_a, (unsigned long long)len_b);
            return 1;
        }
        boundary_checks++;
        if (verbose) {
            printf("[api] boundary %llu/%llu diff ok\n",
                   (unsigned long long)len_a, (unsigned long long)len_b);
            spx_test_print_hex_prefix("  out_a", out_a, sizeof(out_a), 16);
            spx_test_print_hex_prefix("  out_b", out_b, sizeof(out_b), 16);
        }
    }

    poseidon2_hash_thash_f(out_f, sizeof(out_f), input, 49);
    poseidon2_hash_thash_h(out_h, sizeof(out_h), input, 49);
    poseidon2_hash_thash_tl(out_tl, sizeof(out_tl), input, 49);

    if (!check_diff(out_f, out_h, sizeof(out_f))) {
        printf("FAIL: THASH F/H domain separation\n");
        return 1;
    }
    if (!check_diff(out_h, out_tl, sizeof(out_h))) {
        printf("FAIL: THASH H/TL domain separation\n");
        return 1;
    }
    if (!check_diff(out_f, out_tl, sizeof(out_f))) {
        printf("FAIL: THASH F/TL domain separation\n");
        return 1;
    }

    printf("poseidon2_api test: OK | checks(oneshot/inc=%llu, boundary=%llu) | elapsed=%.6f s\n",
           (unsigned long long)oneshot_inc_checks,
           (unsigned long long)boundary_checks,
           spx_test_now_seconds() - t0);
    if (verbose) {
        spx_test_print_hex_prefix("thash_f", out_f, sizeof(out_f), 24);
        spx_test_print_hex_prefix("thash_h", out_h, sizeof(out_h), 24);
        spx_test_print_hex_prefix("thash_tl", out_tl, sizeof(out_tl), 24);
    }
    return 0;
}
