#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../poseidon2.h"
#include "poseidon2_test_utils.h"

static int check_u64_eq(const uint64_t *a, const uint64_t *b, size_t n)
{
    return memcmp(a, b, n * sizeof(uint64_t)) == 0;
}

static int check_u8_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void print_fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(int argc, char **argv)
{
    static const uint64_t exp_permute[SPX_POSEIDON2_T] = {
        UINT64_C(0x569e62988f30ee99), UINT64_C(0xcd0890fce37eff2f),
        UINT64_C(0x62a011536b1b030f), UINT64_C(0x14f7a9c23b8f9596),
        UINT64_C(0x0a5679aab66b4926), UINT64_C(0x073945ef6f8d25c6),
        UINT64_C(0xa547d99d30cc4908), UINT64_C(0x4da3e0d8a309a431),
        UINT64_C(0xd239414f8c188b48), UINT64_C(0xc55323140789ed64),
        UINT64_C(0xfd6099973bbf4f9d), UINT64_C(0xccf2de30be16af5b)};
    static const uint8_t exp_hash_a[64] = {
        0x8b, 0x11, 0x48, 0x2b, 0xab, 0xef, 0x8b, 0x15, 0x6b, 0xb4, 0xbb, 0x80, 0x2f, 0x1a, 0x6a, 0xeb,
        0xac, 0x4f, 0xbf, 0x1b, 0x70, 0x20, 0xee, 0x5d, 0xa2, 0xd0, 0x2e, 0x9a, 0xce, 0xfb, 0x8b, 0x85,
        0x92, 0xb8, 0x14, 0xcf, 0x4c, 0x81, 0xe7, 0x4d, 0x39, 0x04, 0x30, 0x36, 0x4e, 0x93, 0x6e, 0x93,
        0xea, 0x17, 0xfc, 0x4d, 0x0d, 0x8f, 0x3d, 0x6e, 0x7b, 0xbf, 0x3a, 0xed, 0x96, 0xe5, 0x02, 0x36};
    static const uint8_t exp_hash_b[64] = {
        0x24, 0xf9, 0x6e, 0x94, 0x3b, 0x96, 0xc6, 0xc8, 0x5b, 0xce, 0x17, 0xbd, 0xb4, 0x59, 0x87, 0x80,
        0x55, 0x3f, 0xb5, 0x2c, 0x60, 0xb1, 0xe7, 0x20, 0x3b, 0x83, 0x6d, 0xaf, 0xd2, 0x57, 0xcf, 0x7a,
        0x0a, 0x8d, 0x99, 0x55, 0x94, 0x0a, 0xf0, 0xd7, 0xd5, 0x02, 0x01, 0x2c, 0x63, 0xc0, 0xe6, 0xd6,
        0x86, 0x38, 0x66, 0xfc, 0xc0, 0x47, 0x9e, 0xb6, 0x32, 0xbd, 0xa8, 0xbc, 0xe7, 0x63, 0x52, 0x1d};

    uint64_t st[SPX_POSEIDON2_T];
    uint8_t in_a[64];
    uint8_t in_b[49];
    uint8_t out_a[64];
    uint8_t out_b[64];
    int verbose = spx_test_is_verbose(argc, argv);
    double t0 = spx_test_now_seconds();
    size_t i;

    for (i = 0; i < SPX_POSEIDON2_T; i++)
    {
        st[i] = (uint64_t)(i + 1);
    }
    poseidon2_permute(st);
    if (!check_u64_eq(st, exp_permute, SPX_POSEIDON2_T))
    {
        print_fail("permute_kat");
        return 1;
    }
    if (verbose) {
        printf("[kat] permute vector matched\n");
    }

    for (i = 0; i < sizeof(in_a); i++)
    {
        in_a[i] = (uint8_t)i;
    }
    for (i = 0; i < sizeof(in_b); i++)
    {
        in_b[i] = (uint8_t)(0xa0 + i);
    }

    poseidon2_hash_bytes_domain(out_a, sizeof(out_a),
                                SPX_P2_DOMAIN_HASH_MESSAGE,
                                in_a, sizeof(in_a));
    poseidon2_hash_bytes_domain(out_b, sizeof(out_b),
                                SPX_P2_DOMAIN_THASH_H,
                                in_b, sizeof(in_b));

    if (!check_u8_eq(out_a, exp_hash_a, sizeof(out_a)))
    {
        print_fail("hash_domain_kat_a");
        return 1;
    }
    if (!check_u8_eq(out_b, exp_hash_b, sizeof(out_b)))
    {
        print_fail("hash_domain_kat_b");
        return 1;
    }

    printf("poseidon2_kat test: OK | vectors=3 | elapsed=%.6f s\n",
           spx_test_now_seconds() - t0);
    if (verbose) {
        spx_test_print_hex_prefix("hash_vec_a", out_a, sizeof(out_a), 32);
        spx_test_print_hex_prefix("hash_vec_b", out_b, sizeof(out_b), 32);
    }
    return 0;
}
