#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../poseidon2.h"

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

int main(void)
{
    static const uint64_t exp_permute[SPX_POSEIDON2_T] = {
        UINT64_C(0xe4930b13f59b9a0e), UINT64_C(0xbf64a475d71decb5),
        UINT64_C(0x17bd221310c47173), UINT64_C(0x56781ad22c9c294d),
        UINT64_C(0xd8d945a4f6e9fff2), UINT64_C(0x22d5eb501de51927),
        UINT64_C(0x962a4ed2c0f495e1), UINT64_C(0xeaa3d841e4ec954b),
        UINT64_C(0xfeef316b435d285b), UINT64_C(0x8d0251e658bc13a4),
        UINT64_C(0xa99a6cd9aac315fc), UINT64_C(0xb4aba683cd4246d2)};
    static const uint8_t exp_hash_a[64] = {
        0xfe, 0x92, 0x15, 0xc9, 0xbb, 0x27, 0x9b, 0x50, 0x60, 0xaa, 0x84, 0x53, 0xa9, 0x90, 0xdf, 0x8c,
        0xa6, 0x63, 0xa4, 0x92, 0x08, 0x78, 0xf6, 0x27, 0x3d, 0x96, 0xab, 0xce, 0x8f, 0x59, 0x81, 0xe4,
        0x06, 0xdd, 0xec, 0x80, 0x21, 0x5b, 0x7a, 0x71, 0x56, 0xf0, 0x2b, 0xe8, 0x21, 0xc9, 0x52, 0x90,
        0x3f, 0x5e, 0xe7, 0x3f, 0xe9, 0x3a, 0xe4, 0x79, 0x4c, 0x59, 0x95, 0x18, 0xda, 0xb8, 0xc5, 0x8e};
    static const uint8_t exp_hash_b[64] = {
        0x94, 0x02, 0x8a, 0x6c, 0x1d, 0x34, 0xcc, 0x36, 0x46, 0x91, 0x70, 0x2c, 0x49, 0x90, 0xaf, 0xef,
        0xec, 0x46, 0x97, 0xca, 0x77, 0x26, 0x96, 0x71, 0x99, 0x09, 0x45, 0x46, 0x14, 0xf0, 0x6f, 0xb0,
        0xd3, 0x69, 0x26, 0x4b, 0x0a, 0x59, 0xd6, 0xcb, 0xe1, 0x48, 0x80, 0xb6, 0x76, 0xd0, 0x24, 0x30,
        0x45, 0x29, 0x79, 0xa2, 0x2c, 0xd3, 0x4f, 0x15, 0xaa, 0x6d, 0x12, 0x37, 0x32, 0xf9, 0x9a, 0xef};

    uint64_t st[SPX_POSEIDON2_T];
    uint8_t in_a[64];
    uint8_t in_b[49];
    uint8_t out_a[64];
    uint8_t out_b[64];
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

    printf("poseidon2_kat test: OK\n");
    return 0;
}
