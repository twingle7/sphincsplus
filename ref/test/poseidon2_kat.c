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
        UINT64_C(0xcbd9a89604cbe234), UINT64_C(0x55e7d1ee1a2dade0),
        UINT64_C(0xd98cc473a1f6b04a), UINT64_C(0x2ec1a9e563b0c599),
        UINT64_C(0xc174781fe637eadc), UINT64_C(0xc2b8a224fac22656),
        UINT64_C(0x4eff82b9d7a6238e), UINT64_C(0x349e153eb9909841),
        UINT64_C(0x1bf9dc9574cfc373), UINT64_C(0x70067de9c6615425),
        UINT64_C(0x9a2920773cb46ece), UINT64_C(0x719671c1575177d7)
    };
    static const uint8_t exp_hash_a[64] = {
        0xb4,0x75,0x08,0x2d,0xa0,0x69,0x3c,0x65,0x7c,0x7b,0x5c,0x3a,0x18,0x08,0x9a,0x1f,
        0x2e,0x99,0x63,0xbf,0x4b,0x99,0xd3,0x74,0xc6,0xfa,0x5a,0xb9,0xe1,0x71,0x70,0x78,
        0x44,0x3c,0x90,0x16,0x00,0xef,0xdb,0x15,0x56,0x4a,0xe5,0xee,0xb4,0x68,0xe5,0xc2,
        0x06,0xb2,0x61,0x5a,0xf9,0x48,0x24,0x72,0x1b,0x37,0xc1,0xc8,0x4b,0xf6,0x1e,0xa3
    };
    static const uint8_t exp_hash_b[64] = {
        0x43,0xcd,0x87,0xed,0xb0,0xd9,0x6f,0x3c,0x0e,0xe5,0xa6,0x1e,0x68,0x53,0x14,0x68,
        0x2a,0xa1,0x33,0xc4,0x59,0x34,0xf3,0x4d,0x68,0x37,0x9d,0x5d,0x2f,0x7a,0x22,0xe4,
        0xd2,0x96,0x99,0x9d,0x0b,0x2a,0x37,0x46,0xd9,0x5f,0xc6,0x1d,0x94,0x85,0xbf,0x9e,
        0x1a,0x85,0x8b,0x70,0x3e,0x8d,0xf8,0x3d,0x4f,0x42,0x31,0x5a,0xce,0x04,0x3c,0x8e
    };

    uint64_t st[SPX_POSEIDON2_T];
    uint8_t in_a[64];
    uint8_t in_b[49];
    uint8_t out_a[64];
    uint8_t out_b[64];
    size_t i;

    for (i = 0; i < SPX_POSEIDON2_T; i++) {
        st[i] = (uint64_t)(i + 1);
    }
    poseidon2_permute(st);
    if (!check_u64_eq(st, exp_permute, SPX_POSEIDON2_T)) {
        print_fail("permute_kat");
        return 1;
    }

    for (i = 0; i < sizeof(in_a); i++) {
        in_a[i] = (uint8_t)i;
    }
    for (i = 0; i < sizeof(in_b); i++) {
        in_b[i] = (uint8_t)(0xa0 + i);
    }

    poseidon2_hash_bytes_domain(out_a, sizeof(out_a),
                                SPX_P2_DOMAIN_HASH_MESSAGE,
                                in_a, sizeof(in_a));
    poseidon2_hash_bytes_domain(out_b, sizeof(out_b),
                                SPX_P2_DOMAIN_THASH_H,
                                in_b, sizeof(in_b));

    if (!check_u8_eq(out_a, exp_hash_a, sizeof(out_a))) {
        print_fail("hash_domain_kat_a");
        return 1;
    }
    if (!check_u8_eq(out_b, exp_hash_b, sizeof(out_b))) {
        print_fail("hash_domain_kat_b");
        return 1;
    }

    printf("poseidon2_kat test: OK\n");
    return 0;
}
