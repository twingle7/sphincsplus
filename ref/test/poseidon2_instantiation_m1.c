#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../poseidon2.h"

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int main(void)
{
    uint8_t input[SPX_P2_ENCODED_THASH_BYTES(3)];
    uint8_t out_f[SPX_N];
    uint8_t out_h[SPX_N];
    uint8_t out_tl[SPX_N];
    uint8_t out_map[SPX_N];
    size_t i;
    unsigned long long checks = 0;

    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i + 1);
    }

    poseidon2_hash_thash_f(out_f, sizeof(out_f), input, SPX_P2_ENCODED_THASH_BYTES(1));
    poseidon2_hash_thash_by_inblocks(out_map, sizeof(out_map), input, SPX_P2_ENCODED_THASH_BYTES(1), 1);
    if (!bytes_equal(out_f, out_map, SPX_N)) {
        printf("FAIL: inblocks=1 should map to THASH_F\n");
        return 1;
    }
    checks++;

    poseidon2_hash_thash_h(out_h, sizeof(out_h), input, SPX_P2_ENCODED_THASH_BYTES(2));
    poseidon2_hash_thash_by_inblocks(out_map, sizeof(out_map), input, SPX_P2_ENCODED_THASH_BYTES(2), 2);
    if (!bytes_equal(out_h, out_map, SPX_N)) {
        printf("FAIL: inblocks=2 should map to THASH_H\n");
        return 1;
    }
    checks++;

    poseidon2_hash_thash_tl(out_tl, sizeof(out_tl), input, SPX_P2_ENCODED_THASH_BYTES(3));
    poseidon2_hash_thash_by_inblocks(out_map, sizeof(out_map), input, SPX_P2_ENCODED_THASH_BYTES(3), 3);
    if (!bytes_equal(out_tl, out_map, SPX_N)) {
        printf("FAIL: inblocks>=3 should map to THASH_TL\n");
        return 1;
    }
    checks++;

    if (bytes_equal(out_f, out_h, SPX_N) ||
        bytes_equal(out_h, out_tl, SPX_N) ||
        bytes_equal(out_f, out_tl, SPX_N)) {
        printf("FAIL: THASH domain separation broken\n");
        return 1;
    }
    checks++;

    printf("poseidon2_instantiation_m1 test: OK | checks=%llu\n", checks);
    return 0;
}
