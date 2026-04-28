#include <stdint.h>

#include "../randombytes.h"

static uint64_t g_state = 0x9e3779b97f4a7c15ULL;

void randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned long long i;

    for (i = 0; i < xlen; i++) {
        g_state ^= g_state >> 12;
        g_state ^= g_state << 25;
        g_state ^= g_state >> 27;
        g_state *= 2685821657736338717ULL;
        x[i] = (unsigned char)(g_state >> 56);
    }
}
