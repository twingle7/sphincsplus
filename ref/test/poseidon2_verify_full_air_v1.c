#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/air_verify_full.h"

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
    size_t siglen = 0;
    spx_p2_trace trace;
    spx_p2_trace trace_tampered;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    spx_p2_verify_full_proof_v1 proof;
    uint32_t constraints = 0, violations = 0;

    memset(m, 0x5a, sizeof(m));
    memset(r, 0xa5, sizeof(r));

    if (crypto_sign_keypair(pk, sk) != 0) {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(sig, &siglen, com, SPX_N, sk) != 0 || siglen != SPX_BYTES) {
        fail("sign");
        return 1;
    }
    if (spx_p2_trace_verify_com(&trace, pk, com, sig) != 0) {
        fail("trace_verify");
        return 1;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0 || row_count == 0) {
        fail("count_rows");
        return 1;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(spx_p2_witness_row_v1));
    if (rows == 0) {
        fail("malloc_rows");
        return 1;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0) {
        fail("build_rows");
        free(rows);
        return 1;
    }

    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sig, &trace, rows, row_count,
                                                    &constraints, &violations) != 0) {
        fail("eval");
        free(rows);
        return 1;
    }
    if (violations != 0) {
        fail("violations_nonzero");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_prove_v1(&proof, pk, com, sig, &trace, rows, row_count) != 0) {
        fail("prove");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) != 0) {
        fail("verify");
        free(rows);
        return 1;
    }

    sig[0] ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) == 0) {
        fail("tamper_sigma");
        free(rows);
        return 1;
    }
    sig[0] ^= 1u;

    rows[1].lane_value ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace, rows, row_count) == 0) {
        fail("tamper_rows");
        free(rows);
        return 1;
    }
    rows[1].lane_value ^= 1u;

    memcpy(&trace_tampered, &trace, sizeof(trace_tampered));
    trace_tampered.calls[0].domain_tag ^= 1u;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace_tampered, rows, row_count) == 0) {
        fail("tamper_trace");
        free(rows);
        return 1;
    }

    trace_tampered = trace;
    trace_tampered.dropped_calls = 1;
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, sig, &trace_tampered, rows, row_count) == 0) {
        fail("tamper_drop_meta");
        free(rows);
        return 1;
    }

    printf("poseidon2_verify_full_air_v1 test: OK | constraints=%u rows=%llu calls=%u\n",
           constraints, (unsigned long long)row_count, trace.call_count);
    free(rows);
    return 0;
}
