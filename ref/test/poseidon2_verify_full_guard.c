#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/air_verify_full.h"
#include "../stark/witness_format.h"

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
    size_t siglen = 0;
    spx_p2_trace trace;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    uint32_t constraints = 0;
    uint32_t violations = 0;

    memset(m, 0x42, sizeof(m));
    memset(r, 0x24, sizeof(r));
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
    if (spx_p2_trace_verify_com(&trace, pk, com, sig) != 0)
    {
        fail("trace_verify_com");
        return 1;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0 || row_count == 0)
    {
        fail("count_rows");
        return 1;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(*rows));
    if (rows == 0)
    {
        fail("alloc_rows");
        return 1;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
    {
        fail("build_rows");
        free(rows);
        return 1;
    }
    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sig, &trace, rows, row_count,
                                                    &constraints, &violations) != 0)
    {
        fail("eval_constraints");
        free(rows);
        return 1;
    }
    if (violations != 0)
    {
        fail("valid_trace_should_have_zero_violations");
        free(rows);
        return 1;
    }

    /* Tamper domain tag to trigger module-constraint violation. */
    if (trace.call_count == 0)
    {
        fail("trace_empty");
        free(rows);
        return 1;
    }
    trace.calls[0].domain_tag = 0xffu;
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
    {
        fail("rebuild_rows_after_tamper");
        free(rows);
        return 1;
    }
    constraints = 0;
    violations = 0;
    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sig, &trace, rows, row_count,
                                                    &constraints, &violations) != 0)
    {
        fail("eval_constraints_tamper");
        free(rows);
        return 1;
    }
    if (violations == 0)
    {
        fail("tamper_should_create_violations");
        free(rows);
        return 1;
    }

    free(rows);
    printf("poseidon2_verify_full_guard test: OK | constraints=%u violations=%u\n",
           constraints, violations);
    return 0;
}
