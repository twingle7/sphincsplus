#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../api.h"
#include "../hash_poseidon2_adapter.h"
#include "../show/show_poseidon2.h"
#include "../stark/air_verify_full.h"
#include "../stark/witness_format.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

static int c_verify_full_guard_accept(const uint8_t *pk,
                                      const uint8_t *com,
                                      const uint8_t *sig)
{
    spx_p2_trace trace;
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    uint32_t constraints = 0;
    uint32_t violations = 0;
    int ok = 0;

    if (spx_p2_trace_verify_com(&trace, pk, com, sig) != 0)
    {
        return 0;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0 || row_count == 0)
    {
        return 0;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(*rows));
    if (rows == 0)
    {
        return 0;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
    {
        goto done;
    }
    if (spx_p2_verify_full_air_eval_constraints_v1(pk, com, sig, &trace, rows, row_count,
                                                    &constraints, &violations) != 0)
    {
        goto done;
    }
    ok = (violations == 0) ? 1 : 0;
done:
    free(rows);
    return ok;
}

int main(void)
{
    static spx_p2_cred_internal cred;
    static spx_p2_show show_obj;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t m[24];
    uint8_t r[16];
    uint8_t public_ctx[8] = {1, 3, 3, 7, 2, 9, 4, 6};
    size_t siglen = 0;
    int c_ok;
    int rs_ok;

    memset(&cred, 0, sizeof(cred));
    memset(&show_obj, 0, sizeof(show_obj));
    memset(m, 0x4a, sizeof(m));
    memset(r, 0xa4, sizeof(r));

    if (crypto_sign_keypair(pk, sk) != 0)
    {
        fail("keypair");
        return 1;
    }
    spx_p2_commit(cred.com, m, sizeof(m), r, sizeof(r));
    if (crypto_sign_signature(cred.sigma_com, &siglen, cred.com, SPX_N, sk) != 0 || siglen != SPX_BYTES)
    {
        fail("sign");
        return 1;
    }

    /* Case 1: valid sample => both accept. */
    c_ok = c_verify_full_guard_accept(pk, cred.com, cred.sigma_com);
    rs_ok = (spx_p2_show_prove(&show_obj, pk, &cred, public_ctx, sizeof(public_ctx)) == 0) ? 1 : 0;
    if (!(c_ok == 1 && rs_ok == 1))
    {
        fail("case_valid_mismatch");
        return 1;
    }

    /* Case 2: tampered signature => both reject. */
    cred.sigma_com[0] ^= 1u;
    c_ok = c_verify_full_guard_accept(pk, cred.com, cred.sigma_com);
    rs_ok = (spx_p2_show_prove(&show_obj, pk, &cred, public_ctx, sizeof(public_ctx)) == 0) ? 1 : 0;
    cred.sigma_com[0] ^= 1u;
    if (!(c_ok == 0 && rs_ok == 0))
    {
        fail("case_tamper_sig_mismatch");
        return 1;
    }

    /* Case 3: tampered commitment => both reject. */
    cred.com[0] ^= 1u;
    c_ok = c_verify_full_guard_accept(pk, cred.com, cred.sigma_com);
    rs_ok = (spx_p2_show_prove(&show_obj, pk, &cred, public_ctx, sizeof(public_ctx)) == 0) ? 1 : 0;
    cred.com[0] ^= 1u;
    if (!(c_ok == 0 && rs_ok == 0))
    {
        fail("case_tamper_com_mismatch");
        return 1;
    }

    printf("poseidon2_cross_backend_consistency test: OK\n");
    return 0;
}
