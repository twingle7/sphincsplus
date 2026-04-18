#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../hash_poseidon2_adapter.h"
#include "../poseidon2.h"
#include "air_verify_full.h"
#include "pi_f_format_v1.h"
#include "verifier_v1.h"
#include "witness_format.h"

int spx_p2_verifier_verify_pi_f_v1(const uint8_t *pk, const uint8_t *com,
                                   const uint8_t *pi_f, size_t pi_f_len,
                                   const uint8_t *public_ctx, size_t public_ctx_len)
{
    spx_p2_pi_f_v1_view view;
    uint8_t expected_ctx_binding[SPX_N];
    spx_p2_trace trace;
    spx_p2_witness_row_v1 *rows = 0;
    spx_p2_verify_full_proof_v1 proof;
    size_t row_count = 0;

    if (pk == 0 || com == 0 || pi_f == 0 || (public_ctx_len > 0 && public_ctx == 0))
    {
        return -1;
    }
    if (spx_p2_pi_f_v1_decode(&view, pi_f, pi_f_len) != 0)
    {
        return -1;
    }
    if ((view.flags & SPX_P2_PI_F_V1_FLAG_NONZK_SKELETON) == 0u)
    {
        return -1;
    }
    poseidon2_hash_bytes_domain(expected_ctx_binding, SPX_N, SPX_P2_DOMAIN_CUSTOM,
                                public_ctx, public_ctx_len);
    if (memcmp(view.ctx_binding, expected_ctx_binding, SPX_N) != 0)
    {
        return -1;
    }
    if (view.sigma_len != SPX_BYTES)
    {
        return -1;
    }
    if (spx_p2_trace_verify_com(&trace, pk, com, view.sigma_com) != 0)
    {
        return -1;
    }
    memcpy(proof.commitment, view.commitment, SPX_N);
    proof.constraint_count = view.constraint_count;
    proof.violation_count = view.violation_count;

    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0)
    {
        return -1;
    }
    rows = (spx_p2_witness_row_v1 *)malloc(row_count * sizeof(spx_p2_witness_row_v1));
    if (rows == 0)
    {
        return -1;
    }
    if (spx_p2_witness_build_rows_v1(rows, row_count, &row_count, &trace) != 0)
    {
        free(rows);
        return -1;
    }
    if (spx_p2_verify_full_air_verify_v1(&proof, pk, com, view.sigma_com, &trace, rows, row_count) != 0)
    {
        free(rows);
        return -1;
    }
    free(rows);
    return 0;
}
