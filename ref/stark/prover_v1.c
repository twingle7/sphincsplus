#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../poseidon2.h"
#include "prover_v1.h"
#include "witness_format.h"

int spx_p2_prover_generate_pi_f_v1(uint8_t *out_pi_f, size_t *out_pi_f_len,
                                   size_t max_pi_f_len,
                                   const uint8_t *pk, const uint8_t *com,
                                   const uint8_t *sigma_com,
                                   const uint8_t *public_ctx,
                                   size_t public_ctx_len)
{
    spx_p2_trace trace;
    spx_p2_verify_full_proof_v1 proof;
    spx_p2_pi_f_v1_view view;
    uint8_t ctx_binding[SPX_N];
    spx_p2_witness_row_v1 *rows = 0;
    size_t row_count = 0;
    size_t need_len;

    if (out_pi_f == 0 || out_pi_f_len == 0 || pk == 0 || com == 0 || sigma_com == 0 ||
        (public_ctx_len > 0 && public_ctx == 0))
    {
        return -1;
    }

    if (spx_p2_trace_verify_com(&trace, pk, com, sigma_com) != 0)
    {
        return -1;
    }
    if (spx_p2_witness_count_rows_v1(&trace, &row_count) != 0)
    {
        return -1;
    }
    if (row_count > SPX_P2_TRACE_MAX_LANES)
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
    if (spx_p2_verify_full_air_prove_v1(&proof, pk, com, sigma_com, &trace, rows, row_count) != 0)
    {
        free(rows);
        return -1;
    }
    free(rows);

    poseidon2_hash_bytes_domain(ctx_binding, SPX_N, SPX_P2_DOMAIN_CUSTOM,
                                public_ctx, public_ctx_len);

    need_len = spx_p2_pi_f_v1_encoded_len(SPX_BYTES);
    if (need_len > max_pi_f_len)
    {
        return -1;
    }
    memset(&view, 0, sizeof(view));
    view.flags = SPX_P2_PI_F_V1_FLAG_NONZK_SKELETON;
    view.proof_system_id = SPX_P2_PI_F_V1_PROOF_SYSTEM_ID_SKELETON;
    memcpy(view.ctx_binding, ctx_binding, SPX_N);
    view.sigma_com = sigma_com;
    view.sigma_len = SPX_BYTES;
    memcpy(view.commitment, proof.commitment, SPX_N);
    view.constraint_count = proof.constraint_count;
    view.violation_count = proof.violation_count;
    return spx_p2_pi_f_v1_encode(out_pi_f, out_pi_f_len, max_pi_f_len, &view);
}
