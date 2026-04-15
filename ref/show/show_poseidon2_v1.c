#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "show_poseidon2_v1.h"

int spx_p2_show_from_internal_v1(spx_p2_show_v1 *out,
                                 const spx_p2_cred_v1_internal *cred,
                                 const uint8_t *public_ctx, size_t public_ctx_len)
{
    if (out == 0 || cred == 0) {
        return -1;
    }
    if (public_ctx_len > SPX_P2_PUBLIC_CTX_MAX) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->com, cred->com, SPX_N);

    /*
     * M5 boundary freeze:
     * - pi_f is carried from private material placeholder
     * - real STARK proof object wiring is done in M10
     */
    memcpy(out->pi_f, cred->trace.lanes, (SPX_N <= sizeof(cred->trace.lanes)) ? SPX_N : sizeof(cred->trace.lanes));

    if (public_ctx_len > 0) {
        memcpy(out->public_ctx, public_ctx, public_ctx_len);
    }
    out->public_ctx_len = public_ctx_len;
    return 0;
}

int spx_p2_show_verify_shape_v1(const spx_p2_show_v1 *show)
{
    static const uint8_t zero[SPX_N] = {0};

    if (show == 0) {
        return -1;
    }
    if (show->public_ctx_len > SPX_P2_PUBLIC_CTX_MAX) {
        return -1;
    }
    if (memcmp(show->com, zero, SPX_N) == 0) {
        return -1;
    }
    if (memcmp(show->pi_f, zero, SPX_N) == 0) {
        return -1;
    }
    return 0;
}
