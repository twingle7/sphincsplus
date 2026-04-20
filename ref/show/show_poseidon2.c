#include "show_poseidon2.h"

int spx_p2_show_prove(spx_p2_show *out,
                      const uint8_t *pk,
                      const spx_p2_cred_internal *cred,
                      const uint8_t *public_ctx,
                      size_t public_ctx_len)
{
    return spx_p2_show_prove_v2_strict(out, pk, cred, public_ctx, public_ctx_len);
}

int spx_p2_show_verify(const spx_p2_show *show,
                       const uint8_t *pk)
{
    return spx_p2_show_verify_v2_strict(show, pk);
}

int spx_p2_show_verify_compat(const spx_p2_show *show,
                              const uint8_t *pk)
{
    return spx_p2_show_verify_m10_skeleton_v1(show, pk);
}
