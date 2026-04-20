#include "pi_f_format.h"

size_t spx_p2_pi_f_encoded_len(uint32_t proof_len)
{
    return spx_p2_pi_f_v2_encoded_len(proof_len);
}

int spx_p2_pi_f_encode(uint8_t *out, size_t *out_len, size_t max_out_len,
                       const spx_p2_pi_f_view *view)
{
    return spx_p2_pi_f_v2_encode(out, out_len, max_out_len, view);
}

int spx_p2_pi_f_decode(spx_p2_pi_f_view *out_view,
                       const uint8_t *in, size_t in_len)
{
    return spx_p2_pi_f_v2_decode(out_view, in, in_len);
}
