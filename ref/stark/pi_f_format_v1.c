#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pi_f_format_v1.h"

static void store_u32_le(uint8_t out[4], uint32_t x)
{
    out[0] = (uint8_t)(x & 0xffu);
    out[1] = (uint8_t)((x >> 8) & 0xffu);
    out[2] = (uint8_t)((x >> 16) & 0xffu);
    out[3] = (uint8_t)((x >> 24) & 0xffu);
}

static uint32_t load_u32_le(const uint8_t in[4])
{
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

size_t spx_p2_pi_f_v1_encoded_len(uint32_t sigma_len)
{
    return SPX_P2_PI_F_V1_FIXED_HEADER_BYTES +
           SPX_N +
           sigma_len +
           SPX_N +
           4u + 4u +
           SPX_P2_PI_F_V1_RESERVED_BYTES;
}

int spx_p2_pi_f_v1_encode(uint8_t *out, size_t *out_len, size_t max_out_len,
                          const spx_p2_pi_f_v1_view *view)
{
    size_t need;
    size_t off = 0;
    if (out == 0 || out_len == 0 || view == 0 || view->sigma_com == 0)
    {
        return -1;
    }
    need = spx_p2_pi_f_v1_encoded_len(view->sigma_len);
    if (need > max_out_len)
    {
        return -1;
    }

    store_u32_le(out + off, SPX_P2_PI_F_V1_MAGIC);
    off += 4u;
    store_u32_le(out + off, SPX_P2_PI_F_V1_VERSION);
    off += 4u;
    store_u32_le(out + off, view->flags);
    off += 4u;
    store_u32_le(out + off, SPX_P2_PI_F_V1_FIXED_HEADER_BYTES);
    off += 4u;
    store_u32_le(out + off, (uint32_t)need);
    off += 4u;
    store_u32_le(out + off, view->proof_system_id);
    off += 4u;

    memcpy(out + off, view->ctx_binding, SPX_N);
    off += SPX_N;
    memcpy(out + off, view->sigma_com, view->sigma_len);
    off += view->sigma_len;
    memcpy(out + off, view->commitment, SPX_N);
    off += SPX_N;
    store_u32_le(out + off, view->constraint_count);
    off += 4u;
    store_u32_le(out + off, view->violation_count);
    off += 4u;
    memset(out + off, 0, SPX_P2_PI_F_V1_RESERVED_BYTES);
    off += SPX_P2_PI_F_V1_RESERVED_BYTES;

    *out_len = off;
    return 0;
}

int spx_p2_pi_f_v1_decode(spx_p2_pi_f_v1_view *out_view,
                          const uint8_t *in, size_t in_len)
{
    uint32_t magic;
    uint32_t version;
    uint32_t header_len;
    uint32_t total_len;
    size_t off = 0;
    if (out_view == 0 || in == 0)
    {
        return -1;
    }
    if (in_len < SPX_P2_PI_F_V1_FIXED_HEADER_BYTES + SPX_N + SPX_N + 4u + 4u + SPX_P2_PI_F_V1_RESERVED_BYTES)
    {
        return -1;
    }

    magic = load_u32_le(in + off);
    off += 4u;
    version = load_u32_le(in + off);
    off += 4u;
    out_view->flags = load_u32_le(in + off);
    off += 4u;
    header_len = load_u32_le(in + off);
    off += 4u;
    total_len = load_u32_le(in + off);
    off += 4u;
    out_view->proof_system_id = load_u32_le(in + off);
    off += 4u;

    if (magic != SPX_P2_PI_F_V1_MAGIC || version != SPX_P2_PI_F_V1_VERSION)
    {
        return -1;
    }
    if (header_len != SPX_P2_PI_F_V1_FIXED_HEADER_BYTES)
    {
        return -1;
    }
    if (total_len != (uint32_t)in_len)
    {
        return -1;
    }
    if (in_len < spx_p2_pi_f_v1_encoded_len(SPX_BYTES))
    {
        return -1;
    }

    memcpy(out_view->ctx_binding, in + off, SPX_N);
    off += SPX_N;
    out_view->sigma_com = in + off;
    out_view->sigma_len = SPX_BYTES;
    off += SPX_BYTES;
    memcpy(out_view->commitment, in + off, SPX_N);
    off += SPX_N;
    out_view->constraint_count = load_u32_le(in + off);
    off += 4u;
    out_view->violation_count = load_u32_le(in + off);
    off += 4u;
    if (in_len - off != SPX_P2_PI_F_V1_RESERVED_BYTES)
    {
        return -1;
    }
    {
        size_t i;
        for (i = 0; i < SPX_P2_PI_F_V1_RESERVED_BYTES; i++)
        {
            if (in[off + i] != 0u)
            {
                return -1;
            }
        }
    }
    return 0;
}
