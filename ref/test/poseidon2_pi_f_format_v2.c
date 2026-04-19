#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../stark/pi_f_format_v2.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    uint8_t encoded[SPX_P2_PI_F_V2_MAX_BYTES_FOR_PROOF(64)];
    uint8_t proof_blob[64];
    spx_p2_pi_f_v2_view in_view;
    spx_p2_pi_f_v2_view out_view;
    size_t encoded_len = 0;
    uint32_t i;

    memset(&in_view, 0, sizeof(in_view));
    for (i = 0; i < 64u; i++)
    {
        proof_blob[i] = (uint8_t)(i + 1u);
    }
    for (i = 0; i < SPX_N; i++)
    {
        in_view.public_input_digest[i] = (uint8_t)(0x10u + i);
        in_view.ctx_binding[i] = (uint8_t)(0x40u + i);
        in_view.commitment[i] = (uint8_t)(0x80u + i);
    }
    in_view.flags = SPX_P2_PI_F_V2_FLAG_STARK_PROOF;
    in_view.proof_system_id = SPX_P2_PI_F_V2_PROOF_SYSTEM_ID_STARK;
    in_view.statement_version = SPX_P2_PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1;
    in_view.proof_bytes = proof_blob;
    in_view.proof_len = (uint32_t)sizeof(proof_blob);

    if (spx_p2_pi_f_v2_encode(encoded, &encoded_len, sizeof(encoded), &in_view) != 0)
    {
        fail("encode");
        return 1;
    }
    if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) != 0)
    {
        fail("decode");
        return 1;
    }
    if (out_view.flags != in_view.flags ||
        out_view.proof_system_id != in_view.proof_system_id ||
        out_view.statement_version != in_view.statement_version ||
        out_view.proof_len != in_view.proof_len)
    {
        fail("roundtrip_meta");
        return 1;
    }
    if (memcmp(out_view.public_input_digest, in_view.public_input_digest, SPX_N) != 0 ||
        memcmp(out_view.ctx_binding, in_view.ctx_binding, SPX_N) != 0 ||
        memcmp(out_view.commitment, in_view.commitment, SPX_N) != 0 ||
        memcmp(out_view.proof_bytes, in_view.proof_bytes, in_view.proof_len) != 0)
    {
        fail("roundtrip_payload");
        return 1;
    }

    encoded[0] ^= 1u;
    if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) == 0)
    {
        fail("tamper_magic");
        return 1;
    }
    encoded[0] ^= 1u;

    encoded[12] ^= 1u;
    if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) == 0)
    {
        fail("tamper_header_len");
        return 1;
    }
    encoded[12] ^= 1u;

    encoded[16] ^= 1u;
    if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) == 0)
    {
        fail("tamper_total_len");
        return 1;
    }
    encoded[16] ^= 1u;

    /* proof_len field starts after fixed header and 3 * SPX_N payload bytes. */
    {
        size_t proof_len_off = SPX_P2_PI_F_V2_FIXED_HEADER_BYTES + (size_t)SPX_N * 3u;
        encoded[proof_len_off] ^= 1u;
        if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) == 0)
        {
            fail("tamper_proof_len");
            return 1;
        }
        encoded[proof_len_off] ^= 1u;
    }

    encoded[encoded_len - 1] ^= 1u;
    if (spx_p2_pi_f_v2_decode(&out_view, encoded, encoded_len) == 0)
    {
        fail("tamper_reserved");
        return 1;
    }
    encoded[encoded_len - 1] ^= 1u;

    printf("poseidon2_pi_f_format_v2 test: OK | len=%llu\n",
           (unsigned long long)encoded_len);
    return 0;
}
