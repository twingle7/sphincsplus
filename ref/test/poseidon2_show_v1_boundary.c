#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../show/show_poseidon2_v1.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    spx_p2_cred_v1_internal cred;
    spx_p2_show_v1 show;
    uint8_t public_ctx[4] = {0x01, 0x02, 0x03, 0x04};
    size_t i;

    memset(&cred, 0, sizeof(cred));
    for (i = 0; i < SPX_N; i++) {
        cred.com[i] = (uint8_t)(i + 1u);
    }
    cred.trace.lane_count = 4;
    cred.trace.lanes[0] = 0x1122334455667788ULL;

    if (spx_p2_show_from_internal_v1(&show, &cred, public_ctx, sizeof(public_ctx)) != 0) {
        fail("from_internal");
        return 1;
    }
    if (show.public_ctx_len != sizeof(public_ctx)) {
        fail("public_ctx_len");
        return 1;
    }
    if (spx_p2_show_verify_shape_v1(&show) != 0) {
        fail("verify_shape");
        return 1;
    }

    memset(show.pi_f, 0, sizeof(show.pi_f));
    if (spx_p2_show_verify_shape_v1(&show) == 0) {
        fail("shape_reject_zero_pi_f");
        return 1;
    }

    printf("poseidon2_show_v1_boundary test: OK\n");
    return 0;
}
