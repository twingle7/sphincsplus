#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../poseidon2.h"
#include "../hash_poseidon2_adapter.h"
#include "../stark/air_hashcall.h"
#include "../stark/witness_format.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    spx_p2_trace trace;
    spx_p2_witness_row_v1 rows[32];
    spx_p2_hashcall_proof_v1 proof;
    spx_p2_witness_row_v1 tampered[32];
    size_t row_count = 0;
    uint32_t constraints = 0, violations = 0;

    memset(&trace, 0, sizeof(trace));
    trace.call_count = 1;
    trace.calls[0].domain_tag = SPX_P2_DOMAIN_THASH_H;
    trace.calls[0].input_real_len = 9;
    trace.calls[0].input_lane_count = 2;
    trace.calls[0].input_lane_offset = 0;
    trace.calls[0].output_real_len = 24;
    trace.calls[0].output_lane_count = 3;
    trace.calls[0].output_lane_offset = 2;
    trace.lane_count = 5;
    trace.lanes[0] = 0x11ULL;
    trace.lanes[1] = 0x22ULL;
    trace.lanes[2] = 0x33ULL;
    trace.lanes[3] = 0x44ULL;
    trace.lanes[4] = 0x55ULL;

    if (spx_p2_witness_build_rows_v1(rows, 32, &row_count, &trace) != 0)
    {
        fail("build_rows");
        return 1;
    }
    if (spx_p2_hashcall_air_eval_constraints_v1(&trace, rows, row_count, &constraints, &violations) != 0)
    {
        fail("eval");
        return 1;
    }
    if (violations != 0)
    {
        fail("violations_nonzero");
        return 1;
    }
    if (spx_p2_hashcall_air_prove_v1(&proof, &trace, rows, row_count) != 0)
    {
        fail("prove");
        return 1;
    }
    if (spx_p2_hashcall_air_verify_v1(&proof, &trace, rows, row_count) != 0)
    {
        fail("verify");
        return 1;
    }

    memcpy(tampered, rows, sizeof(rows));
    tampered[1].lane_value ^= 1u;
    if (spx_p2_hashcall_air_verify_v1(&proof, &trace, tampered, row_count) == 0)
    {
        fail("tamper_rows");
        return 1;
    }

    printf("poseidon2_hashcall_air_v1 test: OK | constraints=%u rows=%llu\n",
           constraints, (unsigned long long)row_count);
    return 0;
}
