#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../stark/witness_format.h"

static void fail(const char *name)
{
    printf("FAIL: %s\n", name);
}

int main(void)
{
    spx_p2_trace trace;
    spx_p2_witness_row_v1 rows_a[32];
    spx_p2_witness_row_v1 rows_b[32];
    size_t count_expected = 0;
    size_t count_a = 0;
    size_t count_b = 0;
    int rc;
    memset(&trace, 0, sizeof(trace));

    trace.call_count = 1;
    trace.calls[0].domain_tag = 0x12;
    trace.calls[0].input_real_len = 9;
    trace.calls[0].input_lane_count = 2;
    trace.calls[0].input_lane_offset = 0;
    trace.calls[0].output_real_len = 24;
    trace.calls[0].output_lane_count = 3;
    trace.calls[0].output_lane_offset = 2;
    trace.calls[0].addr_words[0] = 0x11223344u;

    trace.lane_count = 5;
    trace.lanes[0] = 0x0102030405060708ULL;
    trace.lanes[1] = 0x090a0b0c0d0e0f10ULL;
    trace.lanes[2] = 0x1112131415161718ULL;
    trace.lanes[3] = 0x2122232425262728ULL;
    trace.lanes[4] = 0x3132333435363738ULL;

    rc = spx_p2_witness_count_rows_v1(&trace, &count_expected);
    if (rc != 0 || count_expected != 6u) {
        fail("count_rows");
        return 1;
    }

    rc = spx_p2_witness_build_rows_v1(rows_a, 32, &count_a, &trace);
    if (rc != 0 || count_a != count_expected) {
        fail("build_rows");
        return 1;
    }
    rc = spx_p2_witness_build_rows_v1(rows_b, 32, &count_b, &trace);
    if (rc != 0 || count_b != count_expected) {
        fail("build_rows_repeat");
        return 1;
    }
    if (memcmp(rows_a, rows_b, sizeof(spx_p2_witness_row_v1) * count_expected) != 0) {
        fail("deterministic_rows");
        return 1;
    }
    if (rows_a[0].kind != SPX_P2_ROW_KIND_HEADER) {
        fail("header_kind");
        return 1;
    }
    if (rows_a[1].kind != SPX_P2_ROW_KIND_INPUT_LANE || rows_a[1].lane_value != trace.lanes[0]) {
        fail("input_row_0");
        return 1;
    }
    if (rows_a[2].kind != SPX_P2_ROW_KIND_INPUT_LANE || rows_a[2].lane_value != trace.lanes[1]) {
        fail("input_row_1");
        return 1;
    }
    if (rows_a[3].kind != SPX_P2_ROW_KIND_OUTPUT_LANE || rows_a[3].lane_value != trace.lanes[2]) {
        fail("output_row_0");
        return 1;
    }
    if (rows_a[5].kind != SPX_P2_ROW_KIND_OUTPUT_LANE || rows_a[5].lane_value != trace.lanes[4]) {
        fail("output_row_2");
        return 1;
    }

    printf("poseidon2_witness_v1 test: OK | rows=%llu\n", (unsigned long long)count_expected);
    return 0;
}
