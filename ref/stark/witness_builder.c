#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "witness_format.h"

static int validate_call_lane_ranges(const spx_p2_trace *trace,
                                     const spx_p2_hash_call *call)
{
    uint64_t in_end = (uint64_t)call->input_lane_offset + (uint64_t)call->input_lane_count;
    uint64_t out_end = (uint64_t)call->output_lane_offset + (uint64_t)call->output_lane_count;
    if (in_end > trace->lane_count) {
        return -1;
    }
    if (out_end > trace->lane_count) {
        return -1;
    }
    return 0;
}

int spx_p2_witness_count_rows_v1(const spx_p2_trace *trace, size_t *out_row_count)
{
    size_t i;
    size_t rows = 0;
    if (trace == 0 || out_row_count == 0) {
        return -1;
    }
    for (i = 0; i < trace->call_count; i++) {
        const spx_p2_hash_call *call = &trace->calls[i];
        if (validate_call_lane_ranges(trace, call) != 0) {
            return -1;
        }
        rows += 1u + (size_t)call->input_lane_count + (size_t)call->output_lane_count;
    }
    *out_row_count = rows;
    return 0;
}

int spx_p2_witness_build_rows_v1(spx_p2_witness_row_v1 *out_rows,
                                 size_t max_rows, size_t *out_row_count,
                                 const spx_p2_trace *trace)
{
    size_t i;
    size_t row = 0;
    size_t expected = 0;

    if (out_rows == 0 || out_row_count == 0 || trace == 0) {
        return -1;
    }
    if (spx_p2_witness_count_rows_v1(trace, &expected) != 0) {
        return -1;
    }
    if (expected > max_rows) {
        return -2;
    }

    for (i = 0; i < trace->call_count; i++) {
        size_t j;
        const spx_p2_hash_call *call = &trace->calls[i];
        spx_p2_witness_row_v1 *r = &out_rows[row++];

        memset(r, 0, sizeof(*r));
        r->kind = (uint8_t)SPX_P2_ROW_KIND_HEADER;
        r->domain_tag = call->domain_tag;
        r->lane_role = (uint8_t)SPX_P2_LANE_ROLE_NONE;
        r->call_index = (uint32_t)i;
        r->real_len = call->input_real_len;
        r->lane_count = call->input_lane_count;
        memcpy(r->addr_words, call->addr_words, sizeof(r->addr_words));

        for (j = 0; j < call->input_lane_count; j++) {
            spx_p2_witness_row_v1 *ri = &out_rows[row++];
            memset(ri, 0, sizeof(*ri));
            ri->kind = (uint8_t)SPX_P2_ROW_KIND_INPUT_LANE;
            ri->domain_tag = call->domain_tag;
            ri->lane_role = (uint8_t)SPX_P2_LANE_ROLE_INPUT;
            ri->call_index = (uint32_t)i;
            ri->lane_index = (uint32_t)j;
            ri->real_len = call->input_real_len;
            ri->lane_count = call->input_lane_count;
            memcpy(ri->addr_words, call->addr_words, sizeof(ri->addr_words));
            ri->lane_value = trace->lanes[call->input_lane_offset + j];
        }

        for (j = 0; j < call->output_lane_count; j++) {
            spx_p2_witness_row_v1 *ro = &out_rows[row++];
            memset(ro, 0, sizeof(*ro));
            ro->kind = (uint8_t)SPX_P2_ROW_KIND_OUTPUT_LANE;
            ro->domain_tag = call->domain_tag;
            ro->lane_role = (uint8_t)SPX_P2_LANE_ROLE_OUTPUT;
            ro->call_index = (uint32_t)i;
            ro->lane_index = (uint32_t)j;
            ro->real_len = call->output_real_len;
            ro->lane_count = call->output_lane_count;
            memcpy(ro->addr_words, call->addr_words, sizeof(ro->addr_words));
            ro->lane_value = trace->lanes[call->output_lane_offset + j];
        }
    }

    *out_row_count = row;
    return 0;
}
