#ifndef SPX_STARK_WITNESS_FORMAT_H
#define SPX_STARK_WITNESS_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#include "../hash_poseidon2_adapter.h"

typedef enum {
    SPX_P2_ROW_KIND_HEADER = 1,
    SPX_P2_ROW_KIND_INPUT_LANE = 2,
    SPX_P2_ROW_KIND_OUTPUT_LANE = 3
} spx_p2_row_kind_v1;

typedef enum {
    SPX_P2_LANE_ROLE_NONE = 0,
    SPX_P2_LANE_ROLE_INPUT = 1,
    SPX_P2_LANE_ROLE_OUTPUT = 2
} spx_p2_lane_role_v1;

typedef struct {
    uint8_t kind;
    uint8_t domain_tag;
    uint8_t lane_role;
    uint8_t reserved;
    uint32_t call_index;
    uint32_t lane_index;
    uint32_t real_len;
    uint32_t lane_count;
    uint32_t addr_words[8];
    uint64_t lane_value;
} spx_p2_witness_row_v1;

#define spx_p2_witness_count_rows_v1 SPX_NAMESPACE(spx_p2_witness_count_rows_v1)
int spx_p2_witness_count_rows_v1(const spx_p2_trace *trace, size_t *out_row_count);

#define spx_p2_witness_build_rows_v1 SPX_NAMESPACE(spx_p2_witness_build_rows_v1)
int spx_p2_witness_build_rows_v1(spx_p2_witness_row_v1 *out_rows,
                                 size_t max_rows, size_t *out_row_count,
                                 const spx_p2_trace *trace);

#endif
