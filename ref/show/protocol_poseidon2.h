#ifndef SPX_SHOW_PROTOCOL_POSEIDON2_H
#define SPX_SHOW_PROTOCOL_POSEIDON2_H

#include "protocol_poseidon2_v1.h"

/*
 * Public protocol entrypoints.
 * Prefer this header in new code; the `_v1` header is kept only to preserve
 * the historical ABI and older phase-specific tests.
 */

typedef spx_p2_flow_status_v1 spx_p2_flow_status;

#define spx_p2_flow_status_to_string spx_p2_flow_status_to_string_v1
#define spx_p2_protocol_has_rust_backend spx_p2_protocol_has_rust_backend_v1
#define spx_p2_protocol_backend_mode spx_p2_protocol_backend_mode_v1

#define spx_p2_issue_request spx_p2_issue_request_v1
#define spx_p2_issue_sign spx_p2_issue_sign_v1
#define spx_p2_unblind spx_p2_unblind_v1
#define spx_p2_issue_unblind spx_p2_issue_unblind_v1

#define spx_p2_protocol_show spx_p2_protocol_show_v1
#define spx_p2_protocol_show_strict_public spx_p2_protocol_show_strict_public_v1
#define spx_p2_protocol_show_m20 spx_p2_protocol_show_m20_v1
#define spx_p2_protocol_verify spx_p2_protocol_verify_v1
#define spx_p2_protocol_verify_strict_public spx_p2_protocol_verify_strict_public_v1
#define spx_p2_protocol_verify_m20 spx_p2_protocol_verify_m20_v1

#endif
