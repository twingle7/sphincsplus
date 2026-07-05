#ifndef SPX_STARK_SHOW_PROOF_FORMAT_H
#define SPX_STARK_SHOW_PROOF_FORMAT_H

#include "pi_f_format.h"

/*
 * Public proof-format naming used by the final show/prove/verify path.
 * Prefer this header in new code. The older `pi_f_*` names remain available
 * through `pi_f_format.h` for compatibility and low-level migration tests.
 */

typedef spx_p2_pi_f_view spx_p2_show_proof_view;

#define SPX_P2_SHOW_PROOF_MAGIC SPX_P2_PI_F_MAGIC
#define SPX_P2_SHOW_PROOF_VERSION SPX_P2_PI_F_VERSION
#define SPX_P2_SHOW_PROOF_FLAG_STARK SPX_P2_PI_F_FLAG_STARK_PROOF
#define SPX_P2_SHOW_PROOF_STATEMENT_VERSION SPX_P2_PI_F_STATEMENT_VERSION_VERIFY_FULL
#define SPX_P2_SHOW_PROOF_SYSTEM_ID_STARK SPX_P2_PI_F_PROOF_SYSTEM_ID_STARK
#define SPX_P2_SHOW_PROOF_FRAMEWORK_ID_FISCHLIN_STRICT SPX_P2_PI_F_FRAMEWORK_ID_FISCHLIN_STRICT
#define SPX_P2_SHOW_PROOF_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2 \
    SPX_P2_PI_F_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2
#define SPX_P2_SHOW_PROOF_FIXED_HEADER_BYTES SPX_P2_PI_F_FIXED_HEADER_BYTES
#define SPX_P2_SHOW_PROOF_RESERVED_BYTES SPX_P2_PI_F_RESERVED_BYTES
#define SPX_P2_SHOW_PROOF_MAX_BYTES_FOR_PROOF(proof_len) \
    SPX_P2_PI_F_MAX_BYTES_FOR_PROOF(proof_len)

#define spx_p2_show_proof_encoded_len spx_p2_pi_f_encoded_len
#define spx_p2_show_proof_encode spx_p2_pi_f_encode
#define spx_p2_show_proof_decode spx_p2_pi_f_decode

#endif
