# Legacy Interface Map

## Final Unversioned API
- `show/show_poseidon2.h`
  - `spx_p2_show_prove()`
  - `spx_p2_show_verify()`
  - `spx_p2_show_verify_compat()`
- `stark/ffi.h`
  - `spx_p2_ffi_generate_pi_f()`
  - `spx_p2_ffi_verify_pi_f()`
  - `spx_p2_ffi_verify_pi_f_compat()`
- `stark/pi_f_format.h`
  - `spx_p2_pi_f_encode()`
  - `spx_p2_pi_f_decode()`
- `stark/stats.h`
  - `spx_p2_stark_collect_stats()`

## Legacy Versioned API
- Show:
  - `spx_p2_show_prove_v2_strict()`
  - `spx_p2_show_verify_v2_strict()`
  - `spx_p2_show_prove_m10_skeleton_v1()`
  - `spx_p2_show_verify_m10_skeleton_v1()`
- FFI:
  - `spx_p2_ffi_generate_pi_f_v2_strict()`
  - `spx_p2_ffi_verify_pi_f_v2_strict()`
  - `spx_p2_ffi_generate_pi_f_v1()`
  - `spx_p2_ffi_verify_pi_f_v1()`
