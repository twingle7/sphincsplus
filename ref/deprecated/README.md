# Deprecated Code

This directory stores legacy entrypoints that were superseded by the final
unversioned interfaces.

## Policy
- New code should include and call unversioned headers/APIs:
  - `show/show_poseidon2.h`
  - `stark/ffi.h`
  - `stark/pi_f_format.h`
  - `stark/stats.h`
- Legacy versioned entrypoints are kept for compatibility only.
- New tests and integration should use unversioned names.
