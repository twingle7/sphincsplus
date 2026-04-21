#!/usr/bin/env bash
set -euo pipefail

PARAMS="${PARAMS:-sphincs-poseidon2-192s}"
THASH="${THASH:-simple}"
CC_BIN="${CC_BIN:-gcc}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT_DIR/logs/benchmark-stark-v2-local.md"
cd "$ROOT_DIR"

echo "[bench] build rust backend"
(cd stark-rs && cargo build --release)

echo "[bench] build stats test"
make PARAMS="$PARAMS" THASH="$THASH" CC="$CC_BIN" EXTRA_CFLAGS="-DSPX_P2_USE_RUST_STARK" test/poseidon2_stark_stats

echo "[bench] run stats test"
STATS_LINE="$(./test/poseidon2_stark_stats | tail -n 1)"
echo "$STATS_LINE"

CALLS="$(echo "$STATS_LINE" | sed -n 's/.*calls=\([0-9]\+\).*/\1/p')"
LANES="$(echo "$STATS_LINE" | sed -n 's/.*lanes=\([0-9]\+\).*/\1/p')"
ROWS="$(echo "$STATS_LINE" | sed -n 's/.*rows=\([0-9]\+\).*/\1/p')"
PROOF="$(echo "$STATS_LINE" | sed -n 's/.*proof=\([0-9]\+\).*/\1/p')"
MAGIC="$(echo "$STATS_LINE" | sed -n 's/.*magic=\(0x[0-9a-fA-F]\+\).*/\1/p')"
VER="$(echo "$STATS_LINE" | sed -n 's/.*ver=\([0-9]\+\).*/\1/p')"
PROVE_MS="$(echo "$STATS_LINE" | sed -n 's/.*prove_ms=\([0-9.]\+\).*/\1/p')"
VERIFY_MS="$(echo "$STATS_LINE" | sed -n 's/.*verify_ms=\([0-9.]\+\).*/\1/p')"
DATE_STR="$(date +%F)"

cat > "$OUT_FILE" <<EOF
# benchmark-stark-v2 local result

| date | params | backend | trace_calls | trace_lanes | witness_rows | proof_bytes | proof_magic | proof_version | prove_ms | verify_ms |
|---|---|---|---:|---:|---:|---:|---|---:|---:|---:|
| $DATE_STR | $PARAMS | Rust-stark | $CALLS | $LANES | $ROWS | $PROOF | $MAGIC | $VER | $PROVE_MS | $VERIFY_MS |
EOF

echo "[bench] wrote $OUT_FILE"
