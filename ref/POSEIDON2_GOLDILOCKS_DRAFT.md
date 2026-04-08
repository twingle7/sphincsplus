# Poseidon2 Draft Profile (Goldilocks + Sponge-First)

## Scope

This document defines a draft interface and parameter profile for replacing the
placeholder backend in `ref/poseidon2.c` with a real Poseidon2 implementation.
It is intentionally conservative and engineering-oriented:

- keep SPHINCS+ call sites stable;
- use a single sponge model first;
- defer compression-mode optimization until after correctness is validated.

## Intended Use In This Repository

- `prf_addr` uses domain `SPX_P2_DOMAIN_PRF_ADDR`.
- `gen_message_random` uses domain `SPX_P2_DOMAIN_GEN_MESSAGE_RANDOM`.
- `hash_message` uses domain `SPX_P2_DOMAIN_HASH_MESSAGE`.
- `thash` (simple) uses domain `SPX_P2_DOMAIN_THASH_SIMPLE`.

Additional `THASH_F/H/TL` domain IDs are reserved in the API for later
fine-grained separation if we choose to split by semantic role.

## Draft Field Choice

Primary target field: Goldilocks prime field

- prime: `p = 2^64 - 2^32 + 1`
- element representation: one `uint64_t` in canonical range `[0, p-1]`
- rationale:
  - good software performance on 64-bit CPUs;
  - good fit for STARK-friendly arithmetization and low-overhead field ops;
  - broad adoption in modern STARK systems.

## Draft Sponge Profile

The current draft API in `poseidon2.h` uses:

- `t = 12` words
- `capacity = 6` words
- `rate = 6` words = `48` bytes

Reasoning:

- `SPX_N = 24` for the current `192s` set, and this profile leaves a safety
  margin on capacity while still providing practical throughput.
- one unified sponge avoids early design fragmentation across SPHINCS+ paths.

## Byte Encoding Plan (Draft)

For absorb:

1. Prefix with one-byte domain tag (already done in API wrapper).
2. Absorb payload as a byte stream.
3. Split stream into `rate` chunks.
4. For each 8-byte lane, decode as little-endian `uint64_t`.
5. For partial tail, zero-pad within the chunk.
6. Apply Poseidon2 permutation between absorb blocks.
7. Finalize with explicit padding rule:
   - append `0x01` after message bytes in the next free byte;
   - set high bit (`0x80`) of the last rate byte in final block.

For squeeze:

1. Output little-endian bytes from rate lanes.
2. Apply permutation when more output is required.
3. Truncate to requested `outlen`.

Note: this keeps a deterministic byte API compatible with existing SPHINCS+
integration and can be mirrored in STARK circuits.

## API Contract (Current Draft In Code)

- `poseidon2_permute(uint64_t state[t])`
  - low-level permutation hook;
  - currently stubbed, must become full Poseidon2 rounds.
- `poseidon2_inc_init(ctx, domain_tag)`
- `poseidon2_inc_absorb(ctx, input, inlen)`
- `poseidon2_inc_finalize(ctx)`
- `poseidon2_inc_squeeze(output, outlen, ctx)`
- `poseidon2_hash_bytes_domain(output, outlen, domain_tag, input, inlen)`

Backward-compatible helper:

- `poseidon2_hash_bytes(output, outlen, domain_bytes, domainlen, input, inlen)`
  - absorbed under `SPX_P2_DOMAIN_CUSTOM`;
  - kept for transitional compatibility only.

## Why Sponge-First Instead Of Compression-First

Pros:

- one mode handles all variable lengths (`inblocks`) in SPHINCS+;
- lower implementation and audit complexity in first secure milestone;
- fewer domain-separation mistakes early on.

Cons:

- fixed-arity calls may be slower than tuned compression circuits;
- less optimal for some proving workloads.

Decision:

- start with sponge-first for correctness and integration speed;
- add optional compression shortcuts only after KAT and differential tests pass.

## Conformance And Validation Plan

Before declaring the backend "real Poseidon2":

1. add permutation known-answer tests (KAT) for selected states;
2. add sponge KAT for absorb/squeeze with domain tags;
3. cross-check vectors against one reference implementation;
4. rerun SPHINCS+ `test/spx` and `test/fors` for `poseidon2-192s`;
5. run randomized sign/verify regression (multiple seeds).

## Non-Goals For This Draft

- no claims of cryptographic conformance yet;
- no robust-thash mode yet;
- no SIMD or x4/x8 vectorized backend yet.
