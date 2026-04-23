PARAMS = sphincs-haraka-128f
THASH = robust

CC=/usr/bin/gcc
CFLAGS=-Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

# Auto-link Rust STARK backend when strict macro is enabled via EXTRA_CFLAGS.
# Override RUST_STARK_LIB_DIR if your artifacts are elsewhere.
RUST_STARK_LIB_DIR ?= $(CURDIR)/stark-rs/target/release
ifneq (,$(findstring -DSPX_P2_USE_RUST_STARK,$(EXTRA_CFLAGS)))
	LDLIBS += -L$(RUST_STARK_LIB_DIR) -lsphincsplus_stark_rs -Wl,-rpath,$(RUST_STARK_LIB_DIR)
endif

SOURCES =          address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c
HEADERS = params.h address.h randombytes.h merkle.h wots.h wotsx1.h utils.h utilsx1.h fors.h api.h  hash.h thash.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += fips202.c hash_shake.c thash_shake_$(THASH).c
	HEADERS += fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += haraka.c hash_haraka.c thash_haraka_$(THASH).c
	HEADERS += haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += sha2.c hash_sha2.c thash_sha2_$(THASH).c
	HEADERS += sha2.h
endif
ifneq (,$(findstring poseidon2,$(PARAMS)))
	SOURCES += fips202.c poseidon2.c hash_poseidon2.c thash_poseidon2_simple.c hash_poseidon2_adapter.c bsig_poseidon2_v0.c show/show_poseidon2_v1.c show/show_poseidon2.c stark/witness_builder.c stark/air_poseidon2_perm.c stark/air_poseidon2_sponge.c stark/air_hashcall.c stark/air_verify_minimal.c stark/air_verify_full.c stark/pi_f_format_v1.c stark/pi_f_format_v2.c stark/pi_f_format.c stark/prover_v1.c stark/verifier_v1.c stark/ffi_v1.c stark/ffi.c stark/stats_v1.c stark/stats.c
	HEADERS += fips202.h poseidon2.h poseidon2_params_goldilocks_profile.h hash_poseidon2_adapter.h bsig_poseidon2_v0.h show/show_poseidon2_v1.h show/show_poseidon2.h stark/witness_format.h stark/air_poseidon2_perm.h stark/air_poseidon2_sponge.h stark/air_hashcall.h stark/air_verify_minimal.h stark/air_verify_full.h stark/pi_f_format_v1.h stark/pi_f_format_v2.h stark/pi_f_format.h stark/prover_v1.h stark/verifier_v1.h stark/ffi_v1.h stark/ffi.h stark/stats_v1.h stark/stats.h
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS =         test/fors \
		test/spx \

ifneq (,$(findstring poseidon2,$(PARAMS)))
	TESTS += test/poseidon2_api
	TESTS += test/poseidon2_kat
	TESTS += test/poseidon2_adapter
	TESTS += test/poseidon2_instantiation_m1
	TESTS += test/poseidon2_show_v1_boundary
	TESTS += test/poseidon2_witness_v1
	TESTS += test/poseidon2_perm_air_v1
	TESTS += test/poseidon2_sponge_air_v1
	TESTS += test/poseidon2_hashcall_air_v1
	TESTS += test/poseidon2_verify_minimal_air_v1
	TESTS += test/poseidon2_verify_full_air_v1
	TESTS += test/poseidon2_show_v1
	TESTS += test/poseidon2_fischlin_blind_e2e
	TESTS += test/poseidon2_roles_interaction
	TESTS += test/poseidon2_trace_replay_binding
	TESTS += test/poseidon2_statement_binding
	TESTS += test/poseidon2_verify_full_guard
	TESTS += test/poseidon2_cross_backend_consistency
	TESTS += test/poseidon2_pi_f_format
	TESTS += test/poseidon2_stark_ffi_v1
	TESTS += test/poseidon2_stark_stats
endif

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/haraka: test/haraka.c $(filter-out haraka.c,$(SOURCES)) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(SOURCES)) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
