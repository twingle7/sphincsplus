PARAMS = sphincs-haraka-128f
THASH = robust

CC=/usr/bin/gcc
CFLAGS=-Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

# Auto-link Rust STARK backend when strict macro is enabled via EXTRA_CFLAGS.
# Override RUST_STARK_LIB_DIR if your artifacts are elsewhere.
RUST_STARK_LIB_DIR ?= $(CURDIR)/stark-rs/target/release
RUST_STARK_STATIC_LIB = $(RUST_STARK_LIB_DIR)/libsphincsplus_stark_rs.a
LINK_EXTRA_DEPS =
RUST_STARK_LDLIBS = -lpthread -lm
ifeq ($(OS),Windows_NT)
	RUST_STARK_LDLIBS +=
else
	RUST_STARK_LDLIBS += -ldl
endif
ifneq (,$(findstring -DSPX_P2_USE_RUST_STARK,$(EXTRA_CFLAGS)))
	LDLIBS += $(RUST_STARK_STATIC_LIB) $(RUST_STARK_LDLIBS)
	LINK_EXTRA_DEPS += $(RUST_STARK_STATIC_LIB)
endif

SOURCES =          address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c hash_profile.c
HEADERS = params.h address.h randombytes.h merkle.h wots.h wotsx1.h utils.h utilsx1.h fors.h api.h  hash.h thash.h hash_profile.h

ifneq (,$(findstring shake,$(PARAMS)))
	CFLAGS += -DSPX_BACKEND_SHAKE=1
	SOURCES += fips202.c hash_shake.c thash_shake_$(THASH).c
	HEADERS += fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	CFLAGS += -DSPX_BACKEND_HARAKA=1
	SOURCES += haraka.c hash_haraka.c thash_haraka_$(THASH).c
	HEADERS += haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	CFLAGS += -DSPX_BACKEND_SHA2=1
	SOURCES += sha2.c hash_sha2.c thash_sha2_$(THASH).c
	HEADERS += sha2.h
endif
ifneq (,$(findstring poseidon2,$(PARAMS)))
	CFLAGS += -DSPX_BACKEND_POSEIDON2=1
	SOURCES += fips202.c poseidon2.c hash_poseidon2.c thash_poseidon2_simple.c hash_poseidon2_adapter.c bsig_poseidon2_v0.c show/show_poseidon2_v1.c show/show_poseidon2.c show/protocol_poseidon2_v1.c stark/witness_builder.c stark/air_poseidon2_perm.c stark/air_poseidon2_sponge.c stark/air_hashcall.c stark/air_verify_minimal.c stark/air_verify_full.c stark/pi_f_format_v1.c stark/pi_f_format_v2.c stark/pi_f_format.c stark/prover_v1.c stark/verifier_v1.c stark/relation_migration_v1.c stark/ffi_v1.c stark/ffi.c stark/stats_v1.c stark/stats.c
	HEADERS += fips202.h poseidon2.h poseidon2_params_goldilocks_profile.h hash_poseidon2_adapter.h bsig_poseidon2_v0.h show/show_poseidon2_v1.h show/show_poseidon2.h show/protocol_poseidon2_v1.h show/protocol_poseidon2.h stark/witness_format.h stark/air_poseidon2_perm.h stark/air_poseidon2_sponge.h stark/air_hashcall.h stark/air_verify_minimal.h stark/air_verify_full.h stark/pi_f_format_v1.h stark/pi_f_format_v2.h stark/pi_f_format.h stark/show_proof_format.h stark/prover_v1.h stark/verifier_v1.h stark/relation_migration_v1.h stark/ffi_v1.h stark/ffi.h stark/stats_v1.h stark/stats.h stark/thash_bench.h
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS =         test/fors \
		test/spx \

POSEIDON2_TESTS = \
		test/poseidon2_api \
		test/poseidon2_kat \
		test/poseidon2_adapter \
		test/poseidon2_instantiation_m1 \
		test/poseidon2_show_v1_boundary \
		test/poseidon2_witness_v1 \
		test/poseidon2_perm_air_v1 \
		test/poseidon2_sponge_air_v1 \
		test/poseidon2_hashcall_air_v1 \
		test/poseidon2_verify_minimal_air_v1 \
		test/poseidon2_verify_full_air_v1 \
		test/poseidon2_show_v1 \
		test/poseidon2_fischlin_blind_e2e \
		test/poseidon2_fischlin_spec_flow_v1 \
		test/poseidon2_fischlin_statement_bound_spec \
		test/poseidon2_protocol_flow_demo_v1 \
		test/poseidon2_protocol_flow_statement_bound \
		test/poseidon2_roles_interaction \
		test/poseidon2_show_m18_route_isolation \
		test/poseidon2_trace_replay_binding \
		test/poseidon2_statement_binding \
		test/poseidon2_verify_full_guard \
		test/poseidon2_cross_backend_consistency \
		test/poseidon2_show_proof_format \
		test/poseidon2_stark_ffi_v1 \
		test/poseidon2_stark_strict_core_enforcement \
		test/poseidon2_stark_stats \
		test/thash_backend_stark_compare

POSEIDON2_BENCHMARKS = test/poseidon2_protocol_benchmark_v1 test/poseidon2_protocol_benchmark_statement_bound

ifneq (,$(findstring poseidon2,$(PARAMS)))
	TESTS += $(POSEIDON2_TESTS)
	BENCHMARKS += $(POSEIDON2_BENCHMARKS)
endif

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARKS)

benchmark: $(BENCHMARKS:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto $(LDLIBS)

test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

test/hash_profile_verify: test/hash_profile_verify.c test/hash_profile_randombytes.c $(filter-out randombytes.c,$(SOURCES)) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(filter-out randombytes.c,$(SOURCES)) test/hash_profile_randombytes.c $< $(LDLIBS)

test/thash_backend_stark_compare: test/thash_backend_stark_compare.c $(SOURCES) sha2.c stark/thash_bench.c $(HEADERS) sha2.h stark/thash_bench.h $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -DSPX_SHA2=1 -o $@ $(SOURCES) sha2.c stark/thash_bench.c $< $(LDLIBS)

test/poseidon2_protocol_flow_strict_public: test/poseidon2_protocol_flow_demo_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_fischlin_strict_public_spec: test/poseidon2_fischlin_spec_flow_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_fischlin_statement_bound_spec: test/poseidon2_fischlin_spec_flow_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_protocol_benchmark_strict_public: test/poseidon2_protocol_benchmark_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_protocol_benchmark_statement_bound: test/poseidon2_protocol_benchmark_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_protocol_flow_statement_bound: test/poseidon2_protocol_flow_demo_v1.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/poseidon2_show_proof_format: test/poseidon2_pi_f_format.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%: test/%.c $(SOURCES) $(HEADERS) $(LINK_EXTRA_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/haraka: test/haraka.c $(filter-out haraka.c,$(SOURCES)) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(SOURCES)) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(POSEIDON2_TESTS)
	-$(RM) $(BENCHMARKS)
	-$(RM) $(POSEIDON2_BENCHMARKS)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
