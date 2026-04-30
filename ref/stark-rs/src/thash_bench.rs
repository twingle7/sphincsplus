use std::time::Instant;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::{
    SPX_P2_RUST_ERR_INPUT, SPX_P2_RUST_ERR_NULL, SPX_P2_RUST_ERR_PROVE,
    SPX_P2_RUST_ERR_VERIFY, SPX_P2_RUST_OK,
};

pub const SPX_THASH_BENCH_BACKEND_SHA2_V1: u32 = 1;
pub const SPX_THASH_BENCH_BACKEND_POSEIDON2_V1: u32 = 2;

const SPX_N: usize = 24;
const SPX_ADDR_WORDS: usize = 8;
const SPX_ADDR_BYTES: usize = SPX_ADDR_WORDS * 4;
const SPX_SHA256_ADDR_BYTES: usize = 22;
const POSEIDON2_RATE_BYTES: usize = 48;
const POSEIDON2_ROUNDS_PERMUTATION: usize = 30;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA512_BLOCK_BYTES: usize = 128;
const SHA256_FINAL_PAD_LIMIT: usize = 56;
const SHA512_FINAL_PAD_LIMIT: usize = 112;
const SHA256_ROUNDS_PER_COMPRESSION: usize = 64;
const SHA512_ROUNDS_PER_COMPRESSION: usize = 80;

const POSEIDON2_WIDTH: usize = 9;
const POSEIDON2_TRANSITION_CONSTRAINTS: usize = 10;
const POSEIDON2_BOUNDARY_ASSERTIONS: usize = 14;

const SHA2_WIDTH: usize = 20;
const SHA2_TRANSITION_CONSTRAINTS: usize = 21;
const SHA2_BOUNDARY_ASSERTIONS: usize = 18;

#[repr(C)]
pub struct SpxThashBenchInstanceRawV1 {
    pub backend_id: u32,
    pub mode: u32,
    pub inblocks: u32,
    pub rounds: u32,
    pub pub_seed: *const u8,
    pub addr: *const u32,
    pub input: *const u8,
    pub input_len: usize,
    pub expected_output: *const u8,
}

#[repr(C)]
pub struct SpxThashBenchStatsV1 {
    pub backend_id: u32,
    pub mode: u32,
    pub inblocks: u32,
    pub rounds: u32,
    pub trace_width: u32,
    pub trace_length: u32,
    pub transition_constraints: u32,
    pub boundary_assertions: u32,
    pub constraint_eval_total: u64,
    pub proof_bytes: u64,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub exact_primitive_calls: u32,
    pub exact_round_rows: u32,
    pub input_mix: u64,
    pub output_mix: u64,
    pub result_tag: u64,
}

#[derive(Clone, Copy)]
struct ThashBenchProfile {
    backend_id: u32,
    width: usize,
    transition_constraints: usize,
    boundary_assertions: usize,
}

#[derive(Clone)]
struct ThashBenchPublicInputs {
    backend_id: BaseElement,
    start: BaseElement,
    result: BaseElement,
    step_last: BaseElement,
    input_mix: BaseElement,
    addr_mix: BaseElement,
    seed_mix: BaseElement,
    output_mix: BaseElement,
    domain_mix: BaseElement,
}

impl ToElements<BaseElement> for ThashBenchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.backend_id,
            self.start,
            self.result,
            self.step_last,
            self.input_mix,
            self.addr_mix,
            self.seed_mix,
            self.output_mix,
            self.domain_mix,
        ]
    }
}

struct ThashBenchAir {
    context: AirContext<BaseElement>,
    profile: ThashBenchProfile,
    start: BaseElement,
    result: BaseElement,
    step_last: BaseElement,
    input_mix: BaseElement,
    addr_mix: BaseElement,
    seed_mix: BaseElement,
    output_mix: BaseElement,
    domain_mix: BaseElement,
}

struct ThashBenchProver {
    options: ProofOptions,
    pub_inputs: ThashBenchPublicInputs,
}

fn profile_for_backend(backend_id: u32) -> Option<ThashBenchProfile> {
    match backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => Some(ThashBenchProfile {
            backend_id,
            width: SHA2_WIDTH,
            transition_constraints: SHA2_TRANSITION_CONSTRAINTS,
            boundary_assertions: SHA2_BOUNDARY_ASSERTIONS,
        }),
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => Some(ThashBenchProfile {
            backend_id,
            width: POSEIDON2_WIDTH,
            transition_constraints: POSEIDON2_TRANSITION_CONSTRAINTS,
            boundary_assertions: POSEIDON2_BOUNDARY_ASSERTIONS,
        }),
        _ => None,
    }
}

fn bench_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn mix_bytes(parts: &[&[u8]]) -> BaseElement {
    let mut hi = 0xcbf29ce484222325u64;
    let mut lo = 0x9e3779b97f4a7c15u64;

    for part in parts {
        for &b in *part {
            hi ^= b as u64;
            hi = hi.wrapping_mul(0x100000001b3);
            lo ^= (b as u64).wrapping_add(0x9e3779b97f4a7c15);
            lo = lo.rotate_left(9).wrapping_mul(0x9e3779b185ebca87);
        }
    }

    BaseElement::new(((hi as u128) << 64) | (lo as u128))
}

fn u32_words_as_bytes(addr: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() * 4);
    for word in addr {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn domain_bias(backend_id: u32, inblocks: u32) -> BaseElement {
    let tag = match backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => 0x5348_4132u128,
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => 0x5032_444Eu128,
        _ => 0,
    };
    BaseElement::new(tag + inblocks as u128 * 97u128)
}

fn derive_public_inputs(inst: &SpxThashBenchInstanceRawV1) -> Option<ThashBenchPublicInputs> {
    let profile = profile_for_backend(inst.backend_id)?;
    let _ = profile;
    if inst.pub_seed.is_null() || inst.addr.is_null() || inst.input.is_null() || inst.expected_output.is_null() {
        return None;
    }
    if inst.inblocks == 0 || inst.rounds < 8 || !inst.rounds.is_power_of_two() {
        return None;
    }
    if inst.input_len != inst.inblocks as usize * SPX_N {
        return None;
    }

    let pub_seed = unsafe { std::slice::from_raw_parts(inst.pub_seed, SPX_N) };
    let addr_words = unsafe { std::slice::from_raw_parts(inst.addr, SPX_ADDR_WORDS) };
    let input = unsafe { std::slice::from_raw_parts(inst.input, inst.input_len) };
    let expected_output = unsafe { std::slice::from_raw_parts(inst.expected_output, SPX_N) };
    let addr_bytes = u32_words_as_bytes(addr_words);

    let input_mix = mix_bytes(&[input]);
    let addr_mix = mix_bytes(&[&addr_bytes]);
    let seed_mix = mix_bytes(&[pub_seed]);
    let output_mix = mix_bytes(&[expected_output]);
    let domain_mix = input_mix + addr_mix + seed_mix + domain_bias(inst.backend_id, inst.inblocks);
    let start = mix_bytes(&[
        pub_seed,
        &addr_bytes,
        input,
        expected_output,
        &inst.backend_id.to_le_bytes(),
        &inst.inblocks.to_le_bytes(),
        &inst.rounds.to_le_bytes(),
    ]);

    Some(ThashBenchPublicInputs {
        backend_id: BaseElement::new(inst.backend_id as u128),
        start,
        result: BaseElement::ZERO,
        step_last: BaseElement::new((inst.rounds - 1) as u128),
        input_mix,
        addr_mix,
        seed_mix,
        output_mix,
        domain_mix,
    })
}

fn exact_poseidon2_work_units(input_len: usize) -> (u32, u32) {
    let absorbed_bytes = 1usize + SPX_N + SPX_ADDR_BYTES + input_len;
    let permutation_calls = (absorbed_bytes / POSEIDON2_RATE_BYTES) + 1usize;
    (
        permutation_calls as u32,
        (permutation_calls * POSEIDON2_ROUNDS_PERMUTATION) as u32,
    )
}

fn exact_sha2_work_units(inblocks: u32, input_len: usize) -> (u32, u32) {
    let msg_len = SPX_SHA256_ADDR_BYTES + input_len;
    let (block_bytes, final_pad_limit, rounds_per_compression) = if SPX_N >= 24 && inblocks > 1 {
        (
            SHA512_BLOCK_BYTES,
            SHA512_FINAL_PAD_LIMIT,
            SHA512_ROUNDS_PER_COMPRESSION,
        )
    } else {
        (
            SHA256_BLOCK_BYTES,
            SHA256_FINAL_PAD_LIMIT,
            SHA256_ROUNDS_PER_COMPRESSION,
        )
    };
    let full_blocks = msg_len / block_bytes;
    let rem = msg_len % block_bytes;
    let padded_blocks = if rem < final_pad_limit { 1usize } else { 2usize };
    let compression_calls = full_blocks + padded_blocks;
    (
        compression_calls as u32,
        (compression_calls * rounds_per_compression) as u32,
    )
}

fn exact_work_units(inst: &SpxThashBenchInstanceRawV1) -> (u32, u32) {
    match inst.backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => exact_sha2_work_units(inst.inblocks, inst.input_len),
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => exact_poseidon2_work_units(inst.input_len),
        _ => (0, 0),
    }
}

fn result_column(profile: ThashBenchProfile) -> usize {
    match profile.backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => 18,
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => 7,
        _ => 0,
    }
}

fn p2_next_state(cur: BaseElement, input_mix: BaseElement, seed_mix: BaseElement, domain_mix: BaseElement) -> BaseElement {
    cur.exp(7u32.into()) + input_mix + seed_mix + domain_mix + BaseElement::new(17u128)
}

fn build_poseidon2_trace(pub_inputs: &ThashBenchPublicInputs, trace_len: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(POSEIDON2_WIDTH, trace_len);
    trace.fill(
        |state| {
            state[0] = pub_inputs.start;
            state[1] = BaseElement::ZERO;
            state[2] = pub_inputs.input_mix;
            state[3] = pub_inputs.addr_mix;
            state[4] = pub_inputs.seed_mix;
            state[5] = pub_inputs.output_mix;
            state[6] = pub_inputs.domain_mix;
            state[7] = pub_inputs.output_mix + pub_inputs.domain_mix;
            state[8] = pub_inputs.domain_mix;
        },
        |_, state| {
            let prev0 = state[0];
            let prev1 = state[1];
            let prev3 = state[3];
            let prev5 = state[5];
            let prev7 = state[7];

            state[0] = p2_next_state(prev0, state[2], state[4], state[6]);
            state[1] = prev1 + BaseElement::ONE;
            state[7] = prev7 + prev0 + prev3 * BaseElement::new(3u128) + prev5;
        },
    );
    trace
}

fn build_sha2_trace(pub_inputs: &ThashBenchPublicInputs, trace_len: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(SHA2_WIDTH, trace_len);
    trace.fill(
        |state| {
            state[0] = pub_inputs.start;
            state[1] = pub_inputs.start + BaseElement::new(5u128);
            state[2] = pub_inputs.start + BaseElement::new(11u128);
            state[3] = pub_inputs.start + BaseElement::new(17u128);
            state[4] = pub_inputs.start + BaseElement::new(23u128);
            state[5] = pub_inputs.start + BaseElement::new(29u128);
            state[6] = pub_inputs.start + BaseElement::new(31u128);
            state[7] = pub_inputs.start + BaseElement::new(37u128);
            state[8] = pub_inputs.input_mix;
            state[9] = pub_inputs.addr_mix;
            state[10] = pub_inputs.seed_mix;
            state[11] = pub_inputs.output_mix;
            state[12] = BaseElement::ZERO;
            state[13] = pub_inputs.input_mix;
            state[14] = pub_inputs.addr_mix;
            state[15] = pub_inputs.seed_mix;
            state[16] = pub_inputs.output_mix;
            state[17] = pub_inputs.domain_mix;
            state[18] = pub_inputs.output_mix + pub_inputs.domain_mix;
            state[19] = pub_inputs.domain_mix;
        },
        |_, state| {
            let a = state[0];
            let b = state[1];
            let c = state[2];
            let d = state[3];
            let e = state[4];
            let f = state[5];
            let g = state[6];
            let h = state[7];
            let w0 = state[8];
            let w1 = state[9];
            let w2 = state[10];
            let w3 = state[11];
            let step = state[12];
            let input_mix = state[13];
            let addr_mix = state[14];
            let seed_mix = state[15];
            let output_mix = state[16];
            let domain_mix = state[17];
            let acc = state[18];

            state[0] = h + e * e + w0 + seed_mix + BaseElement::new(3u128);
            state[1] = a;
            state[2] = b + w1;
            state[3] = c;
            state[4] = d + a * f + addr_mix;
            state[5] = e;
            state[6] = f + w2;
            state[7] = g;
            state[8] = w1 + input_mix + step + f;
            state[9] = w2 + addr_mix + a;
            state[10] = w3 + seed_mix + b;
            state[11] = w0 + output_mix + c;
            state[12] = step + BaseElement::ONE;
            state[18] = acc + a + e + w0 + output_mix + domain_mix;
            state[19] = domain_mix;
        },
    );
    trace
}

fn build_trace(profile: ThashBenchProfile, pub_inputs: &ThashBenchPublicInputs, trace_len: usize) -> TraceTable<BaseElement> {
    match profile.backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => build_sha2_trace(pub_inputs, trace_len),
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => build_poseidon2_trace(pub_inputs, trace_len),
        _ => unreachable!(),
    }
}

fn degrees_for_profile(profile: ThashBenchProfile) -> Vec<TransitionConstraintDegree> {
    match profile.backend_id {
        SPX_THASH_BENCH_BACKEND_SHA2_V1 => vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ],
        SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => vec![
            TransitionConstraintDegree::new(7),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ],
        _ => unreachable!(),
    }
}

impl Air for ThashBenchAir {
    type BaseField = BaseElement;
    type PublicInputs = ThashBenchPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: ThashBenchPublicInputs, options: ProofOptions) -> Self {
        let backend_id = pub_inputs.backend_id.as_int() as u32;
        let profile = profile_for_backend(backend_id).expect("invalid backend id");
        let degrees = degrees_for_profile(profile);
        Self {
            context: AirContext::new(trace_info, degrees, profile.boundary_assertions, options),
            profile,
            start: pub_inputs.start,
            result: pub_inputs.result,
            step_last: pub_inputs.step_last,
            input_mix: pub_inputs.input_mix,
            addr_mix: pub_inputs.addr_mix,
            seed_mix: pub_inputs.seed_mix,
            output_mix: pub_inputs.output_mix,
            domain_mix: pub_inputs.domain_mix,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        match self.profile.backend_id {
            SPX_THASH_BENCH_BACKEND_SHA2_V1 => {
                result[0] = next[0] - (current[7] + current[4] * current[4] + current[8] + current[15] + E::from(3u32));
                result[1] = next[1] - current[0];
                result[2] = next[2] - (current[1] + current[9]);
                result[3] = next[3] - current[2];
                result[4] = next[4] - (current[3] + current[0] * current[5] + current[14]);
                result[5] = next[5] - current[4];
                result[6] = next[6] - (current[5] + current[10]);
                result[7] = next[7] - current[6];
                result[8] = next[8] - (current[9] + current[13] + current[12] + current[5]);
                result[9] = next[9] - (current[10] + current[14] + current[0]);
                result[10] = next[10] - (current[11] + current[15] + current[1]);
                result[11] = next[11] - (current[8] + current[16] + current[2]);
                result[12] = next[12] - (current[12] + E::ONE);
                result[13] = next[13] - current[13];
                result[14] = next[14] - current[14];
                result[15] = next[15] - current[15];
                result[16] = next[16] - current[16];
                result[17] = next[17] - current[17];
                result[18] = next[18] - (current[18] + current[0] + current[4] + current[8] + current[16] + current[17]);
                result[19] = next[19] - current[19];
                result[20] = current[19] - current[17];
            }
            SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => {
                result[0] = next[0] - (current[0].exp(7u32.into()) + current[2] + current[4] + current[6] + E::from(17u32));
                result[1] = next[1] - (current[1] + E::ONE);
                result[2] = next[2] - current[2];
                result[3] = next[3] - current[3];
                result[4] = next[4] - current[4];
                result[5] = next[5] - current[5];
                result[6] = next[6] - current[6];
                result[7] = next[7] - (current[7] + current[0] + current[3] * E::from(3u32) + current[5]);
                result[8] = next[8] - current[8];
                result[9] = current[8] - current[6];
            }
            _ => unreachable!(),
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        match self.profile.backend_id {
            SPX_THASH_BENCH_BACKEND_SHA2_V1 => vec![
                Assertion::single(0, 0, self.start),
                Assertion::single(12, 0, BaseElement::ZERO),
                Assertion::single(12, last_step, self.step_last),
                Assertion::single(13, 0, self.input_mix),
                Assertion::single(13, last_step, self.input_mix),
                Assertion::single(14, 0, self.addr_mix),
                Assertion::single(14, last_step, self.addr_mix),
                Assertion::single(15, 0, self.seed_mix),
                Assertion::single(15, last_step, self.seed_mix),
                Assertion::single(16, 0, self.output_mix),
                Assertion::single(16, last_step, self.output_mix),
                Assertion::single(17, 0, self.domain_mix),
                Assertion::single(17, last_step, self.domain_mix),
                Assertion::single(18, last_step, self.result),
                Assertion::single(19, 0, self.domain_mix),
                Assertion::single(19, last_step, self.domain_mix),
                Assertion::single(1, 0, self.start + BaseElement::new(5u128)),
                Assertion::single(7, 0, self.start + BaseElement::new(37u128)),
            ],
            SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 => vec![
                Assertion::single(0, 0, self.start),
                Assertion::single(1, 0, BaseElement::ZERO),
                Assertion::single(1, last_step, self.step_last),
                Assertion::single(2, 0, self.input_mix),
                Assertion::single(2, last_step, self.input_mix),
                Assertion::single(3, 0, self.addr_mix),
                Assertion::single(3, last_step, self.addr_mix),
                Assertion::single(4, 0, self.seed_mix),
                Assertion::single(4, last_step, self.seed_mix),
                Assertion::single(5, 0, self.output_mix),
                Assertion::single(5, last_step, self.output_mix),
                Assertion::single(6, 0, self.domain_mix),
                Assertion::single(6, last_step, self.domain_mix),
                Assertion::single(7, last_step, self.result),
            ],
            _ => unreachable!(),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

impl ThashBenchProver {
    fn new(options: ProofOptions, pub_inputs: ThashBenchPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for ThashBenchProver {
    type BaseField = BaseElement;
    type Air = ThashBenchAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ThashBenchPublicInputs {
        let mut out = self.pub_inputs.clone();
        out.result = trace.get(result_column(profile_for_backend(self.pub_inputs.backend_id.as_int() as u32).unwrap()), trace.length() - 1);
        out
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_run_thash_bench_v1(
    out_stats: *mut SpxThashBenchStatsV1,
    inst: *const SpxThashBenchInstanceRawV1,
) -> i32 {
    if out_stats.is_null() || inst.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }

    let stats = &mut *out_stats;
    let inst_ref = &*inst;
    let profile = match profile_for_backend(inst_ref.backend_id) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    let mut pub_inputs = match derive_public_inputs(inst_ref) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    let trace_len = inst_ref.rounds as usize;
    let trace = build_trace(profile, &pub_inputs, trace_len);
    pub_inputs.result = trace.get(result_column(profile), trace_len - 1);

    let prove_begin = Instant::now();
    let proof = match ThashBenchProver::new(bench_options(), pub_inputs.clone()).prove(trace) {
        Ok(v) => v,
        Err(_) => return SPX_P2_RUST_ERR_PROVE,
    };
    let prove_ms = prove_begin.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes = proof.to_bytes();
    let proof_len = proof_bytes.len() as u64;
    let proof_obj = match Proof::from_bytes(&proof_bytes) {
        Ok(v) => v,
        Err(_) => return SPX_P2_RUST_ERR_PROVE,
    };

    let verify_begin = Instant::now();
    let min_opts = AcceptableOptions::MinConjecturedSecurity(64);
    if winterfell::verify::<
        ThashBenchAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof_obj, pub_inputs.clone(), &min_opts)
    .is_err()
    {
        return SPX_P2_RUST_ERR_VERIFY;
    }
    let verify_ms = verify_begin.elapsed().as_secs_f64() * 1000.0;
    let (exact_primitive_calls, exact_round_rows) = exact_work_units(inst_ref);

    *stats = SpxThashBenchStatsV1 {
        backend_id: inst_ref.backend_id,
        mode: inst_ref.mode,
        inblocks: inst_ref.inblocks,
        rounds: inst_ref.rounds,
        trace_width: profile.width as u32,
        trace_length: trace_len as u32,
        transition_constraints: profile.transition_constraints as u32,
        boundary_assertions: profile.boundary_assertions as u32,
        constraint_eval_total: profile.transition_constraints as u64 * (trace_len as u64 - 1u64)
            + profile.boundary_assertions as u64,
        proof_bytes: proof_len,
        prove_ms,
        verify_ms,
        exact_primitive_calls,
        exact_round_rows,
        input_mix: pub_inputs.input_mix.as_int() as u64,
        output_mix: pub_inputs.output_mix.as_int() as u64,
        result_tag: pub_inputs.result.as_int() as u64,
    };
    SPX_P2_RUST_OK
}
