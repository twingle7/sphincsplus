#![allow(clippy::missing_safety_doc)]

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

pub const SPX_P2_STARK_RUST_ABI_VERSION_V1: u32 = 1;

pub const SPX_P2_RUST_OK: i32 = 0;
pub const SPX_P2_RUST_ERR_NULL: i32 = -1;
pub const SPX_P2_RUST_ERR_INPUT: i32 = -2;
pub const SPX_P2_RUST_ERR_BUFFER_SMALL: i32 = -3;
pub const SPX_P2_RUST_ERR_PROVE: i32 = -4;
pub const SPX_P2_RUST_ERR_VERIFY: i32 = -5;
pub const SPX_P2_RUST_ERR_FORMAT: i32 = -6;

const PROOF_MAGIC: u32 = 0x31315253; // "SR11"
const TRACE_LEN: usize = 64;

#[repr(C)]
pub struct SpxP2FfiBlobV1 {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct SpxP2FfiPublicInputsV1 {
    pub pk: *const u8,
    pub com: *const u8,
    pub public_ctx: *const u8,
    pub public_ctx_len: usize,
}

#[repr(C)]
pub struct SpxP2FfiPrivateWitnessV1 {
    pub sigma_com: *const u8,
}

#[derive(Clone)]
struct PublicInputs {
    start: BaseElement,
    result: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

struct WorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
}

impl Air for WorkAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(3)];
        let num_assertions = 2;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_state = frame.current()[0];
        let next_state = current_state.exp(3u32.into()) + E::from(42u32);
        result[0] = frame.next()[0] - next_state;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct WorkProver {
    options: ProofOptions,
}

impl WorkProver {
    fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

impl Prover for WorkProver {
    type BaseField = BaseElement;
    type Air = WorkAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
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

fn options_96bits() -> ProofOptions {
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

fn hash_to_u128(pk: &[u8], com: &[u8], public_ctx: &[u8]) -> u128 {
    let mut acc_hi: u64 = 0xcbf29ce484222325u64;
    let mut acc_lo: u64 = 0x9e3779b97f4a7c15u64;
    for &b in pk.iter().chain(com.iter()).chain(public_ctx.iter()) {
        acc_hi ^= b as u64;
        acc_hi = acc_hi.wrapping_mul(0x100000001b3u64);
        acc_lo ^= (b as u64).wrapping_mul(0x9e3779b97f4a7c15u64);
        acc_lo = acc_lo.rotate_left(13).wrapping_add(0x517cc1b727220a95u64);
    }
    ((acc_hi as u128) << 64) | (acc_lo as u128)
}

fn build_work_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(1, n);
    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42);
        },
    );
    trace
}

fn write_u32_le(out: &mut [u8], x: u32) {
    out[0] = (x & 0xff) as u8;
    out[1] = ((x >> 8) & 0xff) as u8;
    out[2] = ((x >> 16) & 0xff) as u8;
    out[3] = ((x >> 24) & 0xff) as u8;
}

fn read_u32_le(input: &[u8]) -> u32 {
    (input[0] as u32)
        | ((input[1] as u32) << 8)
        | ((input[2] as u32) << 16)
        | ((input[3] as u32) << 24)
}

fn write_u128_le(out: &mut [u8], x: u128) {
    for (i, b) in out.iter_mut().enumerate().take(16) {
        *b = ((x >> (8 * i)) & 0xff) as u8;
    }
}

fn read_u128_le(input: &[u8]) -> u128 {
    let mut x = 0u128;
    for (i, b) in input.iter().enumerate().take(16) {
        x |= (*b as u128) << (8 * i);
    }
    x
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_get_abi_version_v1(out_version: *mut u32) -> i32 {
    if out_version.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }
    *out_version = SPX_P2_STARK_RUST_ABI_VERSION_V1;
    SPX_P2_RUST_OK
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_generate_pi_f_v1(
    out_proof: *mut SpxP2FfiBlobV1,
    pub_inputs: *const SpxP2FfiPublicInputsV1,
    _wit: *const SpxP2FfiPrivateWitnessV1,
) -> i32 {
    if out_proof.is_null() || pub_inputs.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }
    let out = &mut *out_proof;
    let pubi = &*pub_inputs;
    if out.data.is_null() || pubi.pk.is_null() || pubi.com.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.public_ctx_len > 0 && pubi.public_ctx.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }

    let pk = std::slice::from_raw_parts(pubi.pk, 48);
    let com = std::slice::from_raw_parts(pubi.com, 24);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };

    let start_u128 = hash_to_u128(pk, com, public_ctx);
    let start = BaseElement::new(start_u128);
    let trace = build_work_trace(start, TRACE_LEN);
    let result = trace.get(0, TRACE_LEN - 1);
    let proof = match WorkProver::new(options_96bits()).prove(trace) {
        Ok(p) => p,
        Err(_) => return SPX_P2_RUST_ERR_PROVE,
    };
    let proof_bytes = proof.to_bytes();

    let total_len = 4 + 4 + 16 + 16 + 4 + proof_bytes.len();
    if out.cap < total_len {
        return SPX_P2_RUST_ERR_BUFFER_SMALL;
    }
    let out_slice = std::slice::from_raw_parts_mut(out.data, out.cap);
    write_u32_le(&mut out_slice[0..4], PROOF_MAGIC);
    write_u32_le(&mut out_slice[4..8], 1);
    write_u128_le(&mut out_slice[8..24], start_u128);
    write_u128_le(&mut out_slice[24..40], result.as_int());
    write_u32_le(&mut out_slice[40..44], proof_bytes.len() as u32);
    out_slice[44..44 + proof_bytes.len()].copy_from_slice(&proof_bytes);
    out.len = total_len;
    SPX_P2_RUST_OK
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_verify_pi_f_v1(
    proof: *const SpxP2FfiBlobV1,
    pub_inputs: *const SpxP2FfiPublicInputsV1,
) -> i32 {
    if proof.is_null() || pub_inputs.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }
    let pf = &*proof;
    let pubi = &*pub_inputs;
    if pf.data.is_null() || pubi.pk.is_null() || pubi.com.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.public_ctx_len > 0 && pubi.public_ctx.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pf.len < 44 {
        return SPX_P2_RUST_ERR_FORMAT;
    }

    let data = std::slice::from_raw_parts(pf.data, pf.len);
    if read_u32_le(&data[0..4]) != PROOF_MAGIC || read_u32_le(&data[4..8]) != 1 {
        return SPX_P2_RUST_ERR_FORMAT;
    }

    let pk = std::slice::from_raw_parts(pubi.pk, 48);
    let com = std::slice::from_raw_parts(pubi.com, 24);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };
    let expected_start = hash_to_u128(pk, com, public_ctx);
    let start = read_u128_le(&data[8..24]);
    if start != expected_start {
        return SPX_P2_RUST_ERR_VERIFY;
    }
    let result_u128 = read_u128_le(&data[24..40]);
    let proof_len = read_u32_le(&data[40..44]) as usize;
    if pf.len != 44 + proof_len {
        return SPX_P2_RUST_ERR_FORMAT;
    }
    let proof_obj = match Proof::from_bytes(&data[44..]) {
        Ok(p) => p,
        Err(_) => return SPX_P2_RUST_ERR_FORMAT,
    };
    let pub_inputs = PublicInputs {
        start: BaseElement::new(start),
        result: BaseElement::new(result_u128),
    };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(80);
    match winterfell::verify::<
        WorkAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof_obj, pub_inputs, &min_opts)
    {
        Ok(()) => SPX_P2_RUST_OK,
        Err(_) => SPX_P2_RUST_ERR_VERIFY,
    }
}
