#![allow(clippy::missing_safety_doc)]

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
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

const TRACE_LEN: usize = 64;
const PK_LEN: usize = 48;
const COM_LEN: usize = 24;
const SPX_N: usize = 24;

const PI_F_V2_MAGIC: u32 = 0x32504650; // "PFP2"
const PI_F_V2_VERSION: u32 = 2;
const PI_F_V2_FLAG_STARK_PROOF: u32 = 0x0000_0001;
const PI_F_V2_PROOF_SYSTEM_ID_STARK: u32 = 2;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1: u32 = 1;
const PI_F_V2_FIXED_HEADER_BYTES: usize = 7 * 4;
const PI_F_V2_RESERVED_BYTES: usize = 2 * 4;

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
    mix: BaseElement,
    bind: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result, self.mix, self.bind]
    }
}

struct WorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
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
            mix: pub_inputs.mix,
            bind: pub_inputs.bind,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_state = frame.current()[0];
        let round_const = E::from(42u32) + E::from(self.mix) + E::from(self.bind);
        let next_state = current_state.exp(3u32.into()) + round_const;
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
            mix: BaseElement::ZERO,
            bind: BaseElement::ZERO,
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

fn hash_to_u128(parts: &[&[u8]]) -> u128 {
    let mut acc_hi: u64 = 0xcbf29ce484222325u64;
    let mut acc_lo: u64 = 0x9e3779b97f4a7c15u64;
    for part in parts {
        for &b in *part {
            acc_hi ^= b as u64;
            acc_hi = acc_hi.wrapping_mul(0x100000001b3u64);
            acc_lo ^= (b as u64).wrapping_mul(0x9e3779b97f4a7c15u64);
            acc_lo = acc_lo.rotate_left(13).wrapping_add(0x517cc1b727220a95u64);
        }
    }
    ((acc_hi as u128) << 64) | (acc_lo as u128)
}

fn hash_expand(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    let mut seed = hash_to_u128(parts);
    for (i, b) in out.iter_mut().enumerate() {
        let rot = ((i % 17) as u32) + 5;
        seed = seed.rotate_left(rot) ^ (0x9e3779b97f4a7c15u128 + i as u128);
        *b = (seed & 0xff) as u8;
    }
    out
}

fn derive_mix(digest: &[u8]) -> BaseElement {
    let mut x = 0u128;
    for (i, b) in digest.iter().enumerate().take(16) {
        x |= (*b as u128) << (8 * i);
    }
    BaseElement::new(x)
}

fn iterate_state(mut state: BaseElement, mix: BaseElement, bind: BaseElement, n: usize) -> BaseElement {
    for _ in 1..n {
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
    }
    state
}

fn build_work_trace(start: BaseElement, mix: BaseElement, bind: BaseElement, n: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(1, n);
    trace.fill(
        |state| {
            state[0] = start;
        },
        |_, state| {
            state[0] = state[0].exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        },
    );
    trace
}

fn encode_pi_f_v2(
    out: &mut [u8],
    public_input_digest: &[u8],
    ctx_binding: &[u8],
    commitment: &[u8],
    proof_bytes: &[u8],
) -> Option<usize> {
    if public_input_digest.len() != SPX_N || ctx_binding.len() != SPX_N || commitment.len() != SPX_N {
        return None;
    }
    let total_len = PI_F_V2_FIXED_HEADER_BYTES + SPX_N + SPX_N + SPX_N + 4 + proof_bytes.len() + PI_F_V2_RESERVED_BYTES;
    if out.len() < total_len || total_len > u32::MAX as usize {
        return None;
    }
    let mut off = 0usize;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_MAGIC);
    off += 4;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_VERSION);
    off += 4;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_FLAG_STARK_PROOF);
    off += 4;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_FIXED_HEADER_BYTES as u32);
    off += 4;
    write_u32_le(&mut out[off..off + 4], total_len as u32);
    off += 4;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_PROOF_SYSTEM_ID_STARK);
    off += 4;
    write_u32_le(&mut out[off..off + 4], PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1);
    off += 4;

    out[off..off + SPX_N].copy_from_slice(public_input_digest);
    off += SPX_N;
    out[off..off + SPX_N].copy_from_slice(ctx_binding);
    off += SPX_N;
    out[off..off + SPX_N].copy_from_slice(commitment);
    off += SPX_N;

    write_u32_le(&mut out[off..off + 4], proof_bytes.len() as u32);
    off += 4;
    out[off..off + proof_bytes.len()].copy_from_slice(proof_bytes);
    off += proof_bytes.len();
    out[off..off + PI_F_V2_RESERVED_BYTES].fill(0);
    off += PI_F_V2_RESERVED_BYTES;
    Some(off)
}

#[derive(Clone)]
struct PiFV2Decoded<'a> {
    flags: u32,
    proof_system_id: u32,
    statement_version: u32,
    public_input_digest: &'a [u8],
    ctx_binding: &'a [u8],
    commitment: &'a [u8],
    proof_bytes: &'a [u8],
}

fn decode_pi_f_v2(input: &[u8]) -> Option<PiFV2Decoded<'_>> {
    let min_len = PI_F_V2_FIXED_HEADER_BYTES + SPX_N + SPX_N + SPX_N + 4 + PI_F_V2_RESERVED_BYTES;
    if input.len() < min_len {
        return None;
    }
    let mut off = 0usize;
    let magic = read_u32_le(&input[off..off + 4]);
    off += 4;
    let version = read_u32_le(&input[off..off + 4]);
    off += 4;
    let flags = read_u32_le(&input[off..off + 4]);
    off += 4;
    let header_len = read_u32_le(&input[off..off + 4]) as usize;
    off += 4;
    let total_len = read_u32_le(&input[off..off + 4]) as usize;
    off += 4;
    let proof_system_id = read_u32_le(&input[off..off + 4]);
    off += 4;
    let statement_version = read_u32_le(&input[off..off + 4]);
    off += 4;

    if magic != PI_F_V2_MAGIC || version != PI_F_V2_VERSION {
        return None;
    }
    if header_len != PI_F_V2_FIXED_HEADER_BYTES || total_len != input.len() {
        return None;
    }

    let public_input_digest = &input[off..off + SPX_N];
    off += SPX_N;
    let ctx_binding = &input[off..off + SPX_N];
    off += SPX_N;
    let commitment = &input[off..off + SPX_N];
    off += SPX_N;
    let proof_len = read_u32_le(&input[off..off + 4]) as usize;
    off += 4;
    if input.len() < off + proof_len + PI_F_V2_RESERVED_BYTES {
        return None;
    }
    if input.len() - off - PI_F_V2_RESERVED_BYTES != proof_len {
        return None;
    }
    let proof_bytes = &input[off..off + proof_len];
    off += proof_len;
    if input[off..off + PI_F_V2_RESERVED_BYTES].iter().any(|b| *b != 0) {
        return None;
    }

    Some(PiFV2Decoded {
        flags,
        proof_system_id,
        statement_version,
        public_input_digest,
        ctx_binding,
        commitment,
        proof_bytes,
    })
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
    wit: *const SpxP2FfiPrivateWitnessV1,
) -> i32 {
    if out_proof.is_null() || pub_inputs.is_null() || wit.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }
    let out = &mut *out_proof;
    let pubi = &*pub_inputs;
    let witv = &*wit;
    if out.data.is_null() || pubi.pk.is_null() || pubi.com.is_null() || witv.sigma_com.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.public_ctx_len > 0 && pubi.public_ctx.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }

    let pk = std::slice::from_raw_parts(pubi.pk, PK_LEN);
    let com = std::slice::from_raw_parts(pubi.com, COM_LEN);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };
    let statement = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1.to_le_bytes();
    let public_input_digest = hash_expand(&[pk, com, public_ctx, &statement], SPX_N);
    let ctx_binding = hash_expand(&[public_ctx], SPX_N);
    let bind_digest = hash_expand(&[public_input_digest.as_slice(), ctx_binding.as_slice()], 16);
    let start_u128 = hash_to_u128(&[pk, com, public_ctx]);
    let start = BaseElement::new(start_u128);
    let mix = derive_mix(&public_input_digest);
    let bind = derive_mix(&bind_digest);
    let result = iterate_state(start, mix, bind, TRACE_LEN);
    let trace = build_work_trace(start, mix, bind, TRACE_LEN);
    let proof = match WorkProver::new(options_96bits()).prove(trace) {
        Ok(p) => p,
        Err(_) => return SPX_P2_RUST_ERR_PROVE,
    };
    let proof_bytes = proof.to_bytes();
    let commitment = hash_expand(&[proof_bytes.as_slice()], SPX_N);

    let out_slice = std::slice::from_raw_parts_mut(out.data, out.cap);
    let encoded_len = match encode_pi_f_v2(
        out_slice,
        &public_input_digest,
        &ctx_binding,
        &commitment,
        &proof_bytes,
    ) {
        Some(n) => n,
        None => return SPX_P2_RUST_ERR_BUFFER_SMALL,
    };
    out.len = encoded_len;

    let _ = result;
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
    let data = std::slice::from_raw_parts(pf.data, pf.len);
    let decoded = match decode_pi_f_v2(data) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_FORMAT,
    };
    if decoded.flags & PI_F_V2_FLAG_STARK_PROOF == 0
        || decoded.proof_system_id != PI_F_V2_PROOF_SYSTEM_ID_STARK
        || decoded.statement_version != PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1
    {
        return SPX_P2_RUST_ERR_FORMAT;
    }

    let pk = std::slice::from_raw_parts(pubi.pk, PK_LEN);
    let com = std::slice::from_raw_parts(pubi.com, COM_LEN);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };
    let statement = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1.to_le_bytes();
    let expected_public_input_digest = hash_expand(&[pk, com, public_ctx, &statement], SPX_N);
    let expected_ctx_binding = hash_expand(&[public_ctx], SPX_N);
    if decoded.public_input_digest != expected_public_input_digest.as_slice()
        || decoded.ctx_binding != expected_ctx_binding.as_slice()
    {
        return SPX_P2_RUST_ERR_VERIFY;
    }

    let start_u128 = hash_to_u128(&[pk, com, public_ctx]);
    let start = BaseElement::new(start_u128);
    let mix = derive_mix(decoded.public_input_digest);
    let bind_seed = hash_expand(&[decoded.public_input_digest, decoded.ctx_binding], 16);
    let bind = derive_mix(&bind_seed);
    let result = iterate_state(start, mix, bind, TRACE_LEN);
    let _ = decoded.commitment;

    let proof_obj = match Proof::from_bytes(decoded.proof_bytes) {
        Ok(p) => p,
        Err(_) => return SPX_P2_RUST_ERR_FORMAT,
    };
    let pub_inputs = PublicInputs {
        start,
        result,
        mix,
        bind,
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
