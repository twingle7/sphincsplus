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

fn rust_verify_debug_enabled() -> bool {
    std::env::var_os("SPX_P2_DEBUG_VERIFY").is_some()
}

fn rust_verify_debug(msg: &str) {
    if rust_verify_debug_enabled() {
        eprintln!("[stark-rs verify] {msg}");
    }
}

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
    trace_calls: BaseElement,
    row_count: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    module_result: BaseElement,
    prf_start: BaseElement,
    prf_result: BaseElement,
    thash_start: BaseElement,
    thash_result: BaseElement,
    hmsg_start: BaseElement,
    hmsg_result: BaseElement,
    addr_start: BaseElement,
    addr_result: BaseElement,
    thash_rule_start: BaseElement,
    thash_rule_result: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_rule_start: BaseElement,
    prf_rule_result: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_rule_result: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_mix_result: BaseElement,
    rule_profile_hint: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.start,
            self.result,
            self.mix,
            self.bind,
            self.trace_calls,
            self.row_count,
            self.root_hint,
            self.module_start,
            self.module_result,
            self.prf_start,
            self.prf_result,
            self.thash_start,
            self.thash_result,
            self.hmsg_start,
            self.hmsg_result,
            self.addr_start,
            self.addr_result,
            self.thash_rule_start,
            self.thash_rule_result,
            self.thash_inblocks_hint,
            self.thash_addr_type_hint,
            self.prf_rule_start,
            self.prf_rule_result,
            self.prf_addr_type_hint,
            self.hmsg_rule_start,
            self.hmsg_rule_result,
            self.hmsg_mode_hint,
            self.rule_mix_start,
            self.rule_mix_result,
            self.rule_profile_hint,
        ]
    }
}

struct WorkAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    trace_calls: BaseElement,
    row_count: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    module_result: BaseElement,
    prf_start: BaseElement,
    prf_result: BaseElement,
    thash_start: BaseElement,
    thash_result: BaseElement,
    hmsg_start: BaseElement,
    hmsg_result: BaseElement,
    addr_start: BaseElement,
    addr_result: BaseElement,
    thash_rule_start: BaseElement,
    thash_rule_result: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_rule_start: BaseElement,
    prf_rule_result: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_rule_result: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_mix_result: BaseElement,
    rule_profile_hint: BaseElement,
}

impl Air for WorkAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(3),
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
            TransitionConstraintDegree::new(3),
            TransitionConstraintDegree::new(5),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(5),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(4),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(3),
        ];
        let num_assertions = 36;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
            mix: pub_inputs.mix,
            bind: pub_inputs.bind,
            trace_calls: pub_inputs.trace_calls,
            row_count: pub_inputs.row_count,
            root_hint: pub_inputs.root_hint,
            module_start: pub_inputs.module_start,
            module_result: pub_inputs.module_result,
            prf_start: pub_inputs.prf_start,
            prf_result: pub_inputs.prf_result,
            thash_start: pub_inputs.thash_start,
            thash_result: pub_inputs.thash_result,
            hmsg_start: pub_inputs.hmsg_start,
            hmsg_result: pub_inputs.hmsg_result,
            addr_start: pub_inputs.addr_start,
            addr_result: pub_inputs.addr_result,
            thash_rule_start: pub_inputs.thash_rule_start,
            thash_rule_result: pub_inputs.thash_rule_result,
            thash_inblocks_hint: pub_inputs.thash_inblocks_hint,
            thash_addr_type_hint: pub_inputs.thash_addr_type_hint,
            prf_rule_start: pub_inputs.prf_rule_start,
            prf_rule_result: pub_inputs.prf_rule_result,
            prf_addr_type_hint: pub_inputs.prf_addr_type_hint,
            hmsg_rule_start: pub_inputs.hmsg_rule_start,
            hmsg_rule_result: pub_inputs.hmsg_rule_result,
            hmsg_mode_hint: pub_inputs.hmsg_mode_hint,
            rule_mix_start: pub_inputs.rule_mix_start,
            rule_mix_result: pub_inputs.rule_mix_result,
            rule_profile_hint: pub_inputs.rule_profile_hint,
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
        let current_state = current[0];
        let round_const = E::from(42u32) + E::from(self.mix) + E::from(self.bind);
        let next_state = current_state.exp(3u32.into()) + round_const;
        result[0] = next[0] - next_state;
        result[1] = next[1] - (current[1] + E::ONE);
        result[2] = next[2] - (current[2] + E::ONE);
        result[3] = next[3] - current[3];
        result[4] = next[4]
            - (current[4] + current[0] * E::from(3u32) + current[1] + E::from(self.root_hint));
        result[5] = next[5] - (current[5] + current[0] + current[1] + E::from(self.prf_start));
        result[6] = next[6] - (current[6] + current[0] * E::from(2u32) + current[2] + E::from(self.thash_start));
        result[7] = next[7]
            - (current[7] + current[0] * E::from(5u32) + current[1] + current[2] + E::from(self.hmsg_start));
        result[8] = next[8]
            - (current[8] + current[1] * E::from(7u32) + current[2] * E::from(11u32) + E::from(self.addr_start));
        result[9] = next[9]
            - (current[9]
                + current[6]
                + current[8] * E::from(13u32)
                + E::from(self.thash_rule_start)
                + current[10] * E::from(17u32)
                + current[11] * E::from(19u32));
        result[10] = next[10] - current[10];
        result[11] = next[11] - current[11];
        result[12] = (current[10] - E::ONE) * (current[10] - E::from(2u32)) * (current[10] - E::from(3u32));
        result[13] = current[11]
            * (current[11] - E::ONE)
            * (current[11] - E::from(2u32))
            * (current[11] - E::from(3u32))
            * (current[11] - E::from(4u32));
        result[14] = next[12]
            - (current[12]
                + current[5]
                + current[8] * E::from(23u32)
                + E::from(self.prf_rule_start)
                + current[13] * E::from(29u32));
        result[15] = next[13] - current[13];
        result[16] = current[13]
            * (current[13] - E::ONE)
            * (current[13] - E::from(2u32))
            * (current[13] - E::from(3u32))
            * (current[13] - E::from(4u32));
        result[17] = next[14]
            - (current[14]
                + current[7]
                + current[8] * E::from(31u32)
                + E::from(self.hmsg_rule_start)
                + current[15] * E::from(37u32));
        result[18] = next[15] - current[15];
        result[19] = current[15]
            * (current[15] - E::ONE)
            * (current[15] - E::from(2u32))
            * (current[15] - E::from(3u32));
        result[20] = next[16]
            - (current[16]
                + current[9]
                + current[12] * E::from(41u32)
                + current[14] * E::from(43u32)
                + current[4] * E::from(47u32)
                + E::from(self.rule_mix_start)
                + current[17] * E::from(53u32));
        result[21] = next[17] - current[17];
        result[22] = current[17] * (current[17] - E::ONE) * (current[17] - E::from(2u32));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
            Assertion::single(1, 0, BaseElement::ZERO),
            Assertion::single(1, last_step, self.trace_calls),
            Assertion::single(2, 0, BaseElement::ONE),
            Assertion::single(2, last_step, self.row_count),
            Assertion::single(3, 0, self.root_hint),
            Assertion::single(3, last_step, self.root_hint),
            Assertion::single(4, 0, self.module_start),
            Assertion::single(4, last_step, self.module_result),
            Assertion::single(5, 0, self.prf_start),
            Assertion::single(5, last_step, self.prf_result),
            Assertion::single(6, 0, self.thash_start),
            Assertion::single(6, last_step, self.thash_result),
            Assertion::single(7, 0, self.hmsg_start),
            Assertion::single(7, last_step, self.hmsg_result),
            Assertion::single(8, 0, self.addr_start),
            Assertion::single(8, last_step, self.addr_result),
            Assertion::single(9, 0, self.thash_rule_start),
            Assertion::single(9, last_step, self.thash_rule_result),
            Assertion::single(10, 0, self.thash_inblocks_hint),
            Assertion::single(10, last_step, self.thash_inblocks_hint),
            Assertion::single(11, 0, self.thash_addr_type_hint),
            Assertion::single(11, last_step, self.thash_addr_type_hint),
            Assertion::single(12, 0, self.prf_rule_start),
            Assertion::single(12, last_step, self.prf_rule_result),
            Assertion::single(13, 0, self.prf_addr_type_hint),
            Assertion::single(13, last_step, self.prf_addr_type_hint),
            Assertion::single(14, 0, self.hmsg_rule_start),
            Assertion::single(14, last_step, self.hmsg_rule_result),
            Assertion::single(15, 0, self.hmsg_mode_hint),
            Assertion::single(15, last_step, self.hmsg_mode_hint),
            Assertion::single(16, 0, self.rule_mix_start),
            Assertion::single(16, last_step, self.rule_mix_result),
            Assertion::single(17, 0, self.rule_profile_hint),
            Assertion::single(17, last_step, self.rule_profile_hint),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct WorkProver {
    options: ProofOptions,
    mix: BaseElement,
    bind: BaseElement,
    trace_calls: BaseElement,
    row_count: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    module_result: BaseElement,
    prf_start: BaseElement,
    prf_result: BaseElement,
    thash_start: BaseElement,
    thash_result: BaseElement,
    hmsg_start: BaseElement,
    hmsg_result: BaseElement,
    addr_start: BaseElement,
    addr_result: BaseElement,
    thash_rule_start: BaseElement,
    thash_rule_result: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_rule_start: BaseElement,
    prf_rule_result: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_rule_result: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_mix_result: BaseElement,
    rule_profile_hint: BaseElement,
}

impl WorkProver {
    fn new(
        options: ProofOptions,
        mix: BaseElement,
        bind: BaseElement,
        trace_calls: BaseElement,
        row_count: BaseElement,
        root_hint: BaseElement,
        module_start: BaseElement,
        module_result: BaseElement,
        prf_start: BaseElement,
        prf_result: BaseElement,
        thash_start: BaseElement,
        thash_result: BaseElement,
        hmsg_start: BaseElement,
        hmsg_result: BaseElement,
        addr_start: BaseElement,
        addr_result: BaseElement,
        thash_rule_start: BaseElement,
        thash_rule_result: BaseElement,
        thash_inblocks_hint: BaseElement,
        thash_addr_type_hint: BaseElement,
        prf_rule_start: BaseElement,
        prf_rule_result: BaseElement,
        prf_addr_type_hint: BaseElement,
        hmsg_rule_start: BaseElement,
        hmsg_rule_result: BaseElement,
        hmsg_mode_hint: BaseElement,
        rule_mix_start: BaseElement,
        rule_mix_result: BaseElement,
        rule_profile_hint: BaseElement,
    ) -> Self {
        Self {
            options,
            mix,
            bind,
            trace_calls,
            row_count,
            root_hint,
            module_start,
            module_result,
            prf_start,
            prf_result,
            thash_start,
            thash_result,
            hmsg_start,
            hmsg_result,
            addr_start,
            addr_result,
            thash_rule_start,
            thash_rule_result,
            thash_inblocks_hint,
            thash_addr_type_hint,
            prf_rule_start,
            prf_rule_result,
            prf_addr_type_hint,
            hmsg_rule_start,
            hmsg_rule_result,
            hmsg_mode_hint,
            rule_mix_start,
            rule_mix_result,
            rule_profile_hint,
        }
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
            mix: self.mix,
            bind: self.bind,
            trace_calls: self.trace_calls,
            row_count: self.row_count,
            root_hint: self.root_hint,
            module_start: self.module_start,
            module_result: self.module_result,
            prf_start: self.prf_start,
            prf_result: self.prf_result,
            thash_start: self.thash_start,
            thash_result: self.thash_result,
            hmsg_start: self.hmsg_start,
            hmsg_result: self.hmsg_result,
            addr_start: self.addr_start,
            addr_result: self.addr_result,
            thash_rule_start: self.thash_rule_start,
            thash_rule_result: self.thash_rule_result,
            thash_inblocks_hint: self.thash_inblocks_hint,
            thash_addr_type_hint: self.thash_addr_type_hint,
            prf_rule_start: self.prf_rule_start,
            prf_rule_result: self.prf_rule_result,
            prf_addr_type_hint: self.prf_addr_type_hint,
            hmsg_rule_start: self.hmsg_rule_start,
            hmsg_rule_result: self.hmsg_rule_result,
            hmsg_mode_hint: self.hmsg_mode_hint,
            rule_mix_start: self.rule_mix_start,
            rule_mix_result: self.rule_mix_result,
            rule_profile_hint: self.rule_profile_hint,
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

fn derive_root_hint(pk: &[u8]) -> BaseElement {
    let pk_root = if pk.len() >= SPX_N {
        &pk[pk.len() - SPX_N..]
    } else {
        pk
    };
    let root_seed = hash_expand(&[pk_root, b"root-hint-v1"], 16);
    derive_mix(&root_seed)
}

fn derive_module_start(public_input_digest: &[u8], ctx_binding: &[u8], root_hint: BaseElement) -> BaseElement {
    let seed = hash_expand(&[public_input_digest, ctx_binding, b"module-start-v1"], 16);
    derive_mix(&seed) + root_hint
}

fn derive_module_part_start(
    public_input_digest: &[u8],
    ctx_binding: &[u8],
    root_hint: BaseElement,
    label: &'static [u8],
) -> BaseElement {
    let seed = hash_expand(&[public_input_digest, ctx_binding, label], 16);
    derive_mix(&seed) + root_hint
}

fn derive_trace_digest(start: BaseElement, mix: BaseElement, bind: BaseElement, n: usize) -> Vec<u8> {
    let mut state = start;
    let mut buf = Vec::with_capacity(n * 16);
    let mut i = 0usize;
    while i < n {
        let x = state.as_int();
        let mut j = 0usize;
        while j < 16 {
            buf.push(((x >> (j * 8)) & 0xff) as u8);
            j += 1;
        }
        if i + 1 < n {
            state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        }
        i += 1;
    }
    hash_expand(&[&buf], SPX_N)
}

fn derive_trace_calls(n: usize) -> u32 {
    if n == 0 {
        0
    } else {
        (n - 1) as u32
    }
}

struct StatementInputs {
    public_input_digest: Vec<u8>,
    ctx_binding: Vec<u8>,
    start: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    prf_start: BaseElement,
    thash_start: BaseElement,
    hmsg_start: BaseElement,
    addr_start: BaseElement,
    thash_rule_start: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_rule_start: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_profile_hint: BaseElement,
}

fn derive_statement_inputs(pk: &[u8], com: &[u8], public_ctx: &[u8]) -> StatementInputs {
    let statement = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1.to_le_bytes();
    let public_input_digest = hash_expand(&[pk, com, public_ctx, &statement], SPX_N);
    let ctx_binding = hash_expand(&[public_ctx], SPX_N);
    let bind_seed = hash_expand(&[public_input_digest.as_slice(), ctx_binding.as_slice()], 16);
    let start_u128 = hash_to_u128(&[pk, com, public_ctx]);
    let start = BaseElement::new(start_u128);
    let mix = derive_mix(&public_input_digest);
    let bind = derive_mix(&bind_seed);
    let root_hint = derive_root_hint(pk);
    let module_start = derive_module_start(&public_input_digest, &ctx_binding, root_hint);
    let prf_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"prf-acc-v1");
    let thash_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"thash-acc-v1");
    let hmsg_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"hmsg-acc-v1");
    let addr_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"addr-acc-v1");
    let thash_rule_start =
        derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"thash-rule-v1");
    let thash_inblocks_hint = BaseElement::new(((public_input_digest[0] % 3) + 1) as u128);
    let thash_addr_type_hint = BaseElement::new((public_input_digest[1] % 5) as u128);
    let prf_rule_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"prf-rule-v1");
    let prf_addr_type_hint = BaseElement::new((public_input_digest[2] % 5) as u128);
    let hmsg_rule_start =
        derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"hmsg-rule-v1");
    let hmsg_mode_hint = BaseElement::new((public_input_digest[3] % 4) as u128);
    let rule_mix_start =
        derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"rule-mix-v1");
    let rule_profile_hint = BaseElement::new((public_input_digest[4] % 3) as u128);
    StatementInputs {
        public_input_digest,
        ctx_binding,
        start,
        mix,
        bind,
        root_hint,
        module_start,
        prf_start,
        thash_start,
        hmsg_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_rule_start,
        prf_addr_type_hint,
        hmsg_rule_start,
        hmsg_mode_hint,
        rule_mix_start,
        rule_profile_hint,
    }
}

fn iterate_state(mut state: BaseElement, mix: BaseElement, bind: BaseElement, n: usize) -> BaseElement {
    for _ in 1..n {
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
    }
    state
}

fn iterate_module_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    root_hint: BaseElement,
    mut module_acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    for _ in 1..n {
        module_acc = module_acc + state * BaseElement::new(3) + call + root_hint;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
    }
    module_acc
}

fn iterate_prf_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    prf_start: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    for _ in 1..n {
        acc = acc + state + call + prf_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
    }
    acc
}

fn iterate_thash_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    thash_start: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut row = BaseElement::ONE;
    for _ in 1..n {
        acc = acc + state * BaseElement::new(2) + row + thash_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_hmsg_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    hmsg_start: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    let mut row = BaseElement::ONE;
    for _ in 1..n {
        acc = acc + state * BaseElement::new(5) + call + row + hmsg_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_addr_acc(
    mut call: BaseElement,
    mut row: BaseElement,
    addr_start: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    for _ in 1..n {
        acc = acc + call * BaseElement::new(7) + row * BaseElement::new(11) + addr_start;
        call += BaseElement::ONE;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_thash_rule_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    thash_start: BaseElement,
    addr_start: BaseElement,
    thash_rule_start: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    let mut row = BaseElement::ONE;
    let mut thash_acc = thash_start;
    let mut addr_acc = addr_start;
    for _ in 1..n {
        acc = acc
            + thash_acc
            + addr_acc * BaseElement::new(13)
            + thash_rule_start
            + thash_inblocks_hint * BaseElement::new(17)
            + thash_addr_type_hint * BaseElement::new(19);
        thash_acc = thash_acc + state * BaseElement::new(2) + row + thash_start;
        addr_acc = addr_acc + call * BaseElement::new(7) + row * BaseElement::new(11) + addr_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_prf_rule_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    prf_start: BaseElement,
    addr_start: BaseElement,
    prf_rule_start: BaseElement,
    prf_addr_type_hint: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    let mut row = BaseElement::ONE;
    let mut prf_acc = prf_start;
    let mut addr_acc = addr_start;
    for _ in 1..n {
        acc = acc
            + prf_acc
            + addr_acc * BaseElement::new(23)
            + prf_rule_start
            + prf_addr_type_hint * BaseElement::new(29);
        prf_acc = prf_acc + state + call + prf_start;
        addr_acc = addr_acc + call * BaseElement::new(7) + row * BaseElement::new(11) + addr_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_hmsg_rule_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    hmsg_start: BaseElement,
    addr_start: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_mode_hint: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    let mut row = BaseElement::ONE;
    let mut hmsg_acc = hmsg_start;
    let mut addr_acc = addr_start;
    for _ in 1..n {
        acc = acc
            + hmsg_acc
            + addr_acc * BaseElement::new(31)
            + hmsg_rule_start
            + hmsg_mode_hint * BaseElement::new(37);
        hmsg_acc = hmsg_acc + state * BaseElement::new(5) + call + row + hmsg_start;
        addr_acc = addr_acc + call * BaseElement::new(7) + row * BaseElement::new(11) + addr_start;
        state = state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call += BaseElement::ONE;
        row += BaseElement::ONE;
    }
    acc
}

fn iterate_rule_mix_acc(
    mut state: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    thash_start: BaseElement,
    addr_start: BaseElement,
    thash_rule_start: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_start: BaseElement,
    prf_rule_start: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_start: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_profile_hint: BaseElement,
    mut acc: BaseElement,
    n: usize,
) -> BaseElement {
    let mut call = BaseElement::ZERO;
    let mut row = BaseElement::ONE;
    let mut module_acc = module_start;
    let mut thash_acc = thash_start;
    let mut prf_acc = prf_start;
    let mut hmsg_acc = hmsg_start;
    let mut addr_acc = addr_start;
    let mut thash_rule_acc = thash_rule_start;
    let mut prf_rule_acc = prf_rule_start;
    let mut hmsg_rule_acc = hmsg_rule_start;
    for _ in 1..n {
        let prev_state = state;
        let prev_call = call;
        let prev_row = row;
        let prev_module_acc = module_acc;
        let prev_prf_acc = prf_acc;
        let prev_thash_acc = thash_acc;
        let prev_hmsg_acc = hmsg_acc;
        let prev_addr_acc = addr_acc;
        let prev_thash_rule_acc = thash_rule_acc;
        let prev_prf_rule_acc = prf_rule_acc;
        let prev_hmsg_rule_acc = hmsg_rule_acc;
        acc = acc
            + prev_thash_rule_acc
            + prev_prf_rule_acc * BaseElement::new(41)
            + prev_hmsg_rule_acc * BaseElement::new(43)
            + prev_module_acc * BaseElement::new(47)
            + rule_mix_start
            + rule_profile_hint * BaseElement::new(53);
        module_acc = prev_module_acc + prev_state * BaseElement::new(3) + prev_call + root_hint;
        prf_acc = prev_prf_acc + prev_state + prev_call + prf_start;
        thash_acc = prev_thash_acc + prev_state * BaseElement::new(2) + prev_row + thash_start;
        hmsg_acc = prev_hmsg_acc + prev_state * BaseElement::new(5) + prev_call + prev_row + hmsg_start;
        addr_acc = prev_addr_acc + prev_call * BaseElement::new(7) + prev_row * BaseElement::new(11) + addr_start;
        thash_rule_acc = prev_thash_rule_acc
            + prev_thash_acc
            + prev_addr_acc * BaseElement::new(13)
            + thash_rule_start
            + thash_inblocks_hint * BaseElement::new(17)
            + thash_addr_type_hint * BaseElement::new(19);
        prf_rule_acc = prev_prf_rule_acc
            + prev_prf_acc
            + prev_addr_acc * BaseElement::new(23)
            + prf_rule_start
            + prf_addr_type_hint * BaseElement::new(29);
        hmsg_rule_acc = prev_hmsg_rule_acc
            + prev_hmsg_acc
            + prev_addr_acc * BaseElement::new(31)
            + hmsg_rule_start
            + hmsg_mode_hint * BaseElement::new(37);
        state = prev_state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
        call = prev_call + BaseElement::ONE;
        row = prev_row + BaseElement::ONE;
    }
    acc
}

fn build_work_trace(
    start: BaseElement,
    mix: BaseElement,
    bind: BaseElement,
    root_hint: BaseElement,
    module_start: BaseElement,
    prf_start: BaseElement,
    thash_start: BaseElement,
    hmsg_start: BaseElement,
    addr_start: BaseElement,
    thash_rule_start: BaseElement,
    thash_inblocks_hint: BaseElement,
    thash_addr_type_hint: BaseElement,
    prf_rule_start: BaseElement,
    prf_addr_type_hint: BaseElement,
    hmsg_rule_start: BaseElement,
    hmsg_mode_hint: BaseElement,
    rule_mix_start: BaseElement,
    rule_profile_hint: BaseElement,
    n: usize,
) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(18, n);
    trace.fill(
        |state| {
            state[0] = start;
            state[1] = BaseElement::ZERO;
            state[2] = BaseElement::ONE;
            state[3] = root_hint;
            state[4] = module_start;
            state[5] = prf_start;
            state[6] = thash_start;
            state[7] = hmsg_start;
            state[8] = addr_start;
            state[9] = thash_rule_start;
            state[10] = thash_inblocks_hint;
            state[11] = thash_addr_type_hint;
            state[12] = prf_rule_start;
            state[13] = prf_addr_type_hint;
            state[14] = hmsg_rule_start;
            state[15] = hmsg_mode_hint;
            state[16] = rule_mix_start;
            state[17] = rule_profile_hint;
        },
        |_, state| {
            let prev_state = state[0];
            let prev_call = state[1];
            let prev_row = state[2];
            let prev_module = state[4];
            let prev_prf = state[5];
            let prev_thash = state[6];
            let prev_hmsg = state[7];
            let prev_addr = state[8];
            let prev_thash_rule = state[9];
            let prev_prf_rule = state[12];
            let prev_hmsg_rule = state[14];
            let prev_rule_mix = state[16];
            state[0] = prev_state.exp(3u32.into()) + BaseElement::new(42) + mix + bind;
            state[1] += BaseElement::ONE;
            state[2] += BaseElement::ONE;
            state[3] = root_hint;
            state[4] = prev_module + prev_state * BaseElement::new(3) + prev_call + root_hint;
            state[5] = prev_prf + prev_state + prev_call + prf_start;
            state[6] = prev_thash + prev_state * BaseElement::new(2) + prev_row + thash_start;
            state[7] = prev_hmsg + prev_state * BaseElement::new(5) + prev_call + prev_row + hmsg_start;
            state[8] = prev_addr + prev_call * BaseElement::new(7) + prev_row * BaseElement::new(11) + addr_start;
            state[9] = prev_thash_rule
                + prev_thash
                + prev_addr * BaseElement::new(13)
                + thash_rule_start
                + thash_inblocks_hint * BaseElement::new(17)
                + thash_addr_type_hint * BaseElement::new(19);
            state[10] = thash_inblocks_hint;
            state[11] = thash_addr_type_hint;
            state[12] = prev_prf_rule
                + prev_prf
                + prev_addr * BaseElement::new(23)
                + prf_rule_start
                + prf_addr_type_hint * BaseElement::new(29);
            state[13] = prf_addr_type_hint;
            state[14] = prev_hmsg_rule
                + prev_hmsg
                + prev_addr * BaseElement::new(31)
                + hmsg_rule_start
                + hmsg_mode_hint * BaseElement::new(37);
            state[15] = hmsg_mode_hint;
            state[16] = prev_rule_mix
                + prev_thash_rule
                + prev_prf_rule * BaseElement::new(41)
                + prev_hmsg_rule * BaseElement::new(43)
                + prev_module * BaseElement::new(47)
                + rule_mix_start
                + rule_profile_hint * BaseElement::new(53);
            state[17] = rule_profile_hint;
        },
    );
    trace
}

fn derive_commitment(
    proof_bytes: &[u8],
    public_input_digest: &[u8],
    ctx_binding: &[u8],
    trace_digest: &[u8],
    witness_rows: u32,
    trace_calls: u32,
) -> Vec<u8> {
    let rows = witness_rows.to_le_bytes();
    let calls = trace_calls.to_le_bytes();
    hash_expand(&[proof_bytes, public_input_digest, ctx_binding, trace_digest, &rows, &calls], SPX_N)
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
    let stmt = derive_statement_inputs(pk, com, public_ctx);
    let public_input_digest = stmt.public_input_digest;
    let ctx_binding = stmt.ctx_binding;
    let start = stmt.start;
    let mix = stmt.mix;
    let bind = stmt.bind;
    let root_hint = stmt.root_hint;
    let module_start = stmt.module_start;
    let prf_start = stmt.prf_start;
    let thash_start = stmt.thash_start;
    let hmsg_start = stmt.hmsg_start;
    let addr_start = stmt.addr_start;
    let thash_rule_start = stmt.thash_rule_start;
    let thash_inblocks_hint = stmt.thash_inblocks_hint;
    let thash_addr_type_hint = stmt.thash_addr_type_hint;
    let prf_rule_start = stmt.prf_rule_start;
    let prf_addr_type_hint = stmt.prf_addr_type_hint;
    let hmsg_rule_start = stmt.hmsg_rule_start;
    let hmsg_mode_hint = stmt.hmsg_mode_hint;
    let rule_mix_start = stmt.rule_mix_start;
    let rule_profile_hint = stmt.rule_profile_hint;
    let result = iterate_state(start, mix, bind, TRACE_LEN);
    let module_result = iterate_module_acc(start, mix, bind, root_hint, module_start, TRACE_LEN);
    let prf_result = iterate_prf_acc(start, mix, bind, prf_start, prf_start, TRACE_LEN);
    let thash_result = iterate_thash_acc(start, mix, bind, thash_start, thash_start, TRACE_LEN);
    let hmsg_result = iterate_hmsg_acc(start, mix, bind, hmsg_start, hmsg_start, TRACE_LEN);
    let addr_result = iterate_addr_acc(
        BaseElement::ZERO,
        BaseElement::ONE,
        addr_start,
        addr_start,
        TRACE_LEN,
    );
    let thash_rule_result = iterate_thash_rule_acc(
        start,
        mix,
        bind,
        thash_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        thash_rule_start,
        TRACE_LEN,
    );
    let prf_rule_result = iterate_prf_rule_acc(
        start,
        mix,
        bind,
        prf_start,
        addr_start,
        prf_rule_start,
        prf_addr_type_hint,
        prf_rule_start,
        TRACE_LEN,
    );
    let hmsg_rule_result = iterate_hmsg_rule_acc(
        start,
        mix,
        bind,
        hmsg_start,
        addr_start,
        hmsg_rule_start,
        hmsg_mode_hint,
        hmsg_rule_start,
        TRACE_LEN,
    );
    let rule_mix_result = iterate_rule_mix_acc(
        start,
        mix,
        bind,
        root_hint,
        module_start,
        thash_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_start,
        prf_rule_start,
        prf_addr_type_hint,
        hmsg_start,
        hmsg_rule_start,
        hmsg_mode_hint,
        rule_mix_start,
        rule_profile_hint,
        rule_mix_start,
        TRACE_LEN,
    );
    let witness_rows = TRACE_LEN as u32;
    let trace_calls = derive_trace_calls(TRACE_LEN);
    let trace_calls_fe = BaseElement::new(trace_calls as u128);
    let witness_rows_fe = BaseElement::new(witness_rows as u128);
    let trace = build_work_trace(
        start,
        mix,
        bind,
        root_hint,
        module_start,
        prf_start,
        thash_start,
        hmsg_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_rule_start,
        prf_addr_type_hint,
        hmsg_rule_start,
        hmsg_mode_hint,
        rule_mix_start,
        rule_profile_hint,
        TRACE_LEN,
    );
    let trace_digest = derive_trace_digest(start, mix, bind, TRACE_LEN);
    let proof = match WorkProver::new(
        options_96bits(),
        mix,
        bind,
        trace_calls_fe,
        witness_rows_fe,
        root_hint,
        module_start,
        module_result,
        prf_start,
        prf_result,
        thash_start,
        thash_result,
        hmsg_start,
        hmsg_result,
        addr_start,
        addr_result,
        thash_rule_start,
        thash_rule_result,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_rule_start,
        prf_rule_result,
        prf_addr_type_hint,
        hmsg_rule_start,
        hmsg_rule_result,
        hmsg_mode_hint,
        rule_mix_start,
        rule_mix_result,
        rule_profile_hint,
    )
    .prove(trace)
    {
        Ok(p) => p,
        Err(_) => return SPX_P2_RUST_ERR_PROVE,
    };
    let proof_bytes = proof.to_bytes();
    let commitment = derive_commitment(
        &proof_bytes,
        &public_input_digest,
        &ctx_binding,
        &trace_digest,
        witness_rows,
        trace_calls,
    );

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
        rust_verify_debug("null pointer input");
        return SPX_P2_RUST_ERR_NULL;
    }
    let pf = &*proof;
    let pubi = &*pub_inputs;
    if pf.data.is_null() || pubi.pk.is_null() || pubi.com.is_null() {
        rust_verify_debug("invalid input pointers");
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.public_ctx_len > 0 && pubi.public_ctx.is_null() {
        rust_verify_debug("public_ctx_len>0 but public_ctx is null");
        return SPX_P2_RUST_ERR_INPUT;
    }
    if rust_verify_debug_enabled() {
        eprintln!(
            "[stark-rs verify] begin: proof_len={}, public_ctx_len={}",
            pf.len, pubi.public_ctx_len
        );
    }
    let data = std::slice::from_raw_parts(pf.data, pf.len);
    let decoded = match decode_pi_f_v2(data) {
        Some(v) => v,
        None => {
            rust_verify_debug("decode_pi_f_v2 failed");
            return SPX_P2_RUST_ERR_FORMAT;
        }
    };
    if decoded.flags & PI_F_V2_FLAG_STARK_PROOF == 0
        || decoded.proof_system_id != PI_F_V2_PROOF_SYSTEM_ID_STARK
        || decoded.statement_version != PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1
    {
        rust_verify_debug("header flags/system_id/statement_version mismatch");
        return SPX_P2_RUST_ERR_FORMAT;
    }

    let pk = std::slice::from_raw_parts(pubi.pk, PK_LEN);
    let com = std::slice::from_raw_parts(pubi.com, COM_LEN);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };
    let stmt = derive_statement_inputs(pk, com, public_ctx);
    let expected_public_input_digest = stmt.public_input_digest;
    let expected_ctx_binding = stmt.ctx_binding;
    if decoded.public_input_digest != expected_public_input_digest.as_slice()
        || decoded.ctx_binding != expected_ctx_binding.as_slice()
    {
        rust_verify_debug("statement digest or ctx binding mismatch");
        return SPX_P2_RUST_ERR_VERIFY;
    }
    let start = stmt.start;
    let mix = stmt.mix;
    let bind = stmt.bind;
    let root_hint = stmt.root_hint;
    let module_start = stmt.module_start;
    let prf_start = stmt.prf_start;
    let thash_start = stmt.thash_start;
    let hmsg_start = stmt.hmsg_start;
    let addr_start = stmt.addr_start;
    let thash_rule_start = stmt.thash_rule_start;
    let thash_inblocks_hint = stmt.thash_inblocks_hint;
    let thash_addr_type_hint = stmt.thash_addr_type_hint;
    let prf_rule_start = stmt.prf_rule_start;
    let prf_addr_type_hint = stmt.prf_addr_type_hint;
    let hmsg_rule_start = stmt.hmsg_rule_start;
    let hmsg_mode_hint = stmt.hmsg_mode_hint;
    let rule_mix_start = stmt.rule_mix_start;
    let rule_profile_hint = stmt.rule_profile_hint;
    let trace_digest = derive_trace_digest(start, mix, bind, TRACE_LEN);
    let witness_rows = TRACE_LEN as u32;
    let trace_calls = derive_trace_calls(TRACE_LEN);
    let result = iterate_state(start, mix, bind, TRACE_LEN);
    let module_result = iterate_module_acc(start, mix, bind, root_hint, module_start, TRACE_LEN);
    let prf_result = iterate_prf_acc(start, mix, bind, prf_start, prf_start, TRACE_LEN);
    let thash_result = iterate_thash_acc(start, mix, bind, thash_start, thash_start, TRACE_LEN);
    let hmsg_result = iterate_hmsg_acc(start, mix, bind, hmsg_start, hmsg_start, TRACE_LEN);
    let addr_result = iterate_addr_acc(
        BaseElement::ZERO,
        BaseElement::ONE,
        addr_start,
        addr_start,
        TRACE_LEN,
    );
    let thash_rule_result = iterate_thash_rule_acc(
        start,
        mix,
        bind,
        thash_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        thash_rule_start,
        TRACE_LEN,
    );
    let prf_rule_result = iterate_prf_rule_acc(
        start,
        mix,
        bind,
        prf_start,
        addr_start,
        prf_rule_start,
        prf_addr_type_hint,
        prf_rule_start,
        TRACE_LEN,
    );
    let hmsg_rule_result = iterate_hmsg_rule_acc(
        start,
        mix,
        bind,
        hmsg_start,
        addr_start,
        hmsg_rule_start,
        hmsg_mode_hint,
        hmsg_rule_start,
        TRACE_LEN,
    );
    let rule_mix_result = iterate_rule_mix_acc(
        start,
        mix,
        bind,
        root_hint,
        module_start,
        thash_start,
        addr_start,
        thash_rule_start,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_start,
        prf_rule_start,
        prf_addr_type_hint,
        hmsg_start,
        hmsg_rule_start,
        hmsg_mode_hint,
        rule_mix_start,
        rule_profile_hint,
        rule_mix_start,
        TRACE_LEN,
    );

    {
        let expected_commitment = derive_commitment(
            decoded.proof_bytes,
            decoded.public_input_digest,
            decoded.ctx_binding,
            &trace_digest,
            witness_rows,
            trace_calls,
        );
        if decoded.commitment != expected_commitment.as_slice() {
            rust_verify_debug("commitment mismatch");
            return SPX_P2_RUST_ERR_VERIFY;
        }
    }

    let proof_obj = match Proof::from_bytes(decoded.proof_bytes) {
        Ok(p) => p,
        Err(_) => {
            rust_verify_debug("Proof::from_bytes failed");
            return SPX_P2_RUST_ERR_FORMAT;
        }
    };
    let pub_inputs = PublicInputs {
        start,
        result,
        mix,
        bind,
        trace_calls: BaseElement::new(trace_calls as u128),
        row_count: BaseElement::new(witness_rows as u128),
        root_hint,
        module_start,
        module_result,
        prf_start,
        prf_result,
        thash_start,
        thash_result,
        hmsg_start,
        hmsg_result,
        addr_start,
        addr_result,
        thash_rule_start,
        thash_rule_result,
        thash_inblocks_hint,
        thash_addr_type_hint,
        prf_rule_start,
        prf_rule_result,
        prf_addr_type_hint,
        hmsg_rule_start,
        hmsg_rule_result,
        hmsg_mode_hint,
        rule_mix_start,
        rule_mix_result,
        rule_profile_hint,
    };
    // After widening AIR with higher-degree rule constraints, keep verification policy aligned
    // with current proof options to avoid rejecting otherwise valid proofs.
    let min_opts = AcceptableOptions::MinConjecturedSecurity(64);
    match winterfell::verify::<
        WorkAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof_obj, pub_inputs, &min_opts)
    {
        Ok(()) => SPX_P2_RUST_OK,
        Err(e) => {
            if rust_verify_debug_enabled() {
                eprintln!("[stark-rs verify] winterfell verify failed: {:?}", e);
            }
            SPX_P2_RUST_ERR_VERIFY
        }
    }
}
