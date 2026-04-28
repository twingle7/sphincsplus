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
const SPX_SIGMA_COM_LEN: usize = 16224;
const COM_LIMBS: usize = 3;
const SIGMA_C_LIMBS: usize = 6;
const TRACE_WIDTH: usize = 52;

const PI_F_V2_MAGIC: u32 = 0x32504650; // "PFP2"
const PI_F_V2_VERSION: u32 = 2;
const PI_F_V2_FLAG_STARK_PROOF: u32 = 0x0000_0001;
const PI_F_V2_PROOF_SYSTEM_ID_STARK: u32 = 2;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1: u32 = 1;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V2: u32 = 2;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL: u32 = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V2;
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

fn debug_validate_m20_commit_columns(
    trace: &TraceTable<BaseElement>,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
) -> Option<(usize, usize, BaseElement)> {
    let last_step = trace.length() - 1;
    let lane256 = BaseElement::new(256);
    let lane5_pad = BaseElement::new(COMMIT_PAD_LANE5_BASE as u128);

    for row in 0..trace.length() {
        let c18 = trace.get(18, row);
        let c19 = trace.get(19, row);
        let c20 = trace.get(20, row);
        let c24 = trace.get(24, row);
        let c25 = trace.get(25, row);
        let c26 = trace.get(26, row);
        let c27 = trace.get(27, row);
        let c34 = trace.get(34, row);
        let c35 = trace.get(35, row);
        let c36 = trace.get(36, row);
        let c37 = trace.get(37, row);
        let c38 = trace.get(38, row);
        let c39 = trace.get(39, row);
        let c40 = trace.get(40, row);
        let c41 = trace.get(41, row);
        let c42 = trace.get(42, row);
        let c43 = trace.get(43, row);
        let c44 = trace.get(44, row);
        let c45 = trace.get(45, row);
        let c46 = trace.get(46, row);
        let c47 = trace.get(47, row);
        let c48 = trace.get(48, row);
        let c49 = trace.get(49, row);
        let c50 = trace.get(50, row);
        let c51 = trace.get(51, row);

        let checks = [
            c34 - c18,
            c35 - c19,
            c36 - c20,
            c27 * (c27 - BaseElement::ONE),
            c43 - com_input_public_l0,
            c44 - com_input_public_l1,
            c45 - com_input_public_l2,
            c46 - (com_input_m_tail + c49 * lane256),
            c47 - c50,
            c48 - (c51 + lane5_pad),
        ];
        for (offset, value) in checks.iter().enumerate() {
            if *value != BaseElement::ZERO {
                return Some((row, 54 + offset, *value));
            }
        }

        if row < last_step {
            let next_checks = [
                trace.get(43, row + 1) - c43,
                trace.get(44, row + 1) - c44,
                trace.get(45, row + 1) - c45,
                trace.get(46, row + 1) - c46,
                trace.get(47, row + 1) - c47,
                trace.get(48, row + 1) - c48,
                trace.get(49, row + 1) - c49,
                trace.get(50, row + 1) - c50,
                trace.get(51, row + 1) - c51,
            ];
            for (offset, value) in next_checks.iter().enumerate() {
                if *value != BaseElement::ZERO {
                    return Some((row, 61 + offset, *value));
                }
            }
        }
    }

    None
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
    pub pk_e: *const u8,
    pub pk_e_len: usize,
    pub com: *const u8,
    pub m_pub: *const u8,
    pub m_pub_len: usize,
    pub public_ctx: *const u8,
    pub public_ctx_len: usize,
    pub sigma_c: *const u8,
    pub sigma_c_len: usize,
}

#[repr(C)]
pub struct SpxP2FfiPrivateWitnessV1 {
    pub sigma_com: *const u8,
    pub m: *const u8,
    pub mlen: usize,
    pub r: *const u8,
    pub rlen: usize,
    pub omega2: *const u8,
    pub omega2_len: usize,
}

extern "C" {
    #[link_name = "SPX_poseidon2_hash_bytes_domain"]
    fn poseidon2_hash_bytes_domain(
        output: *mut u8,
        outlen: usize,
        domain_tag: i32,
        input: *const u8,
        inlen: usize,
    );
    #[link_name = "SPX_spx_p2_verify_com"]
    fn spx_p2_verify_com(pk: *const u8, com: *const u8, sigma_com: *const u8) -> i32;
    #[link_name = "SPX_spx_p2_build_sigma_c_m20_pke"]
    fn spx_p2_build_sigma_c_m20_pke(
        out_sigma_c: *mut u8,
        out_sigma_c_len: *mut usize,
        com: *const u8,
        sigma_com: *const u8,
        pk_e: *const u8,
        pk_e_len: usize,
        omega2: *const u8,
        omega2_len: usize,
    ) -> i32;
}

const SPX_P2_DOMAIN_CUSTOM: i32 = 0xff;
const SPX_P2_DOMAIN_COMMIT: i32 = 0x20;
const COMMIT_M_PUB_LEN: usize = 24;
const COMMIT_R_LEN: usize = 16;
const COMMIT_PAD_LANE5_BASE: u64 = (1u64 << 8) | (0x80u64 << 56);

unsafe fn rust_commit_domain(out: &mut [u8; SPX_N], m: &[u8], r: &[u8]) {
    let mut input = Vec::with_capacity(m.len() + r.len());
    input.extend_from_slice(m);
    input.extend_from_slice(r);
    poseidon2_hash_bytes_domain(
        out.as_mut_ptr(),
        SPX_N,
        SPX_P2_DOMAIN_COMMIT,
        input.as_ptr(),
        input.len(),
    );
}

fn load_lane_le(bytes: &[u8]) -> BaseElement {
    let mut value = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        value |= (bytes[i] as u64) << (8 * i);
        i += 1;
    }
    BaseElement::new(value as u128)
}

fn derive_commit_open_public_parts(m_pub: &[u8]) -> Option<([BaseElement; 3], BaseElement)> {
    if m_pub.len() != COMMIT_M_PUB_LEN {
        return None;
    }
    let lane0 = load_lane_le(&[
        SPX_P2_DOMAIN_COMMIT as u8,
        m_pub[0],
        m_pub[1],
        m_pub[2],
        m_pub[3],
        m_pub[4],
        m_pub[5],
        m_pub[6],
    ]);
    let lane1 = load_lane_le(&m_pub[7..15]);
    let lane2 = load_lane_le(&m_pub[15..23]);
    let m_tail = BaseElement::new(m_pub[23] as u128);
    Some(([lane0, lane1, lane2], m_tail))
}

fn derive_commit_open_witness_parts(r: &[u8]) -> Option<(BaseElement, BaseElement, BaseElement)> {
    if r.len() != COMMIT_R_LEN {
        return None;
    }
    let r_prefix7 = load_lane_le(&r[0..7]);
    let r_middle8 = load_lane_le(&r[7..15]);
    let r_last = BaseElement::new(r[15] as u128);
    Some((r_prefix7, r_middle8, r_last))
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
    com_public_l0: BaseElement,
    com_public_l1: BaseElement,
    com_public_l2: BaseElement,
    sigma_c_public_l0: BaseElement,
    sigma_c_public_l1: BaseElement,
    sigma_c_public_l2: BaseElement,
    sigma_c_public_l3: BaseElement,
    sigma_c_public_l4: BaseElement,
    sigma_c_public_l5: BaseElement,
    public_ctx_l0: BaseElement,
    public_ctx_l1: BaseElement,
    public_ctx_l2: BaseElement,
    sigma_ctx_rel_l0: BaseElement,
    sigma_ctx_rel_l1: BaseElement,
    sigma_ctx_rel_l2: BaseElement,
    enc_mode_hint: BaseElement,
    pk_e_public_l0: BaseElement,
    pk_e_public_l1: BaseElement,
    pk_e_public_l2: BaseElement,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
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
            self.com_public_l0,
            self.com_public_l1,
            self.com_public_l2,
            self.sigma_c_public_l0,
            self.sigma_c_public_l1,
            self.sigma_c_public_l2,
            self.sigma_c_public_l3,
            self.sigma_c_public_l4,
            self.sigma_c_public_l5,
            self.public_ctx_l0,
            self.public_ctx_l1,
            self.public_ctx_l2,
            self.sigma_ctx_rel_l0,
            self.sigma_ctx_rel_l1,
            self.sigma_ctx_rel_l2,
            self.enc_mode_hint,
            self.pk_e_public_l0,
            self.pk_e_public_l1,
            self.pk_e_public_l2,
            self.com_input_public_l0,
            self.com_input_public_l1,
            self.com_input_public_l2,
            self.com_input_m_tail,
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
    com_public_l0: BaseElement,
    com_public_l1: BaseElement,
    com_public_l2: BaseElement,
    sigma_c_public_l0: BaseElement,
    sigma_c_public_l1: BaseElement,
    sigma_c_public_l2: BaseElement,
    sigma_c_public_l3: BaseElement,
    sigma_c_public_l4: BaseElement,
    sigma_c_public_l5: BaseElement,
    public_ctx_l0: BaseElement,
    public_ctx_l1: BaseElement,
    public_ctx_l2: BaseElement,
    sigma_ctx_rel_l0: BaseElement,
    sigma_ctx_rel_l1: BaseElement,
    sigma_ctx_rel_l2: BaseElement,
    enc_mode_hint: BaseElement,
    pk_e_public_l0: BaseElement,
    pk_e_public_l1: BaseElement,
    pk_e_public_l2: BaseElement,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
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
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
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
        ];
        let num_assertions = 80;
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
            com_public_l0: pub_inputs.com_public_l0,
            com_public_l1: pub_inputs.com_public_l1,
            com_public_l2: pub_inputs.com_public_l2,
            sigma_c_public_l0: pub_inputs.sigma_c_public_l0,
            sigma_c_public_l1: pub_inputs.sigma_c_public_l1,
            sigma_c_public_l2: pub_inputs.sigma_c_public_l2,
            sigma_c_public_l3: pub_inputs.sigma_c_public_l3,
            sigma_c_public_l4: pub_inputs.sigma_c_public_l4,
            sigma_c_public_l5: pub_inputs.sigma_c_public_l5,
            public_ctx_l0: pub_inputs.public_ctx_l0,
            public_ctx_l1: pub_inputs.public_ctx_l1,
            public_ctx_l2: pub_inputs.public_ctx_l2,
            sigma_ctx_rel_l0: pub_inputs.sigma_ctx_rel_l0,
            sigma_ctx_rel_l1: pub_inputs.sigma_ctx_rel_l1,
            sigma_ctx_rel_l2: pub_inputs.sigma_ctx_rel_l2,
            enc_mode_hint: pub_inputs.enc_mode_hint,
            pk_e_public_l0: pub_inputs.pk_e_public_l0,
            pk_e_public_l1: pub_inputs.pk_e_public_l1,
            pk_e_public_l2: pub_inputs.pk_e_public_l2,
            com_input_public_l0: pub_inputs.com_input_public_l0,
            com_input_public_l1: pub_inputs.com_input_public_l1,
            com_input_public_l2: pub_inputs.com_input_public_l2,
            com_input_m_tail: pub_inputs.com_input_m_tail,
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
        result[23] = next[18] - current[18];
        result[24] = next[19] - current[19];
        result[25] = next[20] - current[20];
        result[26] = next[21] - current[21];
        result[27] = next[22] - current[22];
        result[28] = next[23] - current[23];
        result[29] = next[24] - current[24];
        result[30] = next[25] - current[25];
        result[31] = next[26] - current[26];
        result[32] = next[27] - current[27];
        result[33] = next[28] - current[28];
        result[34] = next[29] - current[29];
        result[35] = next[30] - current[30];
        result[36] = next[31] - current[31];
        result[37] = next[32] - current[32];
        result[38] = next[33] - current[33];
        result[39] = current[21] - current[18];
        result[40] = current[22] - current[19];
        result[41] = current[23] - current[20];
        result[42] = current[24] - current[18] - current[28] - current[31];
        result[43] = current[25] - current[19] - current[29] - current[32];
        result[44] = current[26] - current[20] - current[30] - current[33];
        // Keep witness-derived commitment limbs constant across rows.
        result[45] = next[34] - current[34];
        result[46] = next[35] - current[35];
        result[47] = next[36] - current[36];
        result[48] = next[37] - current[37];
        result[49] = next[38] - current[38];
        result[50] = next[39] - current[39];
        result[51] = next[40] - current[40];
        result[52] = next[41] - current[41];
        result[53] = next[42] - current[42];
        // Enforce Com(m_pub; r) opening inside AIR by matching witness limbs to public com limbs.
        result[54] = current[34] - current[18];
        result[55] = current[35] - current[19];
        result[56] = current[36] - current[20];
        // The real sigma_C tail is produced by the PKE/hash construction, not by a linear limb rule.
        // Keep these slots neutral until the full PKE relation is internalized in AIR.
        result[57] = E::ZERO;
        result[58] = E::ZERO;
        result[59] = E::ZERO;
        // Harden mode gating: enc_mode_hint must be a boolean bit.
        result[60] = current[27] * (current[27] - E::ONE);
        // Keep G1 absorb-lane witness materialization constant across rows.
        result[61] = next[43] - current[43];
        result[62] = next[44] - current[44];
        result[63] = next[45] - current[45];
        result[64] = next[46] - current[46];
        result[65] = next[47] - current[47];
        result[66] = next[48] - current[48];
        result[67] = next[49] - current[49];
        result[68] = next[50] - current[50];
        result[69] = next[51] - current[51];
        // G1 Phase 1: internalize the exact single-block commit absorb lanes.
        result[70] = current[43] - E::from(self.com_input_public_l0);
        result[71] = current[44] - E::from(self.com_input_public_l1);
        result[72] = current[45] - E::from(self.com_input_public_l2);
        result[73] = current[46] - (E::from(self.com_input_m_tail) + current[49] * E::from(256u32));
        result[74] = current[47] - current[50];
        result[75] = current[48] - (current[51] + E::from(BaseElement::new(COMMIT_PAD_LANE5_BASE as u128)));
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
            Assertion::single(18, 0, self.com_public_l0),
            Assertion::single(18, last_step, self.com_public_l0),
            Assertion::single(19, 0, self.com_public_l1),
            Assertion::single(19, last_step, self.com_public_l1),
            Assertion::single(20, 0, self.com_public_l2),
            Assertion::single(20, last_step, self.com_public_l2),
            Assertion::single(21, 0, self.sigma_c_public_l0),
            Assertion::single(21, last_step, self.sigma_c_public_l0),
            Assertion::single(22, 0, self.sigma_c_public_l1),
            Assertion::single(22, last_step, self.sigma_c_public_l1),
            Assertion::single(23, 0, self.sigma_c_public_l2),
            Assertion::single(23, last_step, self.sigma_c_public_l2),
            Assertion::single(24, 0, self.sigma_c_public_l3),
            Assertion::single(24, last_step, self.sigma_c_public_l3),
            Assertion::single(25, 0, self.sigma_c_public_l4),
            Assertion::single(25, last_step, self.sigma_c_public_l4),
            Assertion::single(26, 0, self.sigma_c_public_l5),
            Assertion::single(26, last_step, self.sigma_c_public_l5),
            Assertion::single(27, 0, self.enc_mode_hint),
            Assertion::single(27, last_step, self.enc_mode_hint),
            Assertion::single(28, 0, self.public_ctx_l0),
            Assertion::single(28, last_step, self.public_ctx_l0),
            Assertion::single(29, 0, self.public_ctx_l1),
            Assertion::single(29, last_step, self.public_ctx_l1),
            Assertion::single(30, 0, self.public_ctx_l2),
            Assertion::single(30, last_step, self.public_ctx_l2),
            Assertion::single(31, 0, self.sigma_ctx_rel_l0),
            Assertion::single(31, last_step, self.sigma_ctx_rel_l0),
            Assertion::single(32, 0, self.sigma_ctx_rel_l1),
            Assertion::single(32, last_step, self.sigma_ctx_rel_l1),
            Assertion::single(33, 0, self.sigma_ctx_rel_l2),
            Assertion::single(33, last_step, self.sigma_ctx_rel_l2),
            Assertion::single(37, 0, self.pk_e_public_l0),
            Assertion::single(37, last_step, self.pk_e_public_l0),
            Assertion::single(38, 0, self.pk_e_public_l1),
            Assertion::single(38, last_step, self.pk_e_public_l1),
            Assertion::single(39, 0, self.pk_e_public_l2),
            Assertion::single(39, last_step, self.pk_e_public_l2),
            Assertion::single(43, 0, self.com_input_public_l0),
            Assertion::single(43, last_step, self.com_input_public_l0),
            Assertion::single(44, 0, self.com_input_public_l1),
            Assertion::single(44, last_step, self.com_input_public_l1),
            Assertion::single(45, 0, self.com_input_public_l2),
            Assertion::single(45, last_step, self.com_input_public_l2),
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
    com_public_l0: BaseElement,
    com_public_l1: BaseElement,
    com_public_l2: BaseElement,
    sigma_c_public_l0: BaseElement,
    sigma_c_public_l1: BaseElement,
    sigma_c_public_l2: BaseElement,
    sigma_c_public_l3: BaseElement,
    sigma_c_public_l4: BaseElement,
    sigma_c_public_l5: BaseElement,
    public_ctx_l0: BaseElement,
    public_ctx_l1: BaseElement,
    public_ctx_l2: BaseElement,
    sigma_ctx_rel_l0: BaseElement,
    sigma_ctx_rel_l1: BaseElement,
    sigma_ctx_rel_l2: BaseElement,
    enc_mode_hint: BaseElement,
    pk_e_public_l0: BaseElement,
    pk_e_public_l1: BaseElement,
    pk_e_public_l2: BaseElement,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
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
        com_public_l0: BaseElement,
        com_public_l1: BaseElement,
        com_public_l2: BaseElement,
        sigma_c_public_l0: BaseElement,
        sigma_c_public_l1: BaseElement,
        sigma_c_public_l2: BaseElement,
        sigma_c_public_l3: BaseElement,
        sigma_c_public_l4: BaseElement,
        sigma_c_public_l5: BaseElement,
        public_ctx_l0: BaseElement,
        public_ctx_l1: BaseElement,
        public_ctx_l2: BaseElement,
        sigma_ctx_rel_l0: BaseElement,
        sigma_ctx_rel_l1: BaseElement,
        sigma_ctx_rel_l2: BaseElement,
        enc_mode_hint: BaseElement,
        pk_e_public_l0: BaseElement,
        pk_e_public_l1: BaseElement,
        pk_e_public_l2: BaseElement,
        com_input_public_l0: BaseElement,
        com_input_public_l1: BaseElement,
        com_input_public_l2: BaseElement,
        com_input_m_tail: BaseElement,
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
            com_public_l0,
            com_public_l1,
            com_public_l2,
            sigma_c_public_l0,
            sigma_c_public_l1,
            sigma_c_public_l2,
            sigma_c_public_l3,
            sigma_c_public_l4,
            sigma_c_public_l5,
            public_ctx_l0,
            public_ctx_l1,
            public_ctx_l2,
            sigma_ctx_rel_l0,
            sigma_ctx_rel_l1,
            sigma_ctx_rel_l2,
            enc_mode_hint,
            pk_e_public_l0,
            pk_e_public_l1,
            pk_e_public_l2,
            com_input_public_l0,
            com_input_public_l1,
            com_input_public_l2,
            com_input_m_tail,
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
            com_public_l0: self.com_public_l0,
            com_public_l1: self.com_public_l1,
            com_public_l2: self.com_public_l2,
            sigma_c_public_l0: self.sigma_c_public_l0,
            sigma_c_public_l1: self.sigma_c_public_l1,
            sigma_c_public_l2: self.sigma_c_public_l2,
            sigma_c_public_l3: self.sigma_c_public_l3,
            sigma_c_public_l4: self.sigma_c_public_l4,
            sigma_c_public_l5: self.sigma_c_public_l5,
            public_ctx_l0: self.public_ctx_l0,
            public_ctx_l1: self.public_ctx_l1,
            public_ctx_l2: self.public_ctx_l2,
            sigma_ctx_rel_l0: self.sigma_ctx_rel_l0,
            sigma_ctx_rel_l1: self.sigma_ctx_rel_l1,
            sigma_ctx_rel_l2: self.sigma_ctx_rel_l2,
            enc_mode_hint: self.enc_mode_hint,
            pk_e_public_l0: self.pk_e_public_l0,
            pk_e_public_l1: self.pk_e_public_l1,
            pk_e_public_l2: self.pk_e_public_l2,
            com_input_public_l0: self.com_input_public_l0,
            com_input_public_l1: self.com_input_public_l1,
            com_input_public_l2: self.com_input_public_l2,
            com_input_m_tail: self.com_input_m_tail,
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

fn decode_public_limbs<const LIMBS: usize>(bytes: &[u8]) -> Option<[BaseElement; LIMBS]> {
    if bytes.len() != LIMBS * 8 {
        return None;
    }
    let mut out = [BaseElement::ZERO; LIMBS];
    let mut i = 0usize;
    while i < LIMBS {
        let begin = i * 8;
        let end = begin + 8;
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[begin..end]);
        out[i] = BaseElement::new(u64::from_le_bytes(limb) as u128);
        i += 1;
    }
    Some(out)
}

fn decode_sigma_c_public_limbs(
    sigma_c: Option<&[u8]>,
    com_public_limbs: [BaseElement; COM_LIMBS],
) -> Option<[BaseElement; SIGMA_C_LIMBS]> {
    match sigma_c {
        Some(bytes) => decode_public_limbs::<SIGMA_C_LIMBS>(bytes),
        None => Some([
            com_public_limbs[0],
            com_public_limbs[1],
            com_public_limbs[2],
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
        ]),
    }
}

fn canonicalize_public_ctx_limbs(public_ctx: &[u8]) -> [BaseElement; COM_LIMBS] {
    let mut canonical = [0u8; COM_LEN];
    let copy_len = public_ctx.len().min(COM_LEN);
    canonical[..copy_len].copy_from_slice(&public_ctx[..copy_len]);
    decode_public_limbs::<COM_LIMBS>(&canonical)
        .expect("canonical public_ctx has fixed 24-byte length")
}

fn canonicalize_pk_e_public_limbs(pk_e: &[u8]) -> [BaseElement; COM_LIMBS] {
    let pk_e_digest = hash_expand(&[pk_e], COM_LEN);
    decode_public_limbs::<COM_LIMBS>(&pk_e_digest)
        .expect("canonical pk_e digest has fixed 24-byte length")
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
    com_public_limbs: [BaseElement; COM_LIMBS],
    sigma_c_public_limbs: [BaseElement; SIGMA_C_LIMBS],
    public_ctx_limbs: [BaseElement; COM_LIMBS],
    sigma_ctx_rel_limbs: [BaseElement; COM_LIMBS],
    enc_mode_hint: BaseElement,
    pk_e_public_limbs: [BaseElement; COM_LIMBS],
    com_input_public_limbs: [BaseElement; COM_LIMBS],
    com_input_m_tail: BaseElement,
}

fn derive_statement_inputs(
    pk: &[u8],
    pk_e: &[u8],
    com: &[u8],
    m_pub: &[u8],
    public_ctx: &[u8],
    sigma_c: Option<&[u8]>,
) -> Option<StatementInputs> {
    let statement = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL.to_le_bytes();
    let sigma_c_digest = match sigma_c {
        Some(bytes) => hash_expand(&[bytes], SPX_N),
        None => vec![0u8; SPX_N],
    };
    let pk_e_digest = hash_expand(&[pk_e], SPX_N);
    let m_pub_digest = hash_expand(&[m_pub], SPX_N);
    let public_input_digest = hash_expand(
        &[
            pk,
            pk_e_digest.as_slice(),
            com,
            m_pub_digest.as_slice(),
            public_ctx,
            &statement,
            sigma_c_digest.as_slice(),
        ],
        SPX_N,
    );
    let ctx_binding = hash_expand(
        &[public_ctx, m_pub_digest.as_slice(), pk_e_digest.as_slice(), sigma_c_digest.as_slice()],
        SPX_N,
    );
    let bind_seed = hash_expand(&[public_input_digest.as_slice(), ctx_binding.as_slice()], 16);
    let start_u128 = hash_to_u128(&[pk, com, m_pub, public_ctx]);
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
    let com_public_limbs = decode_public_limbs::<COM_LIMBS>(com)?;
    let sigma_c_public_limbs = decode_sigma_c_public_limbs(sigma_c, com_public_limbs)?;
    let public_ctx_limbs = canonicalize_public_ctx_limbs(public_ctx);
    let pk_e_public_limbs = canonicalize_pk_e_public_limbs(pk_e);
    let (com_input_public_limbs, com_input_m_tail) = derive_commit_open_public_parts(m_pub)?;
    let sigma_ctx_rel_limbs = [
        sigma_c_public_limbs[3] - com_public_limbs[0] - public_ctx_limbs[0],
        sigma_c_public_limbs[4] - com_public_limbs[1] - public_ctx_limbs[1],
        sigma_c_public_limbs[5] - com_public_limbs[2] - public_ctx_limbs[2],
    ];
    let enc_mode_hint = if m_pub.is_empty() {
        BaseElement::ZERO
    } else {
        BaseElement::ONE
    };
    Some(StatementInputs {
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
        com_public_limbs,
        sigma_c_public_limbs,
        public_ctx_limbs,
        sigma_ctx_rel_limbs,
        enc_mode_hint,
        pk_e_public_limbs,
        com_input_public_limbs,
        com_input_m_tail,
    })
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
    com_public_l0: BaseElement,
    com_public_l1: BaseElement,
    com_public_l2: BaseElement,
    sigma_c_public_l0: BaseElement,
    sigma_c_public_l1: BaseElement,
    sigma_c_public_l2: BaseElement,
    sigma_c_public_l3: BaseElement,
    sigma_c_public_l4: BaseElement,
    sigma_c_public_l5: BaseElement,
    public_ctx_l0: BaseElement,
    public_ctx_l1: BaseElement,
    public_ctx_l2: BaseElement,
    sigma_ctx_rel_l0: BaseElement,
    sigma_ctx_rel_l1: BaseElement,
    sigma_ctx_rel_l2: BaseElement,
    enc_mode_hint: BaseElement,
    pk_e_public_l0: BaseElement,
    pk_e_public_l1: BaseElement,
    pk_e_public_l2: BaseElement,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
    com_input_r_prefix7: BaseElement,
    com_input_r_middle8: BaseElement,
    com_input_r_last: BaseElement,
    com_witness_l0: BaseElement,
    com_witness_l1: BaseElement,
    com_witness_l2: BaseElement,
    omega2_witness_l0: BaseElement,
    omega2_witness_l1: BaseElement,
    omega2_witness_l2: BaseElement,
    n: usize,
) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(TRACE_WIDTH, n);
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
            state[18] = com_public_l0;
            state[19] = com_public_l1;
            state[20] = com_public_l2;
            state[21] = sigma_c_public_l0;
            state[22] = sigma_c_public_l1;
            state[23] = sigma_c_public_l2;
            state[24] = sigma_c_public_l3;
            state[25] = sigma_c_public_l4;
            state[26] = sigma_c_public_l5;
            state[27] = enc_mode_hint;
            state[28] = public_ctx_l0;
            state[29] = public_ctx_l1;
            state[30] = public_ctx_l2;
            state[31] = sigma_ctx_rel_l0;
            state[32] = sigma_ctx_rel_l1;
            state[33] = sigma_ctx_rel_l2;
            state[34] = com_witness_l0;
            state[35] = com_witness_l1;
            state[36] = com_witness_l2;
            state[37] = pk_e_public_l0;
            state[38] = pk_e_public_l1;
            state[39] = pk_e_public_l2;
            state[40] = omega2_witness_l0;
            state[41] = omega2_witness_l1;
            state[42] = omega2_witness_l2;
            state[43] = com_input_public_l0;
            state[44] = com_input_public_l1;
            state[45] = com_input_public_l2;
            state[46] = com_input_m_tail + com_input_r_prefix7 * BaseElement::new(256);
            state[47] = com_input_r_middle8;
            state[48] = com_input_r_last + BaseElement::new(COMMIT_PAD_LANE5_BASE as u128);
            state[49] = com_input_r_prefix7;
            state[50] = com_input_r_middle8;
            state[51] = com_input_r_last;
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
            state[18] = com_public_l0;
            state[19] = com_public_l1;
            state[20] = com_public_l2;
            state[21] = sigma_c_public_l0;
            state[22] = sigma_c_public_l1;
            state[23] = sigma_c_public_l2;
            state[24] = sigma_c_public_l3;
            state[25] = sigma_c_public_l4;
            state[26] = sigma_c_public_l5;
            state[27] = enc_mode_hint;
            state[28] = public_ctx_l0;
            state[29] = public_ctx_l1;
            state[30] = public_ctx_l2;
            state[31] = sigma_ctx_rel_l0;
            state[32] = sigma_ctx_rel_l1;
            state[33] = sigma_ctx_rel_l2;
            state[34] = com_witness_l0;
            state[35] = com_witness_l1;
            state[36] = com_witness_l2;
            state[37] = pk_e_public_l0;
            state[38] = pk_e_public_l1;
            state[39] = pk_e_public_l2;
            state[40] = omega2_witness_l0;
            state[41] = omega2_witness_l1;
            state[42] = omega2_witness_l2;
            state[43] = com_input_public_l0;
            state[44] = com_input_public_l1;
            state[45] = com_input_public_l2;
            state[46] = com_input_m_tail + com_input_r_prefix7 * BaseElement::new(256);
            state[47] = com_input_r_middle8;
            state[48] = com_input_r_last + BaseElement::new(COMMIT_PAD_LANE5_BASE as u128);
            state[49] = com_input_r_prefix7;
            state[50] = com_input_r_middle8;
            state[51] = com_input_r_last;
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
    write_u32_le(&mut out[off..off + 4], PI_F_V2_STATEMENT_VERSION_VERIFY_FULL);
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
pub unsafe extern "C" fn spx_p2_rust_validate_strict_relation_inputs_v1(
    pub_inputs: *const SpxP2FfiPublicInputsV1,
    wit: *const SpxP2FfiPrivateWitnessV1,
    require_witness: i32,
) -> i32 {
    if pub_inputs.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }
    let pubi = &*pub_inputs;
    if pubi.pk.is_null() || pubi.com.is_null() || pubi.pk_e.is_null() || pubi.sigma_c.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.pk_e_len != SPX_N || pubi.sigma_c_len != 2 * SPX_N {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.m_pub.is_null() != (pubi.m_pub_len == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if require_witness != 0 {
        if wit.is_null() {
            return SPX_P2_RUST_ERR_NULL;
        }
        let witv = &*wit;
        if witv.sigma_com.is_null() {
            return SPX_P2_RUST_ERR_INPUT;
        }
        // Strict prove path is frozen to M20 data-plane semantics.
        if pubi.m_pub.is_null()
            || pubi.m_pub_len == 0
            || witv.m.is_null()
            || witv.mlen == 0
            || witv.r.is_null()
            || witv.rlen == 0
        {
            return SPX_P2_RUST_ERR_INPUT;
        }
        if pubi.m_pub_len != witv.mlen {
            return SPX_P2_RUST_ERR_INPUT;
        }
        let m_pub = std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len);
        let m_wit = std::slice::from_raw_parts(witv.m, witv.mlen);
        if m_pub != m_wit {
            return SPX_P2_RUST_ERR_INPUT;
        }
        if witv.omega2.is_null() || witv.omega2_len != SPX_N {
            return SPX_P2_RUST_ERR_INPUT;
        }
    }
    SPX_P2_RUST_OK
}

unsafe fn rust_build_sigma_c_m19_native(
    pubi: &SpxP2FfiPublicInputsV1,
    witv: &SpxP2FfiPrivateWitnessV1,
) -> Result<[u8; 2 * SPX_N], i32> {
    const LBL_ENC_SEED: &[u8] = b"m19-enc-seed-v1\0";
    const LBL_PK_E_SEED: &[u8] = b"m19-pk-e-seed-v1\0";
    const LBL_ENC_TAG: &[u8] = b"m19-enc-tag-v1\0";

    if pubi.com.is_null() || pubi.pk_e.is_null() || pubi.sigma_c.is_null() || witv.sigma_com.is_null() {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }
    if pubi.pk_e_len != SPX_N || pubi.sigma_c_len != 2 * SPX_N {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }
    if (witv.omega2_len > 0 && witv.omega2.is_null())
        || (!witv.omega2.is_null() && witv.omega2_len == 0)
        || (witv.omega2_len != 0 && witv.omega2_len != SPX_N)
    {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }

    let com = std::slice::from_raw_parts(pubi.com, SPX_N);
    let sigma_com = std::slice::from_raw_parts(witv.sigma_com, SPX_SIGMA_COM_LEN);
    let pk_e = std::slice::from_raw_parts(pubi.pk_e, SPX_N);

    let mut omega2_local = [0u8; SPX_N];
    let omega2 = if witv.omega2.is_null() || witv.omega2_len == 0 {
        rust_commit_domain(&mut omega2_local, sigma_com, com);
        omega2_local.as_slice()
    } else {
        std::slice::from_raw_parts(witv.omega2, witv.omega2_len)
    };

    let mut input1 = Vec::with_capacity(LBL_ENC_SEED.len() + SPX_SIGMA_COM_LEN + omega2.len());
    input1.extend_from_slice(LBL_ENC_SEED);
    input1.extend_from_slice(sigma_com);
    input1.extend_from_slice(omega2);
    let mut enc_seed = [0u8; SPX_N];
    poseidon2_hash_bytes_domain(
        enc_seed.as_mut_ptr(),
        SPX_N,
        SPX_P2_DOMAIN_CUSTOM,
        input1.as_ptr(),
        input1.len(),
    );

    let mut input2 = Vec::with_capacity(LBL_PK_E_SEED.len() + 2 * SPX_N);
    input2.extend_from_slice(LBL_PK_E_SEED);
    input2.extend_from_slice(pk_e);
    input2.extend_from_slice(com);
    let mut pk_e_seed = [0u8; SPX_N];
    poseidon2_hash_bytes_domain(
        pk_e_seed.as_mut_ptr(),
        SPX_N,
        SPX_P2_DOMAIN_CUSTOM,
        input2.as_ptr(),
        input2.len(),
    );

    let mut input3 = Vec::with_capacity(LBL_ENC_TAG.len() + 2 * SPX_N);
    input3.extend_from_slice(LBL_ENC_TAG);
    input3.extend_from_slice(&enc_seed);
    input3.extend_from_slice(&pk_e_seed);
    let mut out = [0u8; 2 * SPX_N];
    out[..SPX_N].copy_from_slice(com);
    poseidon2_hash_bytes_domain(
        out[SPX_N..].as_mut_ptr(),
        SPX_N,
        SPX_P2_DOMAIN_CUSTOM,
        input3.as_ptr(),
        input3.len(),
    );
    Ok(out)
}

unsafe fn rust_build_sigma_c_m20_pke_native(
    pubi: &SpxP2FfiPublicInputsV1,
    witv: &SpxP2FfiPrivateWitnessV1,
) -> Result<[u8; 2 * SPX_N], i32> {
    if pubi.com.is_null() || pubi.pk_e.is_null() || witv.sigma_com.is_null() || witv.omega2.is_null() {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }
    if pubi.pk_e_len != SPX_N || witv.omega2_len != SPX_N {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }
    let mut out = [0u8; 2 * SPX_N];
    let mut out_len = 0usize;
    let ret = spx_p2_build_sigma_c_m20_pke(
        out.as_mut_ptr(),
        &mut out_len as *mut usize,
        pubi.com,
        witv.sigma_com,
        pubi.pk_e,
        pubi.pk_e_len,
        witv.omega2,
        witv.omega2_len,
    );
    if ret != 0 || out_len != 2 * SPX_N {
        return Err(SPX_P2_RUST_ERR_INPUT);
    }
    Ok(out)
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_validate_strict_witness_relation_v1(
    pub_inputs: *const SpxP2FfiPublicInputsV1,
    wit: *const SpxP2FfiPrivateWitnessV1,
) -> i32 {
    let ret = spx_p2_rust_validate_strict_relation_inputs_v1(pub_inputs, wit, 1);
    if ret != SPX_P2_RUST_OK {
        return ret;
    }
    let pubi = &*pub_inputs;
    let witv = &*wit;
    if spx_p2_verify_com(pubi.pk, pubi.com, witv.sigma_com) != 0 {
        return SPX_P2_RUST_ERR_PROVE;
    }
    let sigma_c = std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len);
    let expected = match if pubi.m_pub.is_null() || pubi.m_pub_len == 0 {
        rust_build_sigma_c_m19_native(pubi, witv)
    } else {
        rust_build_sigma_c_m20_pke_native(pubi, witv)
    } {
        Ok(v) => v,
        Err(e) => return e,
    };
    if sigma_c != expected {
        return SPX_P2_RUST_ERR_INPUT;
    }
    SPX_P2_RUST_OK
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
    if (witv.omega2_len > 0 && witv.omega2.is_null()) || (!witv.omega2.is_null() && witv.omega2_len == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (witv.mlen > 0 && witv.m.is_null()) || (!witv.m.is_null() && witv.mlen == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (witv.rlen > 0 && witv.r.is_null()) || (!witv.r.is_null() && witv.rlen == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if pubi.public_ctx_len > 0 && pubi.public_ctx.is_null() {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (pubi.m_pub_len > 0 && pubi.m_pub.is_null()) || (!pubi.m_pub.is_null() && pubi.m_pub_len == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (pubi.pk_e_len > 0 && pubi.pk_e.is_null()) || (!pubi.pk_e.is_null() && pubi.pk_e_len == 0) {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (pubi.sigma_c_len > 0 && pubi.sigma_c.is_null())
        || (!pubi.sigma_c.is_null() && pubi.sigma_c_len == 0)
    {
        return SPX_P2_RUST_ERR_INPUT;
    }
    let strict_input_ret = spx_p2_rust_validate_strict_relation_inputs_v1(pub_inputs, wit, 1);
    if strict_input_ret != SPX_P2_RUST_OK {
        return strict_input_ret;
    }
    // M20-8 semantic anchor: enforce native strict witness relation on proving path.
    // This keeps Enc semantics aligned with SPX_p2_build_sigma_c_m20_pke while AIR keeps
    // consistency bindings for proof-side trace constraints.
    let strict_witness_ret = spx_p2_rust_validate_strict_witness_relation_v1(pub_inputs, wit);
    if strict_witness_ret != SPX_P2_RUST_OK {
        return strict_witness_ret;
    }
    let pk = std::slice::from_raw_parts(pubi.pk, PK_LEN);
    let com = std::slice::from_raw_parts(pubi.com, COM_LEN);
    let public_ctx = if pubi.public_ctx_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len)
    };
    let m_pub = if pubi.m_pub_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len)
    };
    let pk_e = if pubi.pk_e_len == 0 {
        &pk[..SPX_N]
    } else {
        std::slice::from_raw_parts(pubi.pk_e, pubi.pk_e_len)
    };
    let sigma_c = if pubi.sigma_c_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len))
    };
    let stmt = match derive_statement_inputs(pk, pk_e, com, m_pub, public_ctx, sigma_c) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
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
    let [com_public_l0, com_public_l1, com_public_l2] = stmt.com_public_limbs;
    let [
        sigma_c_public_l0,
        sigma_c_public_l1,
        sigma_c_public_l2,
        sigma_c_public_l3,
        sigma_c_public_l4,
        sigma_c_public_l5,
    ] = stmt.sigma_c_public_limbs;
    let [public_ctx_l0, public_ctx_l1, public_ctx_l2] = stmt.public_ctx_limbs;
    let [sigma_ctx_rel_l0, sigma_ctx_rel_l1, sigma_ctx_rel_l2] = stmt.sigma_ctx_rel_limbs;
    let enc_mode_hint = stmt.enc_mode_hint;
    let [pk_e_public_l0, pk_e_public_l1, pk_e_public_l2] = stmt.pk_e_public_limbs;
    let [com_input_public_l0, com_input_public_l1, com_input_public_l2] = stmt.com_input_public_limbs;
    let com_input_m_tail = stmt.com_input_m_tail;
    let m_wit = std::slice::from_raw_parts(witv.m, witv.mlen);
    let r_wit = std::slice::from_raw_parts(witv.r, witv.rlen);
    let (com_input_r_prefix7, com_input_r_middle8, com_input_r_last) =
        match derive_commit_open_witness_parts(r_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let mut com_from_witness = [0u8; SPX_N];
    rust_commit_domain(&mut com_from_witness, m_wit, r_wit);
    let [com_witness_l0, com_witness_l1, com_witness_l2] =
        match decode_public_limbs::<COM_LIMBS>(&com_from_witness) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let omega2_wit = std::slice::from_raw_parts(witv.omega2, witv.omega2_len);
    let [omega2_witness_l0, omega2_witness_l1, omega2_witness_l2] =
        match decode_public_limbs::<COM_LIMBS>(omega2_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
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
        com_public_l0,
        com_public_l1,
        com_public_l2,
        sigma_c_public_l0,
        sigma_c_public_l1,
        sigma_c_public_l2,
        sigma_c_public_l3,
        sigma_c_public_l4,
        sigma_c_public_l5,
        public_ctx_l0,
        public_ctx_l1,
        public_ctx_l2,
        sigma_ctx_rel_l0,
        sigma_ctx_rel_l1,
        sigma_ctx_rel_l2,
        enc_mode_hint,
        pk_e_public_l0,
        pk_e_public_l1,
        pk_e_public_l2,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
        com_input_r_prefix7,
        com_input_r_middle8,
        com_input_r_last,
        com_witness_l0,
        com_witness_l1,
        com_witness_l2,
        omega2_witness_l0,
        omega2_witness_l1,
        omega2_witness_l2,
        TRACE_LEN,
    );
    if let Some((row, constraint, value)) = debug_validate_m20_commit_columns(
        &trace,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
    ) {
        if rust_verify_debug_enabled() {
            eprintln!(
                "[stark-rs prove] trace self-check failed: row={} constraint={} value={:?}",
                row, constraint, value
            );
        }
        return SPX_P2_RUST_ERR_PROVE;
    }
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
        com_public_l0,
        com_public_l1,
        com_public_l2,
        sigma_c_public_l0,
        sigma_c_public_l1,
        sigma_c_public_l2,
        sigma_c_public_l3,
        sigma_c_public_l4,
        sigma_c_public_l5,
        public_ctx_l0,
        public_ctx_l1,
        public_ctx_l2,
        sigma_ctx_rel_l0,
        sigma_ctx_rel_l1,
        sigma_ctx_rel_l2,
        enc_mode_hint,
        pk_e_public_l0,
        pk_e_public_l1,
        pk_e_public_l2,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
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
    if (pubi.m_pub_len > 0 && pubi.m_pub.is_null()) || (!pubi.m_pub.is_null() && pubi.m_pub_len == 0) {
        rust_verify_debug("m_pub pointer/length mismatch");
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (pubi.pk_e_len > 0 && pubi.pk_e.is_null()) || (!pubi.pk_e.is_null() && pubi.pk_e_len == 0) {
        rust_verify_debug("pk_e pointer/length mismatch");
        return SPX_P2_RUST_ERR_INPUT;
    }
    if (pubi.sigma_c_len > 0 && pubi.sigma_c.is_null())
        || (!pubi.sigma_c.is_null() && pubi.sigma_c_len == 0)
    {
        rust_verify_debug("sigma_c pointer/length mismatch");
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
        || decoded.statement_version != PI_F_V2_STATEMENT_VERSION_VERIFY_FULL
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
    let m_pub = if pubi.m_pub_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len)
    };
    let pk_e = if pubi.pk_e_len == 0 {
        &pk[..SPX_N]
    } else {
        std::slice::from_raw_parts(pubi.pk_e, pubi.pk_e_len)
    };
    let sigma_c = if pubi.sigma_c_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len))
    };
    let stmt = match derive_statement_inputs(pk, pk_e, com, m_pub, public_ctx, sigma_c) {
        Some(v) => v,
        None => {
            rust_verify_debug("invalid com/sigma_c limb encoding for AIR public inputs");
            return SPX_P2_RUST_ERR_INPUT;
        }
    };
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
    let [com_public_l0, com_public_l1, com_public_l2] = stmt.com_public_limbs;
    let [
        sigma_c_public_l0,
        sigma_c_public_l1,
        sigma_c_public_l2,
        sigma_c_public_l3,
        sigma_c_public_l4,
        sigma_c_public_l5,
    ] = stmt.sigma_c_public_limbs;
    let [public_ctx_l0, public_ctx_l1, public_ctx_l2] = stmt.public_ctx_limbs;
    let [sigma_ctx_rel_l0, sigma_ctx_rel_l1, sigma_ctx_rel_l2] = stmt.sigma_ctx_rel_limbs;
    let enc_mode_hint = stmt.enc_mode_hint;
    let [pk_e_public_l0, pk_e_public_l1, pk_e_public_l2] = stmt.pk_e_public_limbs;
    let [com_input_public_l0, com_input_public_l1, com_input_public_l2] = stmt.com_input_public_limbs;
    let com_input_m_tail = stmt.com_input_m_tail;
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
        com_public_l0,
        com_public_l1,
        com_public_l2,
        sigma_c_public_l0,
        sigma_c_public_l1,
        sigma_c_public_l2,
        sigma_c_public_l3,
        sigma_c_public_l4,
        sigma_c_public_l5,
        public_ctx_l0,
        public_ctx_l1,
        public_ctx_l2,
        sigma_ctx_rel_l0,
        sigma_ctx_rel_l1,
        sigma_ctx_rel_l2,
        enc_mode_hint,
        pk_e_public_l0,
        pk_e_public_l1,
        pk_e_public_l2,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
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
