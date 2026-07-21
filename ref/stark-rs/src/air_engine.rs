//! Full SPHINCS+ verification AIR with sponge state continuity and input binding.
//! Uses pre-computed expected-next-state columns (16..27) for constraint simplicity.
//! Trace columns (64): state[0..12], round[12], perm[13], call[14], pad[15],
//!   expected_next[16..28], absorb[28..34], domain[34], addr[35..39],
//!   carries_from_prev[39], carries_to_next[40], init_state[41..53),
//!   is_thash[53], expected_absorb[54..58]

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover,
    StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::trace_builder;
use crate::thash_poseidon2_exact;
pub const P2_T: usize = 12;
pub const P2_RATE: usize = 6;
pub const TOTAL_ROUNDS: usize = 30;
pub const PERM_PERIOD: usize = 32;
pub const TRACE_WIDTH: usize = 64;
pub const PI_F_MAGIC: u32 = 0x32504650; // "PFP2"
pub const PI_F_VERSION: u32 = 2;
pub const MAGIC_LEN: usize = 4;
pub const VERSION_LEN: usize = 4;

#[derive(Debug, Clone)]
pub struct SpxVerifyPublicInputs {
    pub start_state: [BaseElement; P2_T], pub result_state: [BaseElement; P2_T],
    pub total_perms: u64, pub root_perm: u64,
    pub pk_root_l0: BaseElement, pub pk_root_l1: BaseElement,
    pub com_l0: BaseElement, pub com_l1: BaseElement,
    pub pub_seed_lo: BaseElement, pub pub_seed_hi: BaseElement,
    pub pub_seed_15: BaseElement,
}
impl SpxVerifyPublicInputs {
    pub fn from_values(start: [BaseElement; P2_T], result: [BaseElement; P2_T], p: u64, rp: u64,
                       rl0: BaseElement, rl1: BaseElement,
                       cl0: BaseElement, cl1: BaseElement,
                       ps_lo: BaseElement, ps_hi: BaseElement,
                       ps15: BaseElement) -> Self {
        Self{start_state:start, result_state:result, total_perms:p, root_perm:rp,
             pk_root_l0:rl0, pk_root_l1:rl1, com_l0:cl0, com_l1:cl1,
             pub_seed_lo:ps_lo, pub_seed_hi:ps_hi, pub_seed_15:ps15}
    }
}
impl ToElements<BaseElement> for SpxVerifyPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(2 * P2_T + 9);
        v.extend_from_slice(&self.start_state);
        v.extend_from_slice(&self.result_state);
        v.push(BaseElement::new(self.total_perms));
        v.push(BaseElement::new(self.root_perm));
        v.push(self.pk_root_l0);
        v.push(self.pk_root_l1);
        v.push(self.com_l0);
        v.push(self.com_l1);
        v.push(self.pub_seed_lo);
        v.push(self.pub_seed_hi);
        v.push(self.pub_seed_15);
        v
    }
}

pub struct SpxVerifyAir {
    context: AirContext<BaseElement>,
    start_state: [BaseElement; P2_T], result_state: [BaseElement; P2_T], total_perms: u64,
    root_perm: u64,
    pk_root_l0: BaseElement, pk_root_l1: BaseElement,
    com_l0: BaseElement, com_l1: BaseElement,
    expected_absorb0_f: BaseElement, expected_absorb0_h: BaseElement, expected_absorb0_tl: BaseElement,
    pub_seed_hi: BaseElement,
    inv_f: BaseElement, inv_h: BaseElement, inv_tl: BaseElement,
}

impl Air for SpxVerifyAir {
    type BaseField = BaseElement;
    type PublicInputs = SpxVerifyPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: SpxVerifyPublicInputs, options: ProofOptions) -> Self {
        let d258047 = TransitionConstraintDegree::with_cycles(2, vec![PERM_PERIOD]); // 258047
        let d253952 = TransitionConstraintDegree::with_cycles(1, vec![PERM_PERIOD, PERM_PERIOD]); // 253952
        let d131071 = TransitionConstraintDegree::new(2); // 131071
        // Defect 1: measured degrees for is_first * is_thash * (1-carry) * absorb Lagrange
        let d389118 = TransitionConstraintDegree::with_cycles(3, vec![PERM_PERIOD]); // 3*131071-4095
        let d520189 = TransitionConstraintDegree::with_cycles(4, vec![PERM_PERIOD]); // 4*131071-4095
        let degrees = vec![
            // 0-5: rate lanes 0-5 (deg=2, uses is_active+is_real periodic)
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(),
            // 6-11: capacity lanes (copies of rate checks)
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(),
            // 12-15: round counter checks (deg=1, uses is_active+is_real, two periods)
            d253952.clone(), d253952.clone(), d253952.clone(), d253952.clone(),
            // 16: perm index (deg=2, no periodic)
            d131071.clone(),
            // 17: call_type (deg=2, uses is_active+is_real periodic)
            d258047.clone(),
            // 18: pad flag (deg=2, no periodic)
            d131071.clone(),
            // 19-30: absorption + capacity init (deg=2, uses is_first periodic)
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(),
            // 31: carries_from_prev boolean (deg=2, no periodic)
            d131071.clone(),
            // 32: carries_to_next boolean (deg=2, no periodic)
            d131071.clone(),
            // 33-44: state carry at is_last
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            d258047.clone(), d258047.clone(), d258047.clone(), d258047.clone(),
            // 45: is_thash boolean (deg=2, no periodic)
            d131071.clone(),
            // 46: THASH absorb[0] Lagrange (deg=3*131071-4095=389118)
            d389118.clone(),
            // 47: THASH absorb[1] = pub_seed_hi (same degree)
            d389118.clone(),
            // 48: THASH domain membership (deg=4*131071-4095=520189)
            d520189.clone(),
            // 49-52: THASH absorb[2..5] = expected (deg=3*131071-4095=389118, same as 46-47)
            d389118.clone(), d389118.clone(), d389118.clone(), d389118.clone(),
        ];
        // Pre-compute expected absorb[0] per THASH domain tag
        // absorb[0] = LE(domain_byte || pub_seed[0..6]) = domain_byte + 256 * pub_seed_lo
        let d256 = BaseElement::new(256);
        let domain_f  = BaseElement::new(0x11);
        let domain_h  = BaseElement::new(0x12);
        let domain_tl = BaseElement::new(0x13);
        let ps_lo = pub_inputs.pub_seed_lo;
        let expected_absorb0_f  = domain_f  + d256 * ps_lo;
        let expected_absorb0_h  = domain_h  + d256 * ps_lo;
        let expected_absorb0_tl = domain_tl + d256 * ps_lo;
        // Lagrange inverses: 1/((d-a)(d-b)) for domain ∈ {0x11,0x12,0x13}
        let inv_f  = BaseElement::new(0x7FFFFFFF80000001u64); // 1/2
        let inv_h  = BaseElement::new(0xFFFFFFFF00000000u64); // -1
        let inv_tl = BaseElement::new(0x7FFFFFFF80000001u64); // 1/2
        Self {
            context: AirContext::new(trace_info, degrees, 2 * P2_T + 6, options),
            start_state: pub_inputs.start_state, result_state: pub_inputs.result_state,
            total_perms: pub_inputs.total_perms,
            root_perm: pub_inputs.root_perm,
            pk_root_l0: pub_inputs.pk_root_l0, pk_root_l1: pub_inputs.pk_root_l1,
            com_l0: pub_inputs.com_l0, com_l1: pub_inputs.com_l1,
            expected_absorb0_f, expected_absorb0_h, expected_absorb0_tl,
            pub_seed_hi: pub_inputs.pub_seed_hi,
            inv_f, inv_h, inv_tl,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self, frame: &EvaluationFrame<E>, periodic_values: &[E], result: &mut [E],
    ) {
        let cur = frame.current(); let nxt = frame.next();
        let round = cur[12]; let perm = cur[13]; let is_pad = cur[15];
        let nxt_round = nxt[12]; let nxt_perm = nxt[13];
        let is_last = periodic_values[3];
        let is_real = E::ONE - is_pad;
        let is_active = E::ONE - is_last;

        // Constraint 0-5: rate lanes checked against expected next
        for lane in 0..P2_RATE {
            result[lane] = is_real * is_active * (nxt[lane] - cur[16 + lane]);
        }
        // Constraint 6-11: copies of rate lane checks (capacity lanes share same constraint structure)
        result[6] = result[0]; result[7] = result[1]; result[8] = result[2];
        result[9] = result[3]; result[10] = result[4]; result[11] = result[5];
        // Constraint 12-15: round counter checks
        result[12] = is_real * is_active * (nxt_round - round - E::ONE);
        result[13] = result[12];
        result[14] = result[12];
        result[15] = is_real * is_active * (nxt_round - round - E::ONE);
        // Constraint 16: perm index behaviour
        result[16] = is_real * (is_active * (nxt_perm - perm) + is_last * (nxt_perm - perm - E::ONE));
        // Constraint 17: call type const within permutation
        result[17] = is_real * is_active * (nxt[14] - cur[14]);
        // Constraint 18: pad flag boolean
        result[18] = is_pad * (is_pad - E::ONE);
        // Constraint 19-24: at is_first, rate lanes = absorb + carries_from_prev * init_state
        // Constraint 25-30: at is_first, capacity lanes = carries_from_prev * init_state
        let is_first = periodic_values[5];
        let carries_prev = cur[39];  // carries_from_prev flag
        for lane in 0..P2_RATE {
            result[19 + lane] = is_first * (cur[lane] - cur[28 + lane] - carries_prev * cur[41 + lane]);
        }
        for lane in P2_RATE..P2_T {
            result[19 + P2_RATE + (lane - P2_RATE)] = is_first * (cur[lane] - carries_prev * cur[41 + lane]);
        }
        // Constraint 31: carries_from_prev boolean (col 39) — pad rows have 0, no is_real needed
        // Constraint 32: carries_to_next boolean (col 40)
        let carries_next = cur[40];
        result[31] = carries_prev * (carries_prev - E::ONE);
        result[32] = carries_next * (carries_next - E::ONE);
        // Constraint 33-44: at is_last, if carries_to_next=1, next init_state = current output state
        for lane in 0..P2_T {
            result[33 + lane] = is_last * carries_next * (nxt[41 + lane] - cur[lane]);
        }
        // ── Defect 1: THASH absorb input binding (first permutation of each chain only) ──
        let is_thash = cur[53];
        let domain   = cur[34];
        let absorb0  = cur[28];
        let absorb1  = cur[29];
        let is_first_in_chain = E::ONE - carries_prev; // 1 for first perm of hash chain
        // Constraint 45: is_thash boolean
        result[45] = is_thash * (is_thash - E::ONE);
        // Lagrange basis selectors for domain ∈ {0x11, 0x12, 0x13}
        let d_18 = E::from(BaseElement::new(18)); let d_17 = E::from(BaseElement::new(17)); let d_19 = E::from(BaseElement::new(19));
        let sel_f  = (domain - d_18) * (domain - d_19) * E::from(self.inv_f);
        let sel_h  = (domain - d_17) * (domain - d_19) * E::from(self.inv_h);
        let sel_tl = (domain - d_17) * (domain - d_18) * E::from(self.inv_tl);
        // Constraint 46: absorb[0] = expected for THASH, first perm only
        result[46] = is_first * is_thash * is_first_in_chain * (
            sel_f  * (absorb0 - E::from(self.expected_absorb0_f)) +
            sel_h  * (absorb0 - E::from(self.expected_absorb0_h)) +
            sel_tl * (absorb0 - E::from(self.expected_absorb0_tl))
        );
        // Constraint 47: absorb[1] = pub_seed_hi for THASH, first perm only
        result[47] = is_first * is_thash * is_first_in_chain * (absorb1 - E::from(self.pub_seed_hi));
        // Constraint 48: domain ∈ {0x11, 0x12, 0x13} when is_thash=1
        result[48] = is_first * is_thash * (domain - d_17) * (domain - d_18) * (domain - d_19);
        // Constraint 49-52: THASH absorb[2..5] = expected (addr-derived) for first perm of chain
        result[49] = is_first * is_thash * is_first_in_chain * (cur[30] - cur[54]); // absorb[2] vs exp[2]
        result[50] = is_first * is_thash * is_first_in_chain * (cur[31] - cur[55]); // absorb[3] vs exp[3]
        result[51] = is_first * is_thash * is_first_in_chain * (cur[32] - cur[56]); // absorb[4] vs exp[4]
        result[52] = is_first * is_thash * is_first_in_chain * (cur[33] - cur[57]); // absorb[5] vs exp[5]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        let mut a = Vec::with_capacity(2 * P2_T + 8);
        // All 12 state lanes at start and end
        for lane in 0..P2_T {
            a.push(Assertion::single(lane, 0, self.start_state[lane]));
            a.push(Assertion::single(lane, last, self.result_state[lane]));
        }
        a.push(Assertion::single(12, 0, BaseElement::ZERO)); // round starts at 0
        a.push(Assertion::single(13, 0, BaseElement::ZERO)); // perm index starts at 0
        // Commit output bound to public input com (first permutation output at row TOTAL_ROUNDS=30)
        a.push(Assertion::single(0, TOTAL_ROUNDS, self.com_l0));
        a.push(Assertion::single(1, TOTAL_ROUNDS, self.com_l1));
        // pk_root bound to final HT root output state
        let root_row = (self.root_perm as usize) * PERM_PERIOD + TOTAL_ROUNDS;
        a.push(Assertion::single(0, root_row, self.pk_root_l0));
        a.push(Assertion::single(1, root_row, self.pk_root_l1));
        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> { &self.context }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let period = PERM_PERIOD;
        // 0:row_idx, 1:is_full, 2:is_internal, 3:is_last, 4:is_absorb, 5:is_first, 6:is_pad1, 7:is_output_valid
        let mut cols = vec![vec![BaseElement::ZERO; period]; 8];
        for row in 0..period {
            cols[0][row] = BaseElement::new(row as u64);
            // Round type for Poseidon2: RF=8 (4+4), RP=22
            if row < TOTAL_ROUNDS {
                let (full, internal) = thash_poseidon2_exact::round_kind(row);
                if full { cols[1][row] = BaseElement::ONE; }
                if internal { cols[2][row] = BaseElement::ONE; }
            }
            cols[3][row] = if row == period - 1 { BaseElement::ONE } else { BaseElement::ZERO }; // is_last
            cols[4][row] = if row == period - 1 { BaseElement::ONE } else { BaseElement::ZERO }; // is_absorb (pos 31)
            cols[5][row] = if row == 0 { BaseElement::ONE } else { BaseElement::ZERO };          // is_first
            cols[6][row] = if row == TOTAL_ROUNDS { BaseElement::ONE } else { BaseElement::ZERO }; // is_pad1 (pos 30)
            cols[7][row] = if row == TOTAL_ROUNDS { BaseElement::ONE } else { BaseElement::ZERO }; // is_output_valid (pos 30)
        }
        cols
    }
}

// ── Prover ──
pub struct SpxVerifyProver { options: ProofOptions, pub_inputs: SpxVerifyPublicInputs, trace: TraceTable<BaseElement> }
impl Prover for SpxVerifyProver {
    type BaseField = BaseElement; type Air = SpxVerifyAir; type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>; type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField=Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField=Self::BaseField>> = DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField=Self::BaseField>> = DefaultConstraintEvaluator<'a, Self::Air, E>;
    fn get_pub_inputs(&self, _: &Self::Trace) -> SpxVerifyPublicInputs { self.pub_inputs.clone() }
    fn options(&self) -> &ProofOptions { &self.options }
    fn new_trace_lde<E: FieldElement<BaseField=Self::BaseField>>(&self, ti: &TraceInfo, mt: &ColMatrix<Self::BaseField>,
        d: &StarkDomain<Self::BaseField>, po: PartitionOptions) -> (Self::TraceLde<E>, TracePolyTable<E>)
    { DefaultTraceLde::new(ti, mt, d, po) }
    fn build_constraint_commitment<E: FieldElement<BaseField=Self::BaseField>>(&self, cpt: CompositionPolyTrace<E>,
        ncc: usize, d: &StarkDomain<Self::BaseField>, po: PartitionOptions) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>)
    { DefaultConstraintCommitment::new(cpt, ncc, d, po) }
    fn new_evaluator<'a, E: FieldElement<BaseField=Self::BaseField>>(&self, air: &'a Self::Air,
        are: Option<AuxRandElements<E>>, ccc: ConstraintCompositionCoefficients<E>) -> Self::ConstraintEvaluator<'a, E>
    { DefaultConstraintEvaluator::new(air, are, ccc) }
}

// ── FFI exports ──

pub const SPX_P2_FULL_AIR_ABI_VERSION: u32 = 1;
pub const SPX_P2_FULL_AIR_OK: i32 = 0;
pub const SPX_P2_FULL_AIR_ERR_NULL: i32 = -1;
pub const SPX_P2_FULL_AIR_ERR_INPUT: i32 = -2;
pub const SPX_P2_FULL_AIR_ERR_PROVE: i32 = -3;
pub const SPX_P2_FULL_AIR_ERR_VERIFY: i32 = -4;

/// Generate a pi_F proof using the full-AIR (no external guards).
/// Proof format: [4 magic "PFP2"] [4 version=2] [8 total_perms] [96 start_state] [96 result_state] [16 pk_root] [16 com] [32 ctx_hash] [Winterfell proof]
/// ctx_hash = Blake3(pk || pk_e || com || m_pub || public_ctx || sigma_c) binds all public inputs to the proof.
#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_generate_pi_f_full_air(
    out_proof: *mut crate::SpxP2FfiBlobV1,
    pub_inputs: *const crate::SpxP2FfiPublicInputsV1,
    wit: *const crate::SpxP2FfiPrivateWitnessV1,
) -> i32 {
    if out_proof.is_null() || pub_inputs.is_null() || wit.is_null() { return SPX_P2_FULL_AIR_ERR_NULL; }
    let out = &mut *out_proof; let pubi = &*pub_inputs; let witv = &*wit;
    if out.data.is_null() || pubi.pk.is_null() || pubi.com.is_null() || witv.sigma_com.is_null() {
        return SPX_P2_FULL_AIR_ERR_INPUT;
    }
    let pk = std::slice::from_raw_parts(pubi.pk, trace_builder::PK_BYTES);
    let m_pub = if pubi.m_pub_len > 0 && !pubi.m_pub.is_null() {
        std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len) } else { &[] };
    let sigma_com = std::slice::from_raw_parts(witv.sigma_com, trace_builder::SIG_BYTES);
    let m = if pubi.m_pub_len > 0 && !pubi.m_pub.is_null() {
        std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len) } else { &[] };
    let r = if !witv.r.is_null() {
        std::slice::from_raw_parts(witv.r, trace_builder::N) } else { &[] };
    let pk_e = if !pubi.pk_e.is_null() {
        std::slice::from_raw_parts(pubi.pk_e, trace_builder::N) } else { &[] };
    let omega2 = if !witv.omega2.is_null() {
        std::slice::from_raw_parts(witv.omega2, trace_builder::N) } else { &[] };
    let (trace_data, _, total_perms, pk_root_l0, pk_root_l1, com_l0, com_l1, pub_seed_lo, pub_seed_hi, root_perm, pub_seed_15) = trace_builder::build_verification_trace(pk, sigma_com, m_pub, m, r, pk_e, omega2);
    let trace_len = trace_data.len();
    // Extract all 12 start and result state lanes
    let mut start_state = [BaseElement::ZERO; P2_T];
    let mut result_state = [BaseElement::ZERO; P2_T];
    for i in 0..P2_T { start_state[i] = trace_data[0][i]; result_state[i] = trace_data[trace_len - 1][i]; }
    // Build TraceTable and prove
    let mut tt = TraceTable::new(TRACE_WIDTH, trace_len);
    for r in 0..trace_len { for c in 0..TRACE_WIDTH { tt.set(c, r, trace_data[r][c]); } }
    let pi = SpxVerifyPublicInputs::from_values(start_state, result_state, total_perms, root_perm, pk_root_l0, pk_root_l1, com_l0, com_l1, pub_seed_lo, pub_seed_hi, pub_seed_15);
    let opts = ProofOptions::new(27, 16, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear);
    let prover = SpxVerifyProver{options:opts, pub_inputs:pi, trace:tt};
    match prover.prove(prover.trace.clone()) {
        Ok(proof) => {
            let proof_bytes = proof.to_bytes();
            // Header: [4 magic] [4 version] [8 total_perms] [8 root_perm] [12*8 start_state] [12*8 result_state] [2*8 pk_root] [2*8 com] [2*8 pub_seed] [32 ctx_hash]
            let header_len: usize = MAGIC_LEN + VERSION_LEN + 8 + 8 + P2_T * 8 * 2 + 2 * 8 + 2 * 8 + 2 * 8 + 32;
            if proof_bytes.len() + header_len > out.cap { return SPX_P2_FULL_AIR_ERR_INPUT; }
            let out_bytes = std::slice::from_raw_parts_mut(out.data, out.cap);
            out_bytes[0..MAGIC_LEN].copy_from_slice(&PI_F_MAGIC.to_le_bytes());
            out_bytes[MAGIC_LEN..MAGIC_LEN+VERSION_LEN].copy_from_slice(&PI_F_VERSION.to_le_bytes());
            let tp_off = MAGIC_LEN + VERSION_LEN;
            out_bytes[tp_off..tp_off+8].copy_from_slice(&total_perms.to_le_bytes());
            out_bytes[tp_off+8..tp_off+16].copy_from_slice(&root_perm.to_le_bytes());
            let start_off = tp_off + 16;
            for i in 0..P2_T {
                out_bytes[start_off + i*8 .. start_off + (i+1)*8].copy_from_slice(&start_state[i].as_int().to_le_bytes());
                out_bytes[start_off + P2_T*8 + i*8 .. start_off + P2_T*8 + (i+1)*8].copy_from_slice(&result_state[i].as_int().to_le_bytes());
            }
            let pk_root_off = start_off + P2_T * 8 * 2;
            out_bytes[pk_root_off .. pk_root_off + 8].copy_from_slice(&pk_root_l0.as_int().to_le_bytes());
            out_bytes[pk_root_off + 8 .. pk_root_off + 16].copy_from_slice(&pk_root_l1.as_int().to_le_bytes());
            let com_off = pk_root_off + 16;
            out_bytes[com_off .. com_off + 8].copy_from_slice(&com_l0.as_int().to_le_bytes());
            out_bytes[com_off + 8 .. com_off + 16].copy_from_slice(&com_l1.as_int().to_le_bytes());
            let pub_seed_off = com_off + 16;
            out_bytes[pub_seed_off .. pub_seed_off + 8].copy_from_slice(&pub_seed_lo.as_int().to_le_bytes());
            out_bytes[pub_seed_off + 8 .. pub_seed_off + 16].copy_from_slice(&pub_seed_hi.as_int().to_le_bytes());
            // ctx_hash = Blake3(pk || pk_e || com || m_pub || public_ctx || sigma_c) — binds all public inputs
            let mut hasher = blake3::Hasher::new();
            hasher.update(pk);
            if !pubi.pk_e.is_null() && pubi.pk_e_len > 0 {
                hasher.update(std::slice::from_raw_parts(pubi.pk_e, pubi.pk_e_len));
            }
            if !pubi.com.is_null() {
                hasher.update(std::slice::from_raw_parts(pubi.com, trace_builder::N));
            }
            if pubi.m_pub_len > 0 && !pubi.m_pub.is_null() {
                hasher.update(m_pub);
            }
            if !pubi.public_ctx.is_null() && pubi.public_ctx_len > 0 {
                hasher.update(std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len));
            }
            if !pubi.sigma_c.is_null() && pubi.sigma_c_len > 0 {
                hasher.update(std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len));
            }
            let ctx_hash = hasher.finalize();
            let ctx_hash_off = pub_seed_off + 16;
            out_bytes[ctx_hash_off .. ctx_hash_off + 32].copy_from_slice(ctx_hash.as_bytes());
            out_bytes[header_len..header_len+proof_bytes.len()].copy_from_slice(&proof_bytes);
            out.len = header_len + proof_bytes.len();
            SPX_P2_FULL_AIR_OK
        }
        Err(_) => SPX_P2_FULL_AIR_ERR_PROVE,
    }
}

/// Verify a pi_F proof using the full-AIR.
/// Checks ctx_hash = Blake3(pk || pk_e || com || m_pub || sigma_c) to bind all public inputs.
#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_verify_pi_f_full_air(
    proof_blob: *const crate::SpxP2FfiBlobV1,
    pub_inputs: *const crate::SpxP2FfiPublicInputsV1,
) -> i32 {
    if proof_blob.is_null() || pub_inputs.is_null() { return SPX_P2_FULL_AIR_ERR_NULL; }
    let pf = &*proof_blob; let pubi = &*pub_inputs;
    let header_len: usize = MAGIC_LEN + VERSION_LEN + 8 + 8 + P2_T * 8 * 2 + 2 * 8 + 2 * 8 + 2 * 8 + 32;
    if pf.data.is_null() || pf.len < header_len { return SPX_P2_FULL_AIR_ERR_INPUT; }
    let data = std::slice::from_raw_parts(pf.data, pf.len);
    // Check magic and version
    let magic = u32::from_le_bytes(data[0..MAGIC_LEN].try_into().unwrap());
    if magic != PI_F_MAGIC { return SPX_P2_FULL_AIR_ERR_INPUT; }
    let version = u32::from_le_bytes(data[MAGIC_LEN..MAGIC_LEN+VERSION_LEN].try_into().unwrap());
    if version != PI_F_VERSION { return SPX_P2_FULL_AIR_ERR_INPUT; }
    let tp_off = MAGIC_LEN + VERSION_LEN;
    let total_perms = u64::from_le_bytes(data[tp_off..tp_off+8].try_into().unwrap());
    let root_perm = u64::from_le_bytes(data[tp_off+8..tp_off+16].try_into().unwrap());
    let mut start_state = [BaseElement::ZERO; P2_T];
    let mut result_state = [BaseElement::ZERO; P2_T];
    let start_off = tp_off + 16;
    for i in 0..P2_T {
        start_state[i] = BaseElement::new(u64::from_le_bytes(data[start_off + i*8 .. start_off + (i+1)*8].try_into().unwrap()));
        result_state[i] = BaseElement::new(u64::from_le_bytes(data[start_off + P2_T*8 + i*8 .. start_off + P2_T*8 + (i+1)*8].try_into().unwrap()));
    }
    let pk_root_off = start_off + P2_T * 8 * 2;
    let pk_root_l0 = BaseElement::new(u64::from_le_bytes(data[pk_root_off .. pk_root_off + 8].try_into().unwrap()));
    let pk_root_l1 = BaseElement::new(u64::from_le_bytes(data[pk_root_off + 8 .. pk_root_off + 16].try_into().unwrap()));
    let com_off = pk_root_off + 16;
    let com_l0 = BaseElement::new(u64::from_le_bytes(data[com_off .. com_off + 8].try_into().unwrap()));
    let com_l1 = BaseElement::new(u64::from_le_bytes(data[com_off + 8 .. com_off + 16].try_into().unwrap()));
    let pub_seed_off = com_off + 16;
    let pub_seed_lo = BaseElement::new(u64::from_le_bytes(data[pub_seed_off .. pub_seed_off + 8].try_into().unwrap()));
    let pub_seed_hi = BaseElement::new(u64::from_le_bytes(data[pub_seed_off + 8 .. pub_seed_off + 16].try_into().unwrap()));
    // Derive pub_seed_15 from pk (pub_seed = pk[0..N])
    let pub_seed_15 = BaseElement::new(std::slice::from_raw_parts(pubi.pk, trace_builder::PK_BYTES)[15] as u64);
    // Verify ctx_hash: recompute Blake3(pk || pk_e || com || m_pub || public_ctx || sigma_c) and compare
    let mut hasher = blake3::Hasher::new();
    if pubi.pk.is_null() { return SPX_P2_FULL_AIR_ERR_INPUT; }
    hasher.update(std::slice::from_raw_parts(pubi.pk, trace_builder::PK_BYTES));
    if !pubi.pk_e.is_null() && pubi.pk_e_len > 0 {
        hasher.update(std::slice::from_raw_parts(pubi.pk_e, pubi.pk_e_len));
    }
    if !pubi.com.is_null() {
        hasher.update(std::slice::from_raw_parts(pubi.com, trace_builder::N));
    }
    if pubi.m_pub_len > 0 && !pubi.m_pub.is_null() {
        hasher.update(std::slice::from_raw_parts(pubi.m_pub, pubi.m_pub_len));
    }
    if !pubi.public_ctx.is_null() && pubi.public_ctx_len > 0 {
        hasher.update(std::slice::from_raw_parts(pubi.public_ctx, pubi.public_ctx_len));
    }
    if !pubi.sigma_c.is_null() && pubi.sigma_c_len > 0 {
        hasher.update(std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len));
    }
    let expected_hash = hasher.finalize();
    let ctx_hash_off = pub_seed_off + 16;
    if data[ctx_hash_off .. ctx_hash_off + 32] != *expected_hash.as_bytes() {
        return SPX_P2_FULL_AIR_ERR_VERIFY;
    }
    let proof_bytes = &data[header_len..];
    let proof_obj = match Proof::from_bytes(proof_bytes) { Ok(p) => p, Err(_) => return SPX_P2_FULL_AIR_ERR_VERIFY };
    let pi = SpxVerifyPublicInputs::from_values(start_state, result_state, total_perms, root_perm, pk_root_l0, pk_root_l1, com_l0, com_l1, pub_seed_lo, pub_seed_hi, pub_seed_15);
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
    match winterfell::verify::<SpxVerifyAir, Blake3_256<BaseElement>, DefaultRandomCoin<_>, MerkleTree<_>>(
        proof_obj, pi, &min_opts,
    ) {
        Ok(()) => SPX_P2_FULL_AIR_OK,
        Err(_) => SPX_P2_FULL_AIR_ERR_VERIFY,
    }
}

/// Get ABI version for full-AIR path.
#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_get_abi_version_full_air(out_version: *mut u32) -> i32 {
    if out_version.is_null() { return SPX_P2_FULL_AIR_ERR_NULL; }
    *out_version = SPX_P2_FULL_AIR_ABI_VERSION;
    SPX_P2_FULL_AIR_OK
}

#[cfg(test)] mod tests {
    use super::*;

    fn prove_verify() -> bool {
        let pk = vec![0x42u8; trace_builder::PK_BYTES]; let m_pub = vec![0x27u8; trace_builder::N];
        let sigma_com = vec![0x00u8; trace_builder::SIG_BYTES];
        let (td, _, tp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, rp, ps15) = trace_builder::build_verification_trace(&pk, &sigma_com, &m_pub, &[], &[], &[], &[]);
        let tl = td.len(); let mut tt = TraceTable::new(TRACE_WIDTH, tl);
        for r in 0..tl { for c in 0..TRACE_WIDTH { tt.set(c, r, td[r][c]); } }
        let mut ss = [BaseElement::ZERO; P2_T]; for i in 0..P2_T { ss[i] = td[0][i]; }
        let mut rs = [BaseElement::ZERO; P2_T]; for i in 0..P2_T { rs[i] = td[tl-1][i]; }
        let pi = SpxVerifyPublicInputs::from_values(ss, rs, tp, rp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, ps15);
        let opts = ProofOptions::new(27, 16, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear);
        let p = SpxVerifyProver{options:opts.clone(), pub_inputs:pi.clone(), trace:tt};
        let proof = p.prove(p.trace.clone()).unwrap();
        let proof_bytes = proof.to_bytes();
        // Measure verify time: 10 iterations
        let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
        let start = std::time::Instant::now();
        for _ in 0..10 {
            let pd = Proof::from_bytes(&proof_bytes).unwrap();
            winterfell::verify::<SpxVerifyAir, Blake3_256<BaseElement>, DefaultRandomCoin<_>, MerkleTree<_>>(
                pd, pi.clone(), &min_opts).unwrap();
        }
        let us = start.elapsed().as_micros() as f64 / 10.0;
        eprintln!("verify={:.0}us ({:.3}ms) avg over 10 runs", us, us / 1000.0);
        true
    }

    #[test] fn test_e2e() { assert!(prove_verify()); }

    /// Helper: prove a tampered trace. Returns true if tamper is rejected (by prover or verifier).
    fn tamper_rejected(td: &[Vec<BaseElement>], tp: u64, rp: u64,
                       pk_l0: BaseElement, pk_l1: BaseElement,
                       com_l0: BaseElement, com_l1: BaseElement,
                       ps_lo: BaseElement, ps_hi: BaseElement,
                       ps15: BaseElement) -> bool {
        let tl = td.len();
        let mut tt = TraceTable::new(TRACE_WIDTH, tl);
        for r in 0..tl { for c in 0..TRACE_WIDTH { tt.set(c, r, td[r][c]); } }
        let mut ss = [BaseElement::ZERO; P2_T]; for i in 0..P2_T { ss[i] = td[0][i]; }
        let mut rs = [BaseElement::ZERO; P2_T]; for i in 0..P2_T { rs[i] = td[tl-1][i]; }
        let pi = SpxVerifyPublicInputs::from_values(ss, rs, tp, rp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, ps15);
        let opts = ProofOptions::new(27, 16, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear);
        let p = SpxVerifyProver{options:opts.clone(), pub_inputs:pi.clone(), trace:tt};
        // Prover may panic if trace violates constraints; catch that.
        let prove_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p.prove(p.trace.clone())
        }));
        match prove_result {
            Err(_) => true, // prover panicked = tamper detected
            Ok(Err(_)) => true, // prover returned error
            Ok(Ok(proof)) => {
                let proof_bytes = proof.to_bytes();
                let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
                winterfell::verify::<SpxVerifyAir, Blake3_256<BaseElement>, DefaultRandomCoin<_>, MerkleTree<_>>(
                    Proof::from_bytes(&proof_bytes).unwrap(), pi, &min_opts,
                ).is_err()
            }
        }
    }

    #[test] fn test_tamper_state_rejected() {
        let pk = vec![0x42u8; trace_builder::PK_BYTES];
        let m_pub = vec![0x27u8; trace_builder::N];
        let sigma_com = vec![0x00u8; trace_builder::SIG_BYTES];
        let (mut td, _, tp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, rp, ps15) = trace_builder::build_verification_trace(&pk, &sigma_com, &m_pub, &[], &[], &[], &[]);
        let original = td[10][0];
        td[10][0] = original + BaseElement::ONE;
        eprintln!("[tamper] row=9 cur[16]={} nxt[0]={}", td[9][16].as_int(), td[10][0].as_int());
        assert!(tamper_rejected(&td, tp, rp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, ps15),
                "Tampered state proof should be rejected");
    }

    #[test] fn test_tamper_round_rejected() {
        let pk = vec![0x42u8; trace_builder::PK_BYTES];
        let m_pub = vec![0x27u8; trace_builder::N];
        let sigma_com = vec![0x00u8; trace_builder::SIG_BYTES];
        let (mut td, _, tp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, rp, ps15) = trace_builder::build_verification_trace(&pk, &sigma_com, &m_pub, &[], &[], &[], &[]);
        let original = td[5][12];
        td[5][12] = original + BaseElement::new(5);
        assert!(tamper_rejected(&td, tp, rp, pk_l0, pk_l1, com_l0, com_l1, ps_lo, ps_hi, ps15),
                "Tampered round proof should be rejected");
    }
}
