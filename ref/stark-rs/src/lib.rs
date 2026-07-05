#![allow(clippy::missing_safety_doc)]

mod thash_bench;
mod thash_sha2_f_exact;
mod thash_poseidon2_exact;
mod thash_sha2_exact;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
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
const POSEIDON2_T: usize = 12;
#[cfg(test)]
const POSEIDON2_ROUNDS: usize = 30;
const POSEIDON2_RATE_BYTES: usize = 48;
const POSEIDON2_RATE_LANES: usize = POSEIDON2_RATE_BYTES / 8;
// Winterfell 0.13 limits total trace columns to 255. With the current
// per-block lane/state layout, 4 suffix blocks keeps TRACE_WIDTH at 231.
const CIPHERTEXT_SUFFIX_BLOCK_COUNT: usize = 4;
const CIPHERTEXT_SUFFIX_OLDER_BLOCK_COUNT: usize = CIPHERTEXT_SUFFIX_BLOCK_COUNT - 3;
const CIPHERTEXT_FINAL_BLOCK_COL_START: usize = 75;
const CIPHERTEXT_PREV_BLOCK_COL_START: usize = CIPHERTEXT_FINAL_BLOCK_COL_START + POSEIDON2_RATE_LANES;
const CIPHERTEXT_PREV_PREV_BLOCK_COL_START: usize = CIPHERTEXT_PREV_BLOCK_COL_START + POSEIDON2_RATE_LANES;
const CIPHERTEXT_OLDER_BLOCK_COL_START: usize = CIPHERTEXT_PREV_PREV_BLOCK_COL_START + POSEIDON2_RATE_LANES;
const CIPHERTEXT_SUFFIX_STATE_COL_START: usize =
    CIPHERTEXT_OLDER_BLOCK_COL_START + CIPHERTEXT_SUFFIX_OLDER_BLOCK_COUNT * POSEIDON2_RATE_LANES;
const CIPHERTEXT_SUFFIX_CHAIN_COLS: usize =
    POSEIDON2_T + CIPHERTEXT_SUFFIX_BLOCK_COUNT * (2 * POSEIDON2_T + POSEIDON2_RATE_LANES);
const TRACE_WIDTH: usize = CIPHERTEXT_SUFFIX_STATE_COL_START + CIPHERTEXT_SUFFIX_CHAIN_COLS;

const PI_F_V2_MAGIC: u32 = 0x32504650; // "PFP2"
const PI_F_V2_VERSION: u32 = 2;
const PI_F_V2_FLAG_STARK_PROOF: u32 = 0x0000_0001;
const PI_F_V2_PROOF_SYSTEM_ID_STARK: u32 = 2;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V1: u32 = 1;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V2: u32 = 2;
const PI_F_V2_STATEMENT_VERSION_VERIFY_FULL: u32 = PI_F_V2_STATEMENT_VERSION_VERIFY_FULL_V2;
const PI_F_V2_FRAMEWORK_ID_FISCHLIN_STRICT: u32 = 1;
const PI_F_V2_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2: u32 = 1;
const PI_F_V2_FIXED_HEADER_BYTES: usize = 7 * 4;
const PI_F_V2_RESERVED_BYTES: usize = 2 * 4;

#[inline(always)]
fn goldilocks_fe(value: u64) -> BaseElement {
    BaseElement::new(value)
}

#[inline(always)]
fn goldilocks_fe_from_u128(value: u128) -> BaseElement {
    goldilocks_fe((value % (GOLDILOCKS_P_U64 as u128)) as u64)
}

fn rust_verify_debug_enabled() -> bool {
    std::env::var_os("SPX_P2_DEBUG_VERIFY").is_some()
}

fn rust_verify_debug(msg: &str) {
    if rust_verify_debug_enabled() {
        eprintln!("[stark-rs verify] {msg}");
    }
}

fn debug_validate_commit_opening_columns(
    trace: &TraceTable<BaseElement>,
    com_input_public_l0: BaseElement,
    com_input_public_l1: BaseElement,
    com_input_public_l2: BaseElement,
    com_input_m_tail: BaseElement,
    ciphertext_prefix_l0: BaseElement,
    ciphertext_prefix_l1: BaseElement,
    ciphertext_prefix_l2: BaseElement,
    ciphertext_prev_prev_block: Poseidon2RateBlock,
    ciphertext_prev_block: Poseidon2RateBlock,
    ciphertext_final_block: Poseidon2RateBlock,
) -> Option<(usize, usize, BaseElement)> {
    let last_step = trace.length() - 1;
    let lane256 = BaseElement::new(256);
    let lane5_pad = goldilocks_fe(COMMIT_PAD_LANE5_BASE);
    let lane7_shift = goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT);
    let ct_pad_lane4 = goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE4_BASE);
    let ct_pad_lane5 = goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE5_BASE);

    for row in 0..trace.length() {
        let c18 = trace.get(18, row);
        let c19 = trace.get(19, row);
        let c20 = trace.get(20, row);
        let _c24 = trace.get(24, row);
        let _c25 = trace.get(25, row);
        let _c26 = trace.get(26, row);
        let c27 = trace.get(27, row);
        let c34 = trace.get(34, row);
        let c35 = trace.get(35, row);
        let c36 = trace.get(36, row);
        let _c37 = trace.get(37, row);
        let _c38 = trace.get(38, row);
        let _c39 = trace.get(39, row);
        let _c40 = trace.get(40, row);
        let _c41 = trace.get(41, row);
        let _c42 = trace.get(42, row);
        let c43 = trace.get(43, row);
        let c44 = trace.get(44, row);
        let c45 = trace.get(45, row);
        let c46 = trace.get(46, row);
        let c47 = trace.get(47, row);
        let c48 = trace.get(48, row);
        let c49 = trace.get(49, row);
        let c50 = trace.get(50, row);
        let c51 = trace.get(51, row);
        let c52 = trace.get(52, row);
        let c53 = trace.get(53, row);
        let c54 = trace.get(54, row);
        let c55 = trace.get(55, row);
        let c56 = trace.get(56, row);
        let c57 = trace.get(57, row);
        let c58 = trace.get(58, row);
        let c59 = trace.get(59, row);
        let c60 = trace.get(60, row);
        let c61 = trace.get(61, row);
        let c62 = trace.get(62, row);
        let c63 = trace.get(63, row);
        let c64 = trace.get(64, row);
        let c65 = trace.get(65, row);
        let c66 = trace.get(66, row);
        let c67 = trace.get(67, row);
        let c68 = trace.get(68, row);
        let c69 = trace.get(69, row);
        let c70 = trace.get(70, row);
        let c71 = trace.get(71, row);
        let c72 = trace.get(72, row);
        let c73 = trace.get(73, row);
        let c74 = trace.get(74, row);
        let c75 = trace.get(75, row);
        let c76 = trace.get(76, row);
        let c77 = trace.get(77, row);
        let c78 = trace.get(78, row);
        let c79 = trace.get(79, row);
        let c80 = trace.get(80, row);
        let c81 = trace.get(81, row);
        let c82 = trace.get(82, row);
        let c83 = trace.get(83, row);
        let c84 = trace.get(84, row);
        let c85 = trace.get(85, row);
        let c86 = trace.get(86, row);
        let c87 = trace.get(87, row);
        let c88 = trace.get(88, row);
        let c89 = trace.get(89, row);
        let c90 = trace.get(90, row);
        let c91 = trace.get(91, row);
        let c92 = trace.get(92, row);

        let checks = [
            c34 - c18,
            c35 - c19,
            c36 - c20,
            c27 * (c27 - BaseElement::ONE),
            c55 - ciphertext_prefix_l0 - trace.get(37, row),
            c56 - ciphertext_prefix_l1 - trace.get(38, row),
            c57 - ciphertext_prefix_l2 - trace.get(39, row),
            c58 - c55 - c18,
            c59 - c56 - c19,
            c60 - c57 - c20,
            c61 - c58 - c52,
            c62 - c59 - c53,
            c63 - c60 - c54,
            c64 - c61 - trace.get(40, row) - c67,
            c65 - c62 - trace.get(41, row) - c68,
            c66 - c63 - trace.get(42, row) - c67 - c68,
            BaseElement::ZERO,
            BaseElement::ZERO,
            BaseElement::ZERO,
            c43 - com_input_public_l0,
            c44 - com_input_public_l1,
            c45 - com_input_public_l2,
            c46 - (com_input_m_tail + c49 * lane256),
            c47 - c50,
            c48 - (c51 + lane5_pad),
            trace.get(40, row) - c69 - c70 * lane256,
            trace.get(41, row) - c71 - c72 * lane256,
            trace.get(42, row) - c73 - c74 * lane256,
            c75 - c67,
            c76 - c68 - c69 * lane7_shift,
            c77 - c70 - c71 * lane7_shift,
            c78 - c72 - c73 * lane7_shift,
            c79 - c74 - ct_pad_lane4,
            c80 - ct_pad_lane5,
            c75 - ciphertext_final_block[0],
            c76 - ciphertext_final_block[1],
            c77 - ciphertext_final_block[2],
            c78 - ciphertext_final_block[3],
            c79 - ciphertext_final_block[4],
            c80 - ciphertext_final_block[5],
            c81 - ciphertext_prev_block[0],
            c82 - ciphertext_prev_block[1],
            c83 - ciphertext_prev_block[2],
            c84 - ciphertext_prev_block[3],
            c85 - ciphertext_prev_block[4],
            c86 - ciphertext_prev_block[5],
            c87 - ciphertext_prev_prev_block[0],
            c88 - ciphertext_prev_prev_block[1],
            c89 - ciphertext_prev_prev_block[2],
            c90 - ciphertext_prev_prev_block[3],
            c91 - ciphertext_prev_prev_block[4],
            c92 - ciphertext_prev_prev_block[5],
        ];
        for (offset, value) in checks.iter().enumerate() {
            if *value != BaseElement::ZERO {
                if rust_verify_debug_enabled() {
                    let final_col = CIPHERTEXT_FINAL_BLOCK_COL_START;
                    eprintln!(
                        "[stark-rs prove] debug self-check detail: offset={} c67={:?} c75={:?} final_col0={:?} expected_final0={:?}",
                        offset,
                        c67,
                        c75,
                        trace.get(final_col, row),
                        ciphertext_final_block[0]
                    );
                }
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
                trace.get(52, row + 1) - c52,
                trace.get(53, row + 1) - c53,
                trace.get(54, row + 1) - c54,
                trace.get(55, row + 1) - c55,
                trace.get(56, row + 1) - c56,
                trace.get(57, row + 1) - c57,
                trace.get(58, row + 1) - c58,
                trace.get(59, row + 1) - c59,
                trace.get(60, row + 1) - c60,
                trace.get(61, row + 1) - c61,
                trace.get(62, row + 1) - c62,
                trace.get(63, row + 1) - c63,
                trace.get(64, row + 1) - c64,
                trace.get(65, row + 1) - c65,
                trace.get(66, row + 1) - c66,
                trace.get(67, row + 1) - c67,
                trace.get(68, row + 1) - c68,
                trace.get(69, row + 1) - c69,
                trace.get(70, row + 1) - c70,
                trace.get(71, row + 1) - c71,
                trace.get(72, row + 1) - c72,
                trace.get(73, row + 1) - c73,
                trace.get(74, row + 1) - c74,
                trace.get(75, row + 1) - c75,
                trace.get(76, row + 1) - c76,
                trace.get(77, row + 1) - c77,
                trace.get(78, row + 1) - c78,
                trace.get(79, row + 1) - c79,
                trace.get(80, row + 1) - c80,
                trace.get(81, row + 1) - c81,
                trace.get(82, row + 1) - c82,
                trace.get(83, row + 1) - c83,
                trace.get(84, row + 1) - c84,
                trace.get(85, row + 1) - c85,
                trace.get(86, row + 1) - c86,
                trace.get(87, row + 1) - c87,
                trace.get(88, row + 1) - c88,
                trace.get(89, row + 1) - c89,
                trace.get(90, row + 1) - c90,
                trace.get(91, row + 1) - c91,
                trace.get(92, row + 1) - c92,
            ];
            for (offset, value) in next_checks.iter().enumerate() {
                if *value != BaseElement::ZERO {
                    return Some((row, 67 + offset, *value));
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
    #[link_name = "SPX_spx_p2_build_sigma_c_ciphertext"]
    fn spx_p2_build_sigma_c_ciphertext(
        out_sigma_c: *mut u8,
        out_sigma_c_len: *mut usize,
        com: *const u8,
        sigma_com: *const u8,
        pk_e: *const u8,
        pk_e_len: usize,
        omega2: *const u8,
        omega2_len: usize,
    ) -> i32;
    #[cfg(not(test))]
    #[link_name = "SPX_poseidon2_permute"]
    fn poseidon2_permute_c(state: *mut u64);
}

const SPX_P2_DOMAIN_CUSTOM: i32 = 0xff;
const SPX_P2_DOMAIN_COMMIT: i32 = 0x20;
const COMMIT_M_PUB_LEN: usize = 24;
const COMMIT_R_LEN: usize = 16;
const CIPHERTEXT_DOMAIN_BYTE: u8 = SPX_P2_DOMAIN_CUSTOM as u8;
const CIPHERTEXT_LABEL_BYTES: &[u8] = b"m20-pke-ct-v1\0";
const COMMIT_PAD_LANE5_BASE: u64 = (1u64 << 8) | (0x80u64 << 56);
const CIPHERTEXT_SPLIT_BYTE7_SHIFT: u64 = 1u64 << 56;
const CIPHERTEXT_FINAL_PAD_LANE4_BASE: u64 = 1u64 << 56;
const CIPHERTEXT_FINAL_PAD_LANE5_BASE: u64 = 0x80u64 << 56;
const GOLDILOCKS_P_U64: u64 = 0xffff_ffff_0000_0001;

type Poseidon2RateBlock = [BaseElement; POSEIDON2_RATE_LANES];
type Poseidon2State = [BaseElement; POSEIDON2_T];

#[derive(Clone, Copy)]
struct CiphertextSuffixStateChain {
    start_post_state: Poseidon2State,
    suffix_blocks: [Poseidon2RateBlock; CIPHERTEXT_SUFFIX_BLOCK_COUNT],
    pre_states: [Poseidon2State; CIPHERTEXT_SUFFIX_BLOCK_COUNT],
    post_states: [Poseidon2State; CIPHERTEXT_SUFFIX_BLOCK_COUNT],
    carries: [[BaseElement; POSEIDON2_RATE_LANES]; CIPHERTEXT_SUFFIX_BLOCK_COUNT],
}

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
    goldilocks_fe(value)
}

fn load_rate_block_le(bytes: &[u8; POSEIDON2_RATE_BYTES]) -> Poseidon2RateBlock {
    let mut lanes = [BaseElement::ZERO; POSEIDON2_RATE_LANES];
    let mut i = 0usize;
    while i < POSEIDON2_RATE_LANES {
        let begin = i * 8;
        let end = begin + 8;
        lanes[i] = load_lane_le(&bytes[begin..end]);
        i += 1;
    }
    lanes
}

fn poseidon2_state_from_u64(words: [u64; POSEIDON2_T]) -> Poseidon2State {
    let mut state = [BaseElement::ZERO; POSEIDON2_T];
    let mut i = 0usize;
    while i < POSEIDON2_T {
        state[i] = goldilocks_fe(words[i]);
        i += 1;
    }
    state
}

fn goldilocks_add_with_carry(a: u64, b: u64) -> (u64, u64) {
    let mut sum = a.wrapping_add(b);
    let carry = if sum < a || sum >= GOLDILOCKS_P_U64 { 1 } else { 0 };
    if carry == 1 {
        sum = sum.wrapping_sub(GOLDILOCKS_P_U64);
    }
    (sum, carry)
}

fn goldilocks_absorb_state_with_block(
    post_state: [u64; POSEIDON2_T],
    block: Poseidon2RateBlock,
) -> ([u64; POSEIDON2_T], [BaseElement; POSEIDON2_RATE_LANES]) {
    let mut pre_state = post_state;
    let mut carries = [BaseElement::ZERO; POSEIDON2_RATE_LANES];
    let mut lane = 0usize;
    while lane < POSEIDON2_RATE_LANES {
        let (sum, carry) = goldilocks_add_with_carry(post_state[lane], block[lane].as_int() as u64);
        pre_state[lane] = sum;
        carries[lane] = goldilocks_fe(carry);
        lane += 1;
    }
    (pre_state, carries)
}

#[cfg(not(test))]
fn poseidon2_permute_state(mut state: [u64; POSEIDON2_T]) -> [u64; POSEIDON2_T] {
    unsafe {
        poseidon2_permute_c(state.as_mut_ptr());
    }
    state
}

#[cfg(test)]
fn poseidon2_permute_state(mut state: [u64; POSEIDON2_T]) -> [u64; POSEIDON2_T] {
    for round in 0..POSEIDON2_ROUNDS {
        crate::thash_poseidon2_exact::poseidon2_round_u64(&mut state, round);
    }
    state
}

fn build_poseidon2_padded_absorb_blocks(message: &[u8]) -> Vec<Poseidon2RateBlock> {
    let mut blocks = Vec::with_capacity(message.len() / POSEIDON2_RATE_BYTES + 1);
    let full_blocks = message.len() / POSEIDON2_RATE_BYTES;
    let mut i = 0usize;
    while i < full_blocks {
        let begin = i * POSEIDON2_RATE_BYTES;
        let mut block = [0u8; POSEIDON2_RATE_BYTES];
        block.copy_from_slice(&message[begin..begin + POSEIDON2_RATE_BYTES]);
        blocks.push(load_rate_block_le(&block));
        i += 1;
    }

    let remainder = message.len() % POSEIDON2_RATE_BYTES;
    let mut final_block = [0u8; POSEIDON2_RATE_BYTES];
    if remainder > 0 {
        let begin = full_blocks * POSEIDON2_RATE_BYTES;
        final_block[..remainder].copy_from_slice(&message[begin..]);
    }
    final_block[remainder] ^= 0x01;
    final_block[POSEIDON2_RATE_BYTES - 1] ^= 0x80;
    blocks.push(load_rate_block_le(&final_block));
    blocks
}

fn build_ciphertext_absorb_blocks(
    pk_e: &[u8],
    com: &[u8],
    sigma_com: &[u8],
    omega2: &[u8],
) -> Option<Vec<Poseidon2RateBlock>> {
    if pk_e.len() != SPX_N || com.len() != COM_LEN || omega2.len() != SPX_N {
        return None;
    }
    let mut transcript = Vec::with_capacity(1 + CIPHERTEXT_LABEL_BYTES.len() + pk_e.len() + com.len() + sigma_com.len() + omega2.len());
    transcript.push(CIPHERTEXT_DOMAIN_BYTE);
    transcript.extend_from_slice(CIPHERTEXT_LABEL_BYTES);
    transcript.extend_from_slice(pk_e);
    transcript.extend_from_slice(com);
    transcript.extend_from_slice(sigma_com);
    transcript.extend_from_slice(omega2);
    Some(build_poseidon2_padded_absorb_blocks(&transcript))
}

fn derive_ciphertext_suffix_blocks(
    pk_e: &[u8],
    com: &[u8],
    sigma_com: &[u8],
    omega2: &[u8],
) -> Option<(Poseidon2RateBlock, Poseidon2RateBlock, Poseidon2RateBlock)> {
    let blocks = build_ciphertext_absorb_blocks(pk_e, com, sigma_com, omega2)?;
    if blocks.len() < 3 {
        return None;
    }
    let last = blocks.len() - 1;
    Some((blocks[last - 2], blocks[last - 1], blocks[last]))
}

fn derive_ciphertext_suffix_state_chain(
    blocks: &[Poseidon2RateBlock],
) -> Option<CiphertextSuffixStateChain> {
    if blocks.len() < CIPHERTEXT_SUFFIX_BLOCK_COUNT {
        return None;
    }
    let split = blocks.len() - CIPHERTEXT_SUFFIX_BLOCK_COUNT;
    let mut suffix_blocks = [[BaseElement::ZERO; POSEIDON2_RATE_LANES]; CIPHERTEXT_SUFFIX_BLOCK_COUNT];
    suffix_blocks.copy_from_slice(&blocks[split..]);
    let mut state = [0u64; POSEIDON2_T];
    for block in &blocks[..split] {
        let (pre_state, _) = goldilocks_absorb_state_with_block(state, *block);
        state = poseidon2_permute_state(pre_state);
    }
    let start_post_state = state;
    let mut pre_states = [[BaseElement::ZERO; POSEIDON2_T]; CIPHERTEXT_SUFFIX_BLOCK_COUNT];
    let mut post_states = [[BaseElement::ZERO; POSEIDON2_T]; CIPHERTEXT_SUFFIX_BLOCK_COUNT];
    let mut carries = [[BaseElement::ZERO; POSEIDON2_RATE_LANES]; CIPHERTEXT_SUFFIX_BLOCK_COUNT];
    for i in 0..CIPHERTEXT_SUFFIX_BLOCK_COUNT {
        let (pre_state, block_carries) = goldilocks_absorb_state_with_block(state, suffix_blocks[i]);
        let post_state = poseidon2_permute_state(pre_state);
        pre_states[i] = poseidon2_state_from_u64(pre_state);
        post_states[i] = poseidon2_state_from_u64(post_state);
        carries[i] = block_carries;
        state = post_state;
    }

    Some(CiphertextSuffixStateChain {
        start_post_state: poseidon2_state_from_u64(start_post_state),
        suffix_blocks,
        pre_states,
        post_states,
        carries,
    })
}

fn ciphertext_suffix_block_col_start(block_idx: usize) -> usize {
    if block_idx < CIPHERTEXT_SUFFIX_OLDER_BLOCK_COUNT {
        return CIPHERTEXT_OLDER_BLOCK_COL_START + block_idx * POSEIDON2_RATE_LANES;
    }
    match block_idx - CIPHERTEXT_SUFFIX_OLDER_BLOCK_COUNT {
        0 => CIPHERTEXT_PREV_PREV_BLOCK_COL_START,
        1 => CIPHERTEXT_PREV_BLOCK_COL_START,
        2 => CIPHERTEXT_FINAL_BLOCK_COL_START,
        _ => unreachable!("suffix block index out of range"),
    }
}

fn ciphertext_suffix_start_post_state_col_start() -> usize {
    CIPHERTEXT_SUFFIX_STATE_COL_START
}

fn ciphertext_suffix_pre_state_col_start(block_idx: usize) -> usize {
    CIPHERTEXT_SUFFIX_STATE_COL_START + POSEIDON2_T + block_idx * (2 * POSEIDON2_T + POSEIDON2_RATE_LANES)
}

fn ciphertext_suffix_post_state_col_start(block_idx: usize) -> usize {
    ciphertext_suffix_pre_state_col_start(block_idx) + POSEIDON2_T
}

fn ciphertext_suffix_carry_col_start(block_idx: usize) -> usize {
    ciphertext_suffix_post_state_col_start(block_idx) + POSEIDON2_T
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
    let m_tail = goldilocks_fe(m_pub[23] as u64);
    Some(([lane0, lane1, lane2], m_tail))
}

fn derive_commit_open_witness_parts(r: &[u8]) -> Option<(BaseElement, BaseElement, BaseElement)> {
    if r.len() != COMMIT_R_LEN {
        return None;
    }
    let r_prefix7 = load_lane_le(&r[0..7]);
    let r_middle8 = load_lane_le(&r[7..15]);
    let r_last = goldilocks_fe(r[15] as u64);
    Some((r_prefix7, r_middle8, r_last))
}

fn derive_signature_witness_prefix_limbs(sigma_com: &[u8]) -> Option<[BaseElement; COM_LIMBS]> {
    if sigma_com.len() < COM_LEN {
        return None;
    }
    decode_public_limbs::<COM_LIMBS>(&sigma_com[..COM_LEN])
}

fn derive_signature_witness_middle_limbs(sigma_com: &[u8]) -> Option<[BaseElement; COM_LIMBS]> {
    if sigma_com.len() < COM_LEN {
        return None;
    }
    let start = (sigma_com.len() - COM_LEN) / 2;
    decode_public_limbs::<COM_LIMBS>(&sigma_com[start..start + COM_LEN])
}

fn derive_signature_witness_quarter_limbs(sigma_com: &[u8]) -> Option<[BaseElement; COM_LIMBS]> {
    if sigma_com.len() < COM_LEN {
        return None;
    }
    let span = sigma_com.len() - COM_LEN;
    let start = span / 4;
    decode_public_limbs::<COM_LIMBS>(&sigma_com[start..start + COM_LEN])
}

fn derive_signature_witness_three_quarter_limbs(sigma_com: &[u8]) -> Option<[BaseElement; COM_LIMBS]> {
    if sigma_com.len() < COM_LEN {
        return None;
    }
    let span = sigma_com.len() - COM_LEN;
    let start = (3 * span) / 4;
    decode_public_limbs::<COM_LIMBS>(&sigma_com[start..start + COM_LEN])
}

fn derive_signature_witness_suffix_limbs(sigma_com: &[u8]) -> Option<[BaseElement; COM_LIMBS]> {
    if sigma_com.len() < COM_LEN {
        return None;
    }
    let start = sigma_com.len() - COM_LEN;
    decode_public_limbs::<COM_LIMBS>(&sigma_com[start..])
}

fn derive_signature_witness_suffix_tail_parts(sigma_com: &[u8]) -> Option<(BaseElement, BaseElement)> {
    if sigma_com.len() < 15 {
        return None;
    }
    let start = sigma_com.len() - 15;
    let tail_l0 = load_lane_le(&sigma_com[start..start + 8]);
    let tail_l1_7 = load_lane_le(&sigma_com[start + 8..]);
    Some((tail_l0, tail_l1_7))
}

fn derive_omega2_tail_block_parts(
    omega2: &[u8],
) -> Option<(BaseElement, BaseElement, BaseElement, BaseElement, BaseElement, BaseElement)> {
    if omega2.len() != SPX_N {
        return None;
    }
    let b0 = goldilocks_fe(omega2[0] as u64);
    let hi7 = load_lane_le(&omega2[1..8]);
    let b8 = goldilocks_fe(omega2[8] as u64);
    let mid7 = load_lane_le(&omega2[9..16]);
    let b16 = goldilocks_fe(omega2[16] as u64);
    let last7 = load_lane_le(&omega2[17..24]);
    Some((b0, hi7, b8, mid7, b16, last7))
}

fn canonicalize_ciphertext_prefix_limbs() -> [BaseElement; COM_LIMBS] {
    let mut canonical = [0u8; COM_LEN];
    let prefix = &[CIPHERTEXT_DOMAIN_BYTE]
        .iter()
        .chain(CIPHERTEXT_LABEL_BYTES.iter())
        .copied()
        .collect::<Vec<u8>>();
    canonical[..prefix.len()].copy_from_slice(prefix);
    decode_public_limbs::<COM_LIMBS>(&canonical)
        .expect("canonical ciphertext prefix has fixed 24-byte length")
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
    ciphertext_prefix_l0: BaseElement,
    ciphertext_prefix_l1: BaseElement,
    ciphertext_prefix_l2: BaseElement,
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
            self.ciphertext_prefix_l0,
            self.ciphertext_prefix_l1,
            self.ciphertext_prefix_l2,
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
    ciphertext_prefix_l0: BaseElement,
    ciphertext_prefix_l1: BaseElement,
    ciphertext_prefix_l2: BaseElement,
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
        let mut degrees = vec![
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
        ];
        degrees.extend((0..285).map(|_| TransitionConstraintDegree::new(1)));
        degrees.extend((0..36).map(|_| TransitionConstraintDegree::new(2)));
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
            ciphertext_prefix_l0: pub_inputs.ciphertext_prefix_l0,
            ciphertext_prefix_l1: pub_inputs.ciphertext_prefix_l1,
            ciphertext_prefix_l2: pub_inputs.ciphertext_prefix_l2,
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
        // The public Sigma.C suffix is bound later to the final suffix sponge
        // post-state. It is not equal to com + an intermediate transcript limb.
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
        result[75] = current[48] - (current[51] + E::from(goldilocks_fe(COMMIT_PAD_LANE5_BASE)));
        // Keep sigma' multi-window chain materialization constant across rows.
        result[76] = next[52] - current[52];
        result[77] = next[53] - current[53];
        result[78] = next[54] - current[54];
        result[79] = next[55] - current[55];
        result[80] = next[56] - current[56];
        result[81] = next[57] - current[57];
        result[82] = next[58] - current[58];
        result[83] = next[59] - current[59];
        result[84] = next[60] - current[60];
        result[85] = next[61] - current[61];
        result[86] = next[62] - current[62];
        result[87] = next[63] - current[63];
        result[88] = next[64] - current[64];
        result[89] = next[65] - current[65];
        result[90] = next[66] - current[66];
        // Shadow the ciphertext absorb order in four phases:
        // prefix+pk_E -> +com -> +sigma' multi-window chain -> +(omega2 + sigma' tail/suffix anchor).
        result[91] = current[55] - E::from(self.ciphertext_prefix_l0) - current[37];
        result[92] = current[56] - E::from(self.ciphertext_prefix_l1) - current[38];
        result[93] = current[57] - E::from(self.ciphertext_prefix_l2) - current[39];
        result[94] = current[58] - current[55] - current[18];
        result[95] = current[59] - current[56] - current[19];
        result[96] = current[60] - current[57] - current[20];
        result[97] = current[61] - current[58] - current[52];
        result[98] = current[62] - current[59] - current[53];
        result[99] = current[63] - current[60] - current[54];
        result[100] = current[64] - current[61] - current[40] - current[67];
        result[101] = current[65] - current[62] - current[41] - current[68];
        result[102] = current[66] - current[63] - current[42] - current[67] - current[68];
        // Scaffold exact byte splits for the final sigma'/omega2 absorb block.
        result[103] = next[67] - current[67];
        result[104] = next[68] - current[68];
        result[105] = next[69] - current[69];
        result[106] = next[70] - current[70];
        result[107] = next[71] - current[71];
        result[108] = next[72] - current[72];
        result[109] = next[73] - current[73];
        result[110] = next[74] - current[74];
        result[111] = current[40] - current[69] - current[70] * E::from(256u32);
        result[112] = current[41] - current[71] - current[72] * E::from(256u32);
        result[113] = current[42] - current[73] - current[74] * E::from(256u32);
        // Materialize the exact final 48-byte ciphertext absorb block:
        // sigma' tail15 || omega2 || pad10*1.
        result[114] = next[75] - current[75];
        result[115] = next[76] - current[76];
        result[116] = next[77] - current[77];
        result[117] = next[78] - current[78];
        result[118] = next[79] - current[79];
        result[119] = next[80] - current[80];
        result[120] = current[75] - current[67];
        result[121] =
            current[76] - current[68] - current[69] * E::from(goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT));
        result[122] =
            current[77] - current[70] - current[71] * E::from(goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT));
        result[123] =
            current[78] - current[72] - current[73] * E::from(goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT));
        result[124] = current[79] - current[74] - E::from(goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE4_BASE));
        result[125] = current[80] - E::from(goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE5_BASE));
        // Materialize the two contiguous sigma' absorb blocks immediately before the final tail block.
        result[126] = next[81] - current[81];
        result[127] = next[82] - current[82];
        result[128] = next[83] - current[83];
        result[129] = next[84] - current[84];
        result[130] = next[85] - current[85];
        result[131] = next[86] - current[86];
        result[132] = next[87] - current[87];
        result[133] = next[88] - current[88];
        result[134] = next[89] - current[89];
        result[135] = next[90] - current[90];
        result[136] = next[91] - current[91];
        result[137] = next[92] - current[92];
        let mut idx = 138usize;
        for block_idx in 0..CIPHERTEXT_SUFFIX_OLDER_BLOCK_COUNT {
            let block_col = CIPHERTEXT_OLDER_BLOCK_COL_START + block_idx * POSEIDON2_RATE_LANES;
            for lane in 0..POSEIDON2_RATE_LANES {
                result[idx] = next[block_col + lane] - current[block_col + lane];
                idx += 1;
            }
        }
        for col in CIPHERTEXT_SUFFIX_STATE_COL_START..TRACE_WIDTH {
            result[idx] = next[col] - current[col];
            idx += 1;
        }
        let goldilocks_modulus = E::from(goldilocks_fe(GOLDILOCKS_P_U64));
        for block_idx in 0..CIPHERTEXT_SUFFIX_BLOCK_COUNT {
            let block_col = ciphertext_suffix_block_col_start(block_idx);
            let pre_col = ciphertext_suffix_pre_state_col_start(block_idx);
            let carry_col = ciphertext_suffix_carry_col_start(block_idx);
            let prev_post_col = if block_idx == 0 {
                ciphertext_suffix_start_post_state_col_start()
            } else {
                ciphertext_suffix_post_state_col_start(block_idx - 1)
            };
            for lane in 0..POSEIDON2_RATE_LANES {
                result[idx] =
                    current[pre_col + lane] - current[prev_post_col + lane] - current[block_col + lane]
                        + current[carry_col + lane] * goldilocks_modulus;
                idx += 1;
            }
            for lane in POSEIDON2_RATE_LANES..POSEIDON2_T {
                result[idx] = current[pre_col + lane] - current[prev_post_col + lane];
                idx += 1;
            }
            for lane in 0..POSEIDON2_RATE_LANES {
                result[idx] = current[carry_col + lane] * (current[carry_col + lane] - E::ONE);
                idx += 1;
            }
        }
        let final_post_col = ciphertext_suffix_post_state_col_start(CIPHERTEXT_SUFFIX_BLOCK_COUNT - 1);
        result[idx] = current[final_post_col] - current[24];
        idx += 1;
        result[idx] = current[final_post_col + 1] - current[25];
        idx += 1;
        result[idx] = current[final_post_col + 2] - current[26];
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
    ciphertext_prefix_l0: BaseElement,
    ciphertext_prefix_l1: BaseElement,
    ciphertext_prefix_l2: BaseElement,
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
        ciphertext_prefix_l0: BaseElement,
        ciphertext_prefix_l1: BaseElement,
        ciphertext_prefix_l2: BaseElement,
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
            ciphertext_prefix_l0,
            ciphertext_prefix_l1,
            ciphertext_prefix_l2,
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
            ciphertext_prefix_l0: self.ciphertext_prefix_l0,
            ciphertext_prefix_l1: self.ciphertext_prefix_l1,
            ciphertext_prefix_l2: self.ciphertext_prefix_l2,
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
    goldilocks_fe_from_u128(x)
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
        out[i] = goldilocks_fe(u64::from_le_bytes(limb));
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
    decode_public_limbs::<COM_LIMBS>(pk_e)
        .expect("pk_e public limbs use the raw 24-byte ciphertext key encoding")
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
    ciphertext_prefix_limbs: [BaseElement; COM_LIMBS],
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
    let start = goldilocks_fe_from_u128(start_u128);
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
    let thash_inblocks_hint = goldilocks_fe(((public_input_digest[0] % 3) + 1) as u64);
    let thash_addr_type_hint = goldilocks_fe((public_input_digest[1] % 5) as u64);
    let prf_rule_start = derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"prf-rule-v1");
    let prf_addr_type_hint = goldilocks_fe((public_input_digest[2] % 5) as u64);
    let hmsg_rule_start =
        derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"hmsg-rule-v1");
    let hmsg_mode_hint = goldilocks_fe((public_input_digest[3] % 4) as u64);
    let rule_mix_start =
        derive_module_part_start(&public_input_digest, &ctx_binding, root_hint, b"rule-mix-v1");
    let rule_profile_hint = goldilocks_fe((public_input_digest[4] % 3) as u64);
    let com_public_limbs = decode_public_limbs::<COM_LIMBS>(com)?;
    let sigma_c_public_limbs = decode_sigma_c_public_limbs(sigma_c, com_public_limbs)?;
    let public_ctx_limbs = canonicalize_public_ctx_limbs(public_ctx);
    let ciphertext_prefix_limbs = canonicalize_ciphertext_prefix_limbs();
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
        ciphertext_prefix_limbs,
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

fn set_ciphertext_suffix_trace_columns(
    state: &mut [BaseElement],
    ciphertext_suffix_state_chain: &CiphertextSuffixStateChain,
) {
    for block_idx in 0..CIPHERTEXT_SUFFIX_BLOCK_COUNT {
        let block_col = ciphertext_suffix_block_col_start(block_idx);
        for lane in 0..POSEIDON2_RATE_LANES {
            state[block_col + lane] = ciphertext_suffix_state_chain.suffix_blocks[block_idx][lane];
        }
    }
    let start_col = ciphertext_suffix_start_post_state_col_start();
    for lane in 0..POSEIDON2_T {
        state[start_col + lane] = ciphertext_suffix_state_chain.start_post_state[lane];
    }
    for block_idx in 0..CIPHERTEXT_SUFFIX_BLOCK_COUNT {
        let pre_col = ciphertext_suffix_pre_state_col_start(block_idx);
        let post_col = ciphertext_suffix_post_state_col_start(block_idx);
        let carry_col = ciphertext_suffix_carry_col_start(block_idx);
        for lane in 0..POSEIDON2_T {
            state[pre_col + lane] = ciphertext_suffix_state_chain.pre_states[block_idx][lane];
            state[post_col + lane] = ciphertext_suffix_state_chain.post_states[block_idx][lane];
        }
        for lane in 0..POSEIDON2_RATE_LANES {
            state[carry_col + lane] = ciphertext_suffix_state_chain.carries[block_idx][lane];
        }
    }
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
    ciphertext_prefix_l0: BaseElement,
    ciphertext_prefix_l1: BaseElement,
    ciphertext_prefix_l2: BaseElement,
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
    sigma_com_window_l0: BaseElement,
    sigma_com_window_l1: BaseElement,
    sigma_com_window_l2: BaseElement,
    sigma_com_tail_l0: BaseElement,
    sigma_com_tail_l1_7: BaseElement,
    omega2_b0: BaseElement,
    omega2_hi7: BaseElement,
    omega2_b8: BaseElement,
    omega2_mid7: BaseElement,
    omega2_b16: BaseElement,
    omega2_last7: BaseElement,
    ciphertext_suffix_state_chain: CiphertextSuffixStateChain,
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
            state[48] = com_input_r_last + goldilocks_fe(COMMIT_PAD_LANE5_BASE);
            state[49] = com_input_r_prefix7;
            state[50] = com_input_r_middle8;
            state[51] = com_input_r_last;
            state[52] = sigma_com_window_l0;
            state[53] = sigma_com_window_l1;
            state[54] = sigma_com_window_l2;
            state[55] = ciphertext_prefix_l0 + pk_e_public_l0;
            state[56] = ciphertext_prefix_l1 + pk_e_public_l1;
            state[57] = ciphertext_prefix_l2 + pk_e_public_l2;
            state[58] = state[55] + com_public_l0;
            state[59] = state[56] + com_public_l1;
            state[60] = state[57] + com_public_l2;
            state[61] = state[58] + sigma_com_window_l0;
            state[62] = state[59] + sigma_com_window_l1;
            state[63] = state[60] + sigma_com_window_l2;
            state[64] = state[61] + omega2_witness_l0 + sigma_com_tail_l0;
            state[65] = state[62] + omega2_witness_l1 + sigma_com_tail_l1_7;
            state[66] = state[63] + omega2_witness_l2 + sigma_com_tail_l0 + sigma_com_tail_l1_7;
            state[67] = sigma_com_tail_l0;
            state[68] = sigma_com_tail_l1_7;
            state[69] = omega2_b0;
            state[70] = omega2_hi7;
            state[71] = omega2_b8;
            state[72] = omega2_mid7;
            state[73] = omega2_b16;
            state[74] = omega2_last7;
            set_ciphertext_suffix_trace_columns(state, &ciphertext_suffix_state_chain);
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
            state[48] = com_input_r_last + goldilocks_fe(COMMIT_PAD_LANE5_BASE);
            state[49] = com_input_r_prefix7;
            state[50] = com_input_r_middle8;
            state[51] = com_input_r_last;
            state[52] = sigma_com_window_l0;
            state[53] = sigma_com_window_l1;
            state[54] = sigma_com_window_l2;
            state[55] = ciphertext_prefix_l0 + pk_e_public_l0;
            state[56] = ciphertext_prefix_l1 + pk_e_public_l1;
            state[57] = ciphertext_prefix_l2 + pk_e_public_l2;
            state[58] = state[55] + com_public_l0;
            state[59] = state[56] + com_public_l1;
            state[60] = state[57] + com_public_l2;
            state[61] = state[58] + sigma_com_window_l0;
            state[62] = state[59] + sigma_com_window_l1;
            state[63] = state[60] + sigma_com_window_l2;
            state[64] = state[61] + omega2_witness_l0 + sigma_com_tail_l0;
            state[65] = state[62] + omega2_witness_l1 + sigma_com_tail_l1_7;
            state[66] = state[63] + omega2_witness_l2 + sigma_com_tail_l0 + sigma_com_tail_l1_7;
            state[67] = sigma_com_tail_l0;
            state[68] = sigma_com_tail_l1_7;
            state[69] = omega2_b0;
            state[70] = omega2_hi7;
            state[71] = omega2_b8;
            state[72] = omega2_mid7;
            state[73] = omega2_b16;
            state[74] = omega2_last7;
            set_ciphertext_suffix_trace_columns(state, &ciphertext_suffix_state_chain);
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
    write_u32_le(&mut out[off..off + 4], PI_F_V2_FRAMEWORK_ID_FISCHLIN_STRICT);
    off += 4;
    write_u32_le(
        &mut out[off..off + 4],
        PI_F_V2_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2,
    );
    off += 4;
    Some(off)
}

#[derive(Clone)]
struct PiFV2Decoded<'a> {
    flags: u32,
    proof_system_id: u32,
    statement_version: u32,
    framework_id: u32,
    signature_system_id: u32,
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
    let framework_id = read_u32_le(&input[off..off + 4]);
    off += 4;
    let signature_system_id = read_u32_le(&input[off..off + 4]);
    if framework_id != PI_F_V2_FRAMEWORK_ID_FISCHLIN_STRICT
        || signature_system_id != PI_F_V2_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2
    {
        return None;
    }

    Some(PiFV2Decoded {
        flags,
        proof_system_id,
        statement_version,
        framework_id,
        signature_system_id,
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
    if pubi.m_pub.is_null() || pubi.m_pub_len == 0 {
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

unsafe fn rust_build_sigma_c_ciphertext_native(
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
    let ret = spx_p2_build_sigma_c_ciphertext(
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
    if pubi.m_pub.is_null() || pubi.m_pub_len == 0 {
        return SPX_P2_RUST_ERR_INPUT;
    }
    if spx_p2_verify_com(pubi.pk, pubi.com, witv.sigma_com) != 0 {
        if rust_verify_debug_enabled() {
            eprintln!("[stark-rs prove] strict witness precheck failed: verify_com rejected sigma_com");
        }
        return SPX_P2_RUST_ERR_PROVE;
    }
    let sigma_c = std::slice::from_raw_parts(pubi.sigma_c, pubi.sigma_c_len);
    let expected = match rust_build_sigma_c_ciphertext_native(pubi, witv) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if sigma_c != expected {
        if rust_verify_debug_enabled() {
            eprintln!("[stark-rs prove] strict witness precheck failed: sigma_c mismatch");
        }
        return SPX_P2_RUST_ERR_INPUT;
    }
    if rust_verify_debug_enabled() {
        eprintln!("[stark-rs prove] strict witness precheck passed");
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
    // Keep ciphertext semantics aligned with the shared Sigma.C builder while AIR keeps
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
    let [ciphertext_prefix_l0, ciphertext_prefix_l1, ciphertext_prefix_l2] = stmt.ciphertext_prefix_limbs;
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
    let sigma_com_wit = std::slice::from_raw_parts(witv.sigma_com, SPX_SIGMA_COM_LEN);
    let [sigma_com_prefix_l0, sigma_com_prefix_l1, sigma_com_prefix_l2] =
        match derive_signature_witness_prefix_limbs(sigma_com_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let [sigma_com_quarter_l0, sigma_com_quarter_l1, sigma_com_quarter_l2] =
        match derive_signature_witness_quarter_limbs(sigma_com_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let [sigma_com_middle_l0, sigma_com_middle_l1, sigma_com_middle_l2] =
        match derive_signature_witness_middle_limbs(sigma_com_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let [sigma_com_three_quarter_l0, sigma_com_three_quarter_l1, sigma_com_three_quarter_l2] =
        match derive_signature_witness_three_quarter_limbs(sigma_com_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let sigma_com_window_l0 =
        sigma_com_prefix_l0 + sigma_com_quarter_l0 + sigma_com_middle_l0 + sigma_com_three_quarter_l0;
    let sigma_com_window_l1 =
        sigma_com_prefix_l1 + sigma_com_quarter_l1 + sigma_com_middle_l1 + sigma_com_three_quarter_l1;
    let sigma_com_window_l2 =
        sigma_com_prefix_l2 + sigma_com_quarter_l2 + sigma_com_middle_l2 + sigma_com_three_quarter_l2;
    let (sigma_com_tail_base_l0, sigma_com_tail_base_l1_7) =
        match derive_signature_witness_suffix_tail_parts(sigma_com_wit) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    let sigma_com_tail_l0 = sigma_com_tail_base_l0;
    let sigma_com_tail_l1_7 = sigma_com_tail_base_l1_7;
    let (omega2_b0, omega2_hi7, omega2_b8, omega2_mid7, omega2_b16, omega2_last7) =
        match derive_omega2_tail_block_parts(omega2_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let (ciphertext_prev_prev_block, ciphertext_prev_block, ciphertext_final_block) =
        match derive_ciphertext_suffix_blocks(pk_e, com, sigma_com_wit, omega2_wit) {
            Some(v) => v,
            None => return SPX_P2_RUST_ERR_INPUT,
        };
    let ciphertext_blocks = match build_ciphertext_absorb_blocks(pk_e, com, sigma_com_wit, omega2_wit) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    let ciphertext_suffix_state_chain = match derive_ciphertext_suffix_state_chain(&ciphertext_blocks) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    if rust_verify_debug_enabled() {
        eprintln!("[stark-rs prove] entering trace build and Winterfell proving");
    }
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
    let trace_calls_fe = goldilocks_fe(trace_calls as u64);
    let witness_rows_fe = goldilocks_fe(witness_rows as u64);
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
        ciphertext_prefix_l0,
        ciphertext_prefix_l1,
        ciphertext_prefix_l2,
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
        sigma_com_window_l0,
        sigma_com_window_l1,
        sigma_com_window_l2,
        sigma_com_tail_l0,
        sigma_com_tail_l1_7,
        omega2_b0,
        omega2_hi7,
        omega2_b8,
        omega2_mid7,
        omega2_b16,
        omega2_last7,
        ciphertext_suffix_state_chain,
        TRACE_LEN,
    );
    if let Some((row, constraint, value)) = debug_validate_commit_opening_columns(
        &trace,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
        ciphertext_prefix_l0,
        ciphertext_prefix_l1,
        ciphertext_prefix_l2,
            ciphertext_prev_prev_block,
            ciphertext_prev_block,
            ciphertext_final_block,
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
        ciphertext_prefix_l0,
        ciphertext_prefix_l1,
        ciphertext_prefix_l2,
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
        Err(e) => {
            if rust_verify_debug_enabled() {
                eprintln!("[stark-rs prove] winterfell prove failed: {:?}", e);
            }
            return SPX_P2_RUST_ERR_PROVE;
        }
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
        None => {
            if rust_verify_debug_enabled() {
                let total_len = PI_F_V2_FIXED_HEADER_BYTES
                    + SPX_N
                    + SPX_N
                    + SPX_N
                    + 4
                    + proof_bytes.len()
                    + PI_F_V2_RESERVED_BYTES;
                eprintln!(
                    "[stark-rs prove] output buffer too small: cap={} required={} proof_bytes={}",
                    out.cap,
                    total_len,
                    proof_bytes.len()
                );
            }
            return SPX_P2_RUST_ERR_BUFFER_SMALL;
        }
    };
    out.len = encoded_len;

    let _ = result;
    SPX_P2_RUST_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_scheduler_materializes_final_three_blocks() {
        let pk_e = [0x11u8; SPX_N];
        let com = [0x22u8; COM_LEN];
        let sigma_com = vec![0x33u8; SPX_SIGMA_COM_LEN];
        let omega2 = [0x44u8; SPX_N];

        let (prev_prev, prev, final_block) =
            derive_ciphertext_suffix_blocks(&pk_e, &com, &sigma_com, &omega2).expect("suffix blocks");

        assert_eq!(prev_prev.len(), POSEIDON2_RATE_LANES);
        assert_eq!(prev.len(), POSEIDON2_RATE_LANES);
        assert_eq!(final_block.len(), POSEIDON2_RATE_LANES);

        let (tail_l0, tail_l1_7) =
            derive_signature_witness_suffix_tail_parts(&sigma_com).expect("tail15");
        let (omega2_b0, omega2_hi7, omega2_b8, omega2_mid7, omega2_b16, omega2_last7) =
            derive_omega2_tail_block_parts(&omega2).expect("omega2 tail");

        assert_eq!(final_block[0], tail_l0);
        assert_eq!(
            final_block[1],
            tail_l1_7 + omega2_b0 * goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT)
        );
        assert_eq!(
            final_block[2],
            omega2_hi7 + omega2_b8 * goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT)
        );
        assert_eq!(
            final_block[3],
            omega2_mid7 + omega2_b16 * goldilocks_fe(CIPHERTEXT_SPLIT_BYTE7_SHIFT)
        );
        assert_eq!(
            final_block[4],
            omega2_last7 + goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE4_BASE)
        );
        assert_eq!(final_block[5], goldilocks_fe(CIPHERTEXT_FINAL_PAD_LANE5_BASE));
    }

    #[test]
    fn ciphertext_scheduler_respects_domain_and_nul_label_prefix() {
        let pk_e = [0u8; SPX_N];
        let com = [0u8; COM_LEN];
        let sigma_com = Vec::new();
        let omega2 = [0u8; SPX_N];
        let blocks = build_ciphertext_absorb_blocks(&pk_e, &com, &sigma_com, &omega2).expect("blocks");

        let expected_prefix = canonicalize_ciphertext_prefix_limbs();
        assert_eq!(blocks[0][0], expected_prefix[0]);
        assert_eq!(blocks[0][1], expected_prefix[1]);
        assert_eq!(blocks[0][2], expected_prefix[2]);
    }

    #[test]
    fn ciphertext_suffix_state_chain_respects_absorb_and_output_binding() {
        let pk_e = [0x51u8; SPX_N];
        let com = [0x29u8; COM_LEN];
        let sigma_com = vec![0x87u8; SPX_SIGMA_COM_LEN];
        let omega2 = [0x13u8; SPX_N];
        let blocks = build_ciphertext_absorb_blocks(&pk_e, &com, &sigma_com, &omega2).expect("blocks");
        let chain = derive_ciphertext_suffix_state_chain(&blocks).expect("state chain");
        let last = blocks.len() - 1;
        let suffix_slice = &blocks[blocks.len() - CIPHERTEXT_SUFFIX_BLOCK_COUNT..];
        assert_eq!(&chain.suffix_blocks[..], suffix_slice);

        let mut replay_state = [0u64; POSEIDON2_T];
        let mut replay_start_post = [0u64; POSEIDON2_T];
        let mut replay_final_post = [0u64; POSEIDON2_T];
        for (idx, block) in blocks.iter().enumerate() {
            let (pre_state, _) = goldilocks_absorb_state_with_block(replay_state, *block);
            replay_state = poseidon2_permute_state(pre_state);
            if idx + CIPHERTEXT_SUFFIX_BLOCK_COUNT + 1 == blocks.len() {
                replay_start_post = replay_state;
            }
            if idx == last {
                replay_final_post = replay_state;
            }
        }
        assert_eq!(chain.start_post_state, poseidon2_state_from_u64(replay_start_post));
        assert_eq!(
            chain.post_states[CIPHERTEXT_SUFFIX_BLOCK_COUNT - 1],
            poseidon2_state_from_u64(replay_final_post)
        );
        for block_idx in 0..CIPHERTEXT_SUFFIX_BLOCK_COUNT {
            let prev_post = if block_idx == 0 {
                chain.start_post_state
            } else {
                chain.post_states[block_idx - 1]
            };
            for lane in 0..POSEIDON2_RATE_LANES {
                let (want, carry) = goldilocks_add_with_carry(
                    prev_post[lane].as_int() as u64,
                    chain.suffix_blocks[block_idx][lane].as_int() as u64,
                );
                assert_eq!(chain.pre_states[block_idx][lane], goldilocks_fe(want));
                assert_eq!(chain.carries[block_idx][lane], goldilocks_fe(carry));
            }
            for lane in POSEIDON2_RATE_LANES..POSEIDON2_T {
                assert_eq!(chain.pre_states[block_idx][lane], prev_post[lane]);
            }
        }
    }
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
        || decoded.framework_id != PI_F_V2_FRAMEWORK_ID_FISCHLIN_STRICT
        || decoded.signature_system_id != PI_F_V2_SIGNATURE_SYSTEM_ID_SPHINCSPLUS_POSEIDON2
    {
        rust_verify_debug("header flags/system_id/statement/framework/signature mismatch");
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
    let [ciphertext_prefix_l0, ciphertext_prefix_l1, ciphertext_prefix_l2] = stmt.ciphertext_prefix_limbs;
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
        trace_calls: goldilocks_fe(trace_calls as u64),
        row_count: goldilocks_fe(witness_rows as u64),
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
        ciphertext_prefix_l0,
        ciphertext_prefix_l1,
        ciphertext_prefix_l2,
        pk_e_public_l0,
        pk_e_public_l1,
        pk_e_public_l2,
        com_input_public_l0,
        com_input_public_l1,
        com_input_public_l2,
        com_input_m_tail,
    };
    // Under Goldilocks with FieldExtension::None, Winterfell's conjectured-security
    // estimate is capped at 63 bits. Keep verifier policy aligned with the actual
    // proof options rather than rejecting valid proofs at the boundary.
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
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
