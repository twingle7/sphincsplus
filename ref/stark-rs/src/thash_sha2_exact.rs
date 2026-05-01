#![allow(dead_code)]

use std::time::Instant;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, ProofOptions, Prover, StarkDomain,
    Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::{
    SPX_P2_RUST_ERR_INPUT, SPX_P2_RUST_ERR_NULL, SPX_P2_RUST_ERR_PROVE, SPX_P2_RUST_OK,
};

const SPX_THASH_BENCH_BACKEND_SHA2_V1: u32 = 1;
const SPX_THASH_BENCH_MODE_SHA2_EXACT_V1: u32 = 2;
const SPX_N: usize = 24;
const SPX_ADDR_WORDS: usize = 8;
const SPX_ADDR_BYTES: usize = SPX_ADDR_WORDS * 4;
const SPX_SHA256_ADDR_BYTES: usize = 22;
const SHA512_BLOCK_BYTES: usize = 128;
const SHA512_WORDS: usize = 16;
const SHA512_ROUNDS: usize = 80;
const SHA2_EXACT_TRACE_LENGTH: usize = 128;
const SHA2_EXACT_PERIOD: usize = 128;
const SHA2_EXACT_TRACE_WIDTH: usize = 564;
const SHA2_EXACT_TRANSITION_CONSTRAINTS: usize = 572;
const SHA2_EXACT_BOUNDARY_ASSERTIONS: usize = 189;

// V2 layout plan: replace the legacy one-row-per-round, 564-column design with
// an 8-micro-step trace. Each micro-step handles 8 bits for the exact bitwise
// SHA-512 relations so the final trace stays within Winterfell's 255-column cap.
const SHA2_EXACT_V2_MICRO_STEPS: usize = 8;
const SHA2_EXACT_V2_BITS_PER_ROW: usize = 8;
const SHA2_EXACT_V2_ACTIVE_ROWS: usize = SHA512_ROUNDS * SHA2_EXACT_V2_MICRO_STEPS;
const SHA2_EXACT_V2_TRACE_LENGTH: usize = 1024;
const SHA2_EXACT_V2_TRACE_WIDTH_TARGET: usize = 96;
const SHA2_EXACT_V2_PERIOD: usize = 8;
const SHA2_EXACT_V2_TRACE_WIDTH: usize = 65;
const SHA2_EXACT_V2_TRANSITION_CONSTRAINTS: usize = 139;
const SHA2_EXACT_V2_ROUND_AUX_WORDS: usize = 11;
const SHA2_EXACT_V2_SLICE_COLUMNS: usize = 8;
const SHA2_EXACT_V2_BOUNDARY_ASSERTIONS: usize = 7550;

const V2_COL_ROUND: usize = 0;
const V2_COL_MICRO: usize = 1;
const V2_COL_ACTIVE: usize = 2;
const V2_COL_STATE_START: usize = 3;
const V2_COL_WINDOW_START: usize = 11;
const V2_COL_K: usize = 27;
const V2_COL_BIG_SIGMA0: usize = 28;
const V2_COL_BIG_SIGMA1: usize = 29;
const V2_COL_CH: usize = 30;
const V2_COL_MAJ: usize = 31;
const V2_COL_T1: usize = 32;
const V2_COL_T2: usize = 33;
const V2_COL_T1_CARRY: usize = 34;
const V2_COL_T2_CARRY: usize = 35;
const V2_COL_SCHEDULE_CARRY: usize = 36;
const V2_COL_STATE0_CARRY: usize = 37;
const V2_COL_STATE4_CARRY: usize = 38;
const V2_COL_DIGEST_START: usize = 39;
const V2_COL_DIGEST_CARRY_START: usize = 47;
const V2_COL_LAST_ROUND: usize = 55;
const V2_COL_SCHEDULE_ACTIVE: usize = 56;
const V2_COL_A_SLICE: usize = 57;
const V2_COL_B_SLICE: usize = 58;
const V2_COL_C_SLICE: usize = 59;
const V2_COL_E_SLICE: usize = 60;
const V2_COL_F_SLICE: usize = 61;
const V2_COL_G_SLICE: usize = 62;
const V2_COL_W1_SLICE: usize = 63;
const V2_COL_W14_SLICE: usize = 64;

const COL_ROUND: usize = 0;
const COL_ACTIVE: usize = 1;
const COL_STATE_START: usize = 2;
const COL_WINDOW_START: usize = 10;
const COL_K: usize = 26;
const COL_BIG_SIGMA0: usize = 27;
const COL_BIG_SIGMA1: usize = 28;
const COL_CH: usize = 29;
const COL_MAJ: usize = 30;
const COL_T1: usize = 31;
const COL_T2: usize = 32;
const COL_T1_CARRY: usize = 33;
const COL_T2_CARRY: usize = 34;
const COL_SCHEDULE_CARRY: usize = 35;
const COL_DIGEST_START: usize = 36;
const COL_DIGEST_CARRY_START: usize = 44;
const COL_A_BITS_START: usize = 52;
const COL_B_BITS_START: usize = COL_A_BITS_START + 64;
const COL_C_BITS_START: usize = COL_B_BITS_START + 64;
const COL_E_BITS_START: usize = COL_C_BITS_START + 64;
const COL_F_BITS_START: usize = COL_E_BITS_START + 64;
const COL_G_BITS_START: usize = COL_F_BITS_START + 64;
const COL_W1_BITS_START: usize = COL_G_BITS_START + 64;
const COL_W14_BITS_START: usize = COL_W1_BITS_START + 64;

const TWO64_MOD_P: u64 = 0xffff_ffff;

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

const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SHA512_K: [u64; SHA512_ROUNDS] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
pub(crate) struct Sha2ExactPreparedV1 {
    pub msg_len: usize,
    pub msg_bytes: [u8; SPX_SHA256_ADDR_BYTES + 2 * SPX_N],
    pub padded_block: [u8; SHA512_BLOCK_BYTES],
    pub schedule_words: [u64; SHA512_ROUNDS],
    pub initial_state: [u64; 8],
}

fn load_be_u64(bytes: &[u8]) -> u64 {
    let mut acc = 0u64;
    for &byte in bytes {
        acc = (acc << 8) | byte as u64;
    }
    acc
}

fn store_be_u64(dst: &mut [u8], value: u64) {
    dst.copy_from_slice(&value.to_be_bytes());
}

fn u32_words_as_le_bytes(addr: &[u32; SPX_ADDR_WORDS]) -> [u8; SPX_ADDR_WORDS * 4] {
    let mut out = [0u8; SPX_ADDR_WORDS * 4];
    for (i, word) in addr.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[inline(always)]
fn rotr64(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline(always)]
fn big_sigma0(x: u64) -> u64 {
    rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)
}

#[inline(always)]
fn big_sigma1(x: u64) -> u64 {
    rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)
}

#[inline(always)]
fn small_sigma0(x: u64) -> u64 {
    rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
}

#[inline(always)]
fn small_sigma1(x: u64) -> u64 {
    rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6)
}

#[inline(always)]
pub(crate) fn sha512_ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

#[inline(always)]
pub(crate) fn sha512_maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sha2_mix_bytes(parts: &[&[u8]]) -> u64 {
    let mut acc = 0xcbf29ce484222325u64;
    for part in parts {
        for &b in *part {
            acc ^= b as u64;
            acc = acc.rotate_left(7).wrapping_mul(0x100000001b3);
        }
    }
    acc
}

#[inline(always)]
fn split_u128_mod_2_64(sum: u128) -> (u64, u64) {
    ((sum & 0xffff_ffff_ffff_ffff) as u64, (sum >> 64) as u64)
}

fn compute_sha2_add_carries(skeleton: &Sha2ExactTraceSkeletonV1) -> Sha2AddCarriesV1 {
    let final_round = &skeleton.round_rows[SHA512_ROUNDS - 1];
    let [a, b, c, d, e, f, g, h] = final_round.state_in;
    let _ = (b, c, d, f, g);
    let sigma1 = big_sigma1(e) as u128;
    let ch = sha512_ch(e, f, g) as u128;
    let t1_sum = (h as u128)
        + sigma1
        + ch
        + (final_round.k as u128)
        + (final_round.w as u128);
    let (_, t1_carry) = split_u128_mod_2_64(t1_sum);

    let sigma0 = big_sigma0(a) as u128;
    let maj = sha512_maj(a, b, c) as u128;
    let t2_sum = sigma0 + maj;
    let (_, t2_carry) = split_u128_mod_2_64(t2_sum);

    let mut digest_carry = [0u64; 8];
    for i in 0..8 {
        let (_, carry) = split_u128_mod_2_64(
            (skeleton.final_state[i] as u128) + (skeleton.initial_state[i] as u128),
        );
        digest_carry[i] = carry;
    }

    Sha2AddCarriesV1 {
        t1: t1_carry,
        t2: t2_carry,
        digest: digest_carry,
    }
}

fn fe(value: u64) -> BaseElement {
    BaseElement::new(value as u128)
}

const SHA512_SEEDED_BYTES: usize = SHA512_BLOCK_BYTES;

fn bit(value: u64, idx: usize) -> BaseElement {
    BaseElement::new(((value >> idx) & 1) as u128)
}

fn word_from_bits_row(current: &[BaseElement], start: usize) -> BaseElement {
    let mut acc = BaseElement::ZERO;
    for i in 0..64 {
        acc += current[start + i] * BaseElement::new((1u128) << i);
    }
    acc
}

fn word_from_bits_row_base<E: FieldElement + From<BaseElement>>(current: &[E], start: usize) -> E {
    let mut acc = E::ZERO;
    for i in 0..64 {
        acc += current[start + i] * E::from(BaseElement::new((1u128) << i));
    }
    acc
}

fn carry_degree4<E: FieldElement + From<BaseElement>>(x: E) -> E {
    x * (x - E::ONE) * (x - E::from(fe(2))) * (x - E::from(fe(3)))
}

fn carry_degree5<E: FieldElement + From<BaseElement>>(x: E) -> E {
    x * (x - E::ONE) * (x - E::from(fe(2))) * (x - E::from(fe(3))) * (x - E::from(fe(4)))
}

fn trace_row_values(trace: &TraceTable<BaseElement>, row: usize) -> Vec<BaseElement> {
    (0..trace.width())
        .map(|col| trace.get(col, row))
        .collect()
}

fn xor3_bits<E: FieldElement>(x: E, y: E, z: E) -> E {
    x + y + z - (x * y + x * z + y * z) * E::from(2u32) + (x * y * z) * E::from(4u32)
}

fn maj_bits<E: FieldElement>(x: E, y: E, z: E) -> E {
    x * y + x * z + y * z - (x * y * z) * E::from(2u32)
}

fn ch_bits<E: FieldElement>(x: E, y: E, z: E) -> E {
    x * y + (E::ONE - x) * z
}

fn xor_rot_word_from_bits<E: FieldElement + From<BaseElement>>(
    current: &[E],
    start: usize,
    r1: usize,
    r2: usize,
    r3: usize,
) -> E {
    let mut acc = E::ZERO;
    for i in 0..64 {
        let b1 = current[start + ((i + r1) & 63)];
        let b2 = current[start + ((i + r2) & 63)];
        let b3 = current[start + ((i + r3) & 63)];
        acc += xor3_bits(b1, b2, b3) * E::from(BaseElement::new((1u128) << i));
    }
    acc
}

fn small_sigma_word_from_bits<E: FieldElement + From<BaseElement>>(
    current: &[E],
    start: usize,
    r1: usize,
    r2: usize,
    shr: usize,
) -> E {
    let mut acc = E::ZERO;
    for i in 0..64 {
        let b1 = current[start + ((i + r1) & 63)];
        let b2 = current[start + ((i + r2) & 63)];
        let b3 = if i + shr < 64 {
            current[start + i + shr]
        } else {
            E::ZERO
        };
        acc += xor3_bits(b1, b2, b3) * E::from(BaseElement::new((1u128) << i));
    }
    acc
}

fn binary_word_formula<E: FieldElement + From<BaseElement>, F: Fn(E, E, E) -> E>(
    current: &[E],
    x_start: usize,
    y_start: usize,
    z_start: usize,
    f: F,
) -> E {
    let mut acc = E::ZERO;
    for i in 0..64 {
        acc += f(current[x_start + i], current[y_start + i], current[z_start + i])
            * E::from(BaseElement::new((1u128) << i));
    }
    acc
}

#[derive(Clone)]
pub(crate) struct Sha2ExactTraceSkeletonV1 {
    pub initial_state: [u64; 8],
    pub schedule_words: [u64; SHA512_ROUNDS],
    pub round_rows: [Sha2RoundRowV1; SHA512_ROUNDS],
    pub round_states: [[u64; 8]; SHA512_ROUNDS + 1],
    pub final_state: [u64; 8],
    pub digest_state: [u64; 8],
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Sha2RoundRowV1 {
    pub round: u32,
    pub state_in: [u64; 8],
    pub w: u64,
    pub k: u64,
    pub t1: u64,
    pub t2: u64,
    pub state_out: [u64; 8],
}

#[derive(Clone)]
struct Sha2ExactPublicInputs {
    initial_state: [BaseElement; 8],
    digest_state: [BaseElement; 8],
    schedule_words: [BaseElement; SHA512_ROUNDS],
    v2_round_aux: [[BaseElement; SHA2_EXACT_V2_ROUND_AUX_WORDS]; SHA512_ROUNDS],
    v2_slice_rows: [[BaseElement; SHA2_EXACT_V2_SLICE_COLUMNS]; SHA2_EXACT_V2_ACTIVE_ROWS],
}

impl ToElements<BaseElement> for Sha2ExactPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = Vec::with_capacity(
            16
                + SHA512_ROUNDS
                + SHA512_ROUNDS * SHA2_EXACT_V2_ROUND_AUX_WORDS
                + SHA2_EXACT_V2_ACTIVE_ROWS * SHA2_EXACT_V2_SLICE_COLUMNS,
        );
        out.extend_from_slice(&self.initial_state);
        out.extend_from_slice(&self.digest_state);
        out.extend_from_slice(&self.schedule_words);
        for row in &self.v2_round_aux {
            out.extend_from_slice(row);
        }
        for row in &self.v2_slice_rows {
            out.extend_from_slice(row);
        }
        out
    }
}

struct Sha2ExactAir {
    context: AirContext<BaseElement>,
    initial_state: [BaseElement; 8],
    digest_state: [BaseElement; 8],
    schedule_words: [BaseElement; SHA512_ROUNDS],
}

struct Sha2ExactProver {
    options: ProofOptions,
    pub_inputs: Sha2ExactPublicInputs,
}

struct Sha2ExactAirV2 {
    context: AirContext<BaseElement>,
    initial_state: [BaseElement; 8],
    digest_state: [BaseElement; 8],
    schedule_words: [BaseElement; SHA512_ROUNDS],
    v2_round_aux: [[BaseElement; SHA2_EXACT_V2_ROUND_AUX_WORDS]; SHA512_ROUNDS],
    v2_slice_rows: [[BaseElement; SHA2_EXACT_V2_SLICE_COLUMNS]; SHA2_EXACT_V2_ACTIVE_ROWS],
}

struct Sha2ExactProverV2 {
    options: ProofOptions,
    pub_inputs: Sha2ExactPublicInputs,
}

#[derive(Clone, Copy)]
struct Sha2AddCarriesV1 {
    t1: u64,
    t2: u64,
    digest: [u64; 8],
}

#[derive(Clone, Copy, Debug, Default)]
struct Sha2BitSliceWitnessV2 {
    bit_base: usize,
    a: u8,
    b: u8,
    c: u8,
    e: u8,
    f: u8,
    g: u8,
    w1: u8,
    w14: u8,
}

#[inline(always)]
fn sha2_v2_round_of_row(row: usize) -> usize {
    row / SHA2_EXACT_V2_MICRO_STEPS
}

#[inline(always)]
fn sha2_v2_micro_of_row(row: usize) -> usize {
    row % SHA2_EXACT_V2_MICRO_STEPS
}

#[inline(always)]
fn sha2_v2_bit_base(micro: usize) -> usize {
    micro * SHA2_EXACT_V2_BITS_PER_ROW
}

#[inline(always)]
fn sha2_v2_slice_u8(value: u64, bit_base: usize) -> u8 {
    debug_assert!(bit_base + SHA2_EXACT_V2_BITS_PER_ROW <= 64);
    ((value >> bit_base) & 0xff) as u8
}

fn sha2_v2_bit_slice_witness(
    row: &Sha2RoundRowV1,
    w1: u64,
    w14: u64,
    micro: usize,
) -> Sha2BitSliceWitnessV2 {
    let bit_base = sha2_v2_bit_base(micro);
    Sha2BitSliceWitnessV2 {
        bit_base,
        a: sha2_v2_slice_u8(row.state_in[0], bit_base),
        b: sha2_v2_slice_u8(row.state_in[1], bit_base),
        c: sha2_v2_slice_u8(row.state_in[2], bit_base),
        e: sha2_v2_slice_u8(row.state_in[4], bit_base),
        f: sha2_v2_slice_u8(row.state_in[5], bit_base),
        g: sha2_v2_slice_u8(row.state_in[6], bit_base),
        w1: sha2_v2_slice_u8(w1, bit_base),
        w14: sha2_v2_slice_u8(w14, bit_base),
    }
}

fn sha2_exact_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn sha512_compress_block(initial_state: [u64; 8], block: &[u8; SHA512_BLOCK_BYTES]) -> [u64; 8] {
    let mut schedule_words = [0u64; SHA512_ROUNDS];
    let mut round_state = initial_state;
    for i in 0..SHA512_WORDS {
        let start = i * 8;
        schedule_words[i] = load_be_u64(&block[start..start + 8]);
    }
    for i in SHA512_WORDS..SHA512_ROUNDS {
        schedule_words[i] = small_sigma1(schedule_words[i - 2])
            .wrapping_add(schedule_words[i - 7])
            .wrapping_add(small_sigma0(schedule_words[i - 15]))
            .wrapping_add(schedule_words[i - 16]);
    }
    for round in 0..SHA512_ROUNDS {
        round_state = sha512_round_step(round_state, schedule_words[round], SHA512_K[round]);
    }
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = round_state[i].wrapping_add(initial_state[i]);
    }
    out
}

pub(crate) fn build_seeded_sha512_initial_state(pub_seed: &[u8; SPX_N]) -> [u64; 8] {
    let mut block = [0u8; SHA512_BLOCK_BYTES];
    block[..SPX_N].copy_from_slice(pub_seed);
    sha512_compress_block(SHA512_IV, &block)
}

pub(crate) fn prepare_sha2_thash_192s_inblocks2(
    pub_seed: &[u8; SPX_N],
    addr_words: &[u32; SPX_ADDR_WORDS],
    input: &[u8; 2 * SPX_N],
) -> Sha2ExactPreparedV1 {
    let addr_bytes = u32_words_as_le_bytes(addr_words);
    let mut msg_bytes = [0u8; SPX_SHA256_ADDR_BYTES + 2 * SPX_N];
    let mut padded_block = [0u8; SHA512_BLOCK_BYTES];
    let mut schedule_words = [0u64; SHA512_ROUNDS];
    let msg_len = msg_bytes.len();
    // Match sha512_inc_finalize(): the final length includes the already
    // absorbed pub_seed block stored in ctx->state_seeded_512.
    let bit_len = ((SHA512_SEEDED_BYTES + msg_len) as u64) * 8;

    msg_bytes[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&addr_bytes[..SPX_SHA256_ADDR_BYTES]);
    msg_bytes[SPX_SHA256_ADDR_BYTES..].copy_from_slice(input);

    padded_block[..msg_len].copy_from_slice(&msg_bytes);
    padded_block[msg_len] = 0x80;
    padded_block[SHA512_BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_be_bytes());

    for i in 0..SHA512_WORDS {
        let start = i * 8;
        schedule_words[i] = load_be_u64(&padded_block[start..start + 8]);
    }
    for i in SHA512_WORDS..SHA512_ROUNDS {
        schedule_words[i] = small_sigma1(schedule_words[i - 2])
            .wrapping_add(schedule_words[i - 7])
            .wrapping_add(small_sigma0(schedule_words[i - 15]))
            .wrapping_add(schedule_words[i - 16]);
    }

    Sha2ExactPreparedV1 {
        msg_len,
        msg_bytes,
        padded_block,
        schedule_words,
        initial_state: build_seeded_sha512_initial_state(pub_seed),
    }
}

pub(crate) fn build_sha2_trace_skeleton_192s_inblocks2(
    pub_seed: &[u8; SPX_N],
    addr_words: &[u32; SPX_ADDR_WORDS],
    input: &[u8; 2 * SPX_N],
) -> Sha2ExactTraceSkeletonV1 {
    let prepared = prepare_sha2_thash_192s_inblocks2(pub_seed, addr_words, input);
    let mut round_rows = [Sha2RoundRowV1::default(); SHA512_ROUNDS];
    let mut round_states = [[0u64; 8]; SHA512_ROUNDS + 1];
    round_states[0] = prepared.initial_state;
    for round in 0..SHA512_ROUNDS {
        let state_in = round_states[round];
        let [a, b, c, _d, e, f, g, h] = state_in;
        let w = prepared.schedule_words[round];
        let k = SHA512_K[round];
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(sha512_ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = big_sigma0(a).wrapping_add(sha512_maj(a, b, c));
        let state_out = sha512_round_step(state_in, w, k);
        round_rows[round] = Sha2RoundRowV1 {
            round: round as u32,
            state_in,
            w,
            k,
            t1,
            t2,
            state_out,
        };
        round_states[round + 1] = state_out;
    }
    let final_state = round_states[SHA512_ROUNDS];
    let mut digest_state = [0u64; 8];
    for i in 0..8 {
        digest_state[i] = final_state[i].wrapping_add(prepared.initial_state[i]);
    }
    Sha2ExactTraceSkeletonV1 {
        initial_state: prepared.initial_state,
        schedule_words: prepared.schedule_words,
        round_rows,
        round_states,
        final_state,
        digest_state,
    }
}

fn sha2_digest_prefix_192s(digest_state: &[u64; 8]) -> [u8; SPX_N] {
    let mut out = [0u8; SPX_N];
    for i in 0..3 {
        store_be_u64(&mut out[i * 8..(i + 1) * 8], digest_state[i]);
    }
    out
}

fn fill_sha2_exact_v2_row(
    state: &mut [BaseElement],
    skeleton: &Sha2ExactTraceSkeletonV1,
    row_idx: usize,
) {
    let active = row_idx < SHA2_EXACT_V2_ACTIVE_ROWS;
    let round = if active { sha2_v2_round_of_row(row_idx) } else { SHA512_ROUNDS };
    let micro = if active { sha2_v2_micro_of_row(row_idx) } else { 0 };
    let state_words = if round < SHA512_ROUNDS {
        skeleton.round_states[round]
    } else {
        skeleton.final_state
    };

    state[V2_COL_ROUND] = fe(round as u64);
    state[V2_COL_MICRO] = fe(micro as u64);
    state[V2_COL_ACTIVE] = fe(active as u64);

    for i in 0..8 {
        state[V2_COL_STATE_START + i] = fe(state_words[i]);
    }
    for i in 0..8 {
        state[V2_COL_DIGEST_START + i] = fe(skeleton.digest_state[i]);
        state[V2_COL_DIGEST_CARRY_START + i] =
            fe(((skeleton.final_state[i] as u128 + skeleton.initial_state[i] as u128) >> 64) as u64);
    }

    if !active {
        for i in 0..16 {
            state[V2_COL_WINDOW_START + i] = BaseElement::ZERO;
        }
        for col in [
            V2_COL_K,
            V2_COL_BIG_SIGMA0,
            V2_COL_BIG_SIGMA1,
            V2_COL_CH,
            V2_COL_MAJ,
            V2_COL_T1,
            V2_COL_T2,
            V2_COL_T1_CARRY,
            V2_COL_T2_CARRY,
            V2_COL_SCHEDULE_CARRY,
            V2_COL_STATE0_CARRY,
            V2_COL_STATE4_CARRY,
            V2_COL_LAST_ROUND,
            V2_COL_SCHEDULE_ACTIVE,
            V2_COL_A_SLICE,
            V2_COL_B_SLICE,
            V2_COL_C_SLICE,
            V2_COL_E_SLICE,
            V2_COL_F_SLICE,
            V2_COL_G_SLICE,
            V2_COL_W1_SLICE,
            V2_COL_W14_SLICE,
        ] {
            state[col] = BaseElement::ZERO;
        }
        return;
    }

    let row = &skeleton.round_rows[round];
    let (_, t1_carry) = split_u128_mod_2_64(
        (row.state_in[7] as u128)
            + (big_sigma1(row.state_in[4]) as u128)
            + (sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u128)
            + (row.k as u128)
            + (row.w as u128),
    );
    let (_, t2_carry) = split_u128_mod_2_64(
        (big_sigma0(row.state_in[0]) as u128)
            + (sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u128),
    );
    let schedule_carry = if round <= 63 {
        ((skeleton.schedule_words[round] as u128)
            + (skeleton.schedule_words[round + 9] as u128)
            + (small_sigma0(skeleton.schedule_words[round + 1]) as u128)
            + (small_sigma1(skeleton.schedule_words[round + 14]) as u128))
            >> 64
    } else {
        0
    };
    let state0_sum = (row.t1 as u128) + (row.t2 as u128);
    let state4_sum = (row.state_in[3] as u128) + (row.t1 as u128);
    let state0_carry = (state0_sum >> 64) as u64;
    let state4_carry = (state4_sum >> 64) as u64;
    for i in 0..16 {
        let idx = round + i;
        state[V2_COL_WINDOW_START + i] = if idx < SHA512_ROUNDS {
            fe(skeleton.schedule_words[idx])
        } else {
            BaseElement::ZERO
        };
    }

    let w1 = if round + 1 < SHA512_ROUNDS {
        skeleton.schedule_words[round + 1]
    } else {
        0
    };
    let w14 = if round + 14 < SHA512_ROUNDS {
        skeleton.schedule_words[round + 14]
    } else {
        0
    };
    let slice = sha2_v2_bit_slice_witness(row, w1, w14, micro);

    state[V2_COL_K] = fe(row.k);
    state[V2_COL_BIG_SIGMA0] = fe(big_sigma0(row.state_in[0]));
    state[V2_COL_BIG_SIGMA1] = fe(big_sigma1(row.state_in[4]));
    state[V2_COL_CH] = fe(sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]));
    state[V2_COL_MAJ] = fe(sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]));
    state[V2_COL_T1] = fe(row.t1);
    state[V2_COL_T2] = fe(row.t2);
    state[V2_COL_T1_CARRY] = fe(t1_carry);
    state[V2_COL_T2_CARRY] = fe(t2_carry);
    state[V2_COL_SCHEDULE_CARRY] = fe(schedule_carry as u64);
    state[V2_COL_STATE0_CARRY] = fe(state0_carry);
    state[V2_COL_STATE4_CARRY] = fe(state4_carry);
    state[V2_COL_LAST_ROUND] = fe((round + 1 == SHA512_ROUNDS) as u64);
    state[V2_COL_SCHEDULE_ACTIVE] = fe((round < 64) as u64);
    state[V2_COL_A_SLICE] = fe(slice.a as u64);
    state[V2_COL_B_SLICE] = fe(slice.b as u64);
    state[V2_COL_C_SLICE] = fe(slice.c as u64);
    state[V2_COL_E_SLICE] = fe(slice.e as u64);
    state[V2_COL_F_SLICE] = fe(slice.f as u64);
    state[V2_COL_G_SLICE] = fe(slice.g as u64);
    state[V2_COL_W1_SLICE] = fe(slice.w1 as u64);
    state[V2_COL_W14_SLICE] = fe(slice.w14 as u64);
}

fn build_sha2_exact_trace_v2(skeleton: &Sha2ExactTraceSkeletonV1) -> TraceTable<BaseElement> {
    debug_assert!(SHA2_EXACT_V2_TRACE_WIDTH <= SHA2_EXACT_V2_TRACE_WIDTH_TARGET);
    let mut trace = TraceTable::new(SHA2_EXACT_V2_TRACE_WIDTH, SHA2_EXACT_V2_TRACE_LENGTH);
    trace.fill(
        |state| fill_sha2_exact_v2_row(state, skeleton, 0),
        |step, state| fill_sha2_exact_v2_row(state, skeleton, step + 1),
    );
    trace
}

fn debug_validate_sha2_exact_trace_v2(
    trace: &TraceTable<BaseElement>,
    skeleton: &Sha2ExactTraceSkeletonV1,
) -> Option<(usize, usize, BaseElement, BaseElement)> {
    for row in 0..trace.length() {
        let mut expected = vec![BaseElement::ZERO; SHA2_EXACT_V2_TRACE_WIDTH];
        fill_sha2_exact_v2_row(&mut expected, skeleton, row);
        for (col, want) in expected.iter().enumerate() {
            let got = trace.get(col, row);
            if got != *want {
                return Some((row, col, *want, got));
            }
        }
    }
    None
}

fn build_sha2_exact_public_inputs_v2(skeleton: &Sha2ExactTraceSkeletonV1) -> Sha2ExactPublicInputs {
    let mut pub_inputs = build_sha2_exact_public_inputs_v1(skeleton);
    let mut round_aux = [[BaseElement::ZERO; SHA2_EXACT_V2_ROUND_AUX_WORDS]; SHA512_ROUNDS];
    let mut slice_rows = [[BaseElement::ZERO; SHA2_EXACT_V2_SLICE_COLUMNS]; SHA2_EXACT_V2_ACTIVE_ROWS];

    for round in 0..SHA512_ROUNDS {
        let row = &skeleton.round_rows[round];
        let (_, t1_carry) = split_u128_mod_2_64(
            (row.state_in[7] as u128)
                + (big_sigma1(row.state_in[4]) as u128)
                + (sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u128)
                + (row.k as u128)
                + (row.w as u128),
        );
        let (_, t2_carry) = split_u128_mod_2_64(
            (big_sigma0(row.state_in[0]) as u128)
                + (sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u128),
        );
        let schedule_carry = if round <= 63 {
            ((skeleton.schedule_words[round] as u128)
                + (skeleton.schedule_words[round + 9] as u128)
                + (small_sigma0(skeleton.schedule_words[round + 1]) as u128)
                + (small_sigma1(skeleton.schedule_words[round + 14]) as u128))
                >> 64
        } else {
            0
        };
        let state0_carry = (((row.t1 as u128) + (row.t2 as u128)) >> 64) as u64;
        let state4_carry = (((row.state_in[3] as u128) + (row.t1 as u128)) >> 64) as u64;
        round_aux[round] = [
            fe(big_sigma0(row.state_in[0])),
            fe(big_sigma1(row.state_in[4])),
            fe(sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6])),
            fe(sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2])),
            fe(row.t1),
            fe(row.t2),
            fe(t1_carry),
            fe(t2_carry),
            fe(schedule_carry as u64),
            fe(state0_carry),
            fe(state4_carry),
        ];

        let w1 = if round + 1 < SHA512_ROUNDS {
            skeleton.schedule_words[round + 1]
        } else {
            0
        };
        let w14 = if round + 14 < SHA512_ROUNDS {
            skeleton.schedule_words[round + 14]
        } else {
            0
        };
        for micro in 0..SHA2_EXACT_V2_MICRO_STEPS {
            let row_idx = round * SHA2_EXACT_V2_MICRO_STEPS + micro;
            let slice = sha2_v2_bit_slice_witness(row, w1, w14, micro);
            slice_rows[row_idx] = [
                fe(slice.a as u64),
                fe(slice.b as u64),
                fe(slice.c as u64),
                fe(slice.e as u64),
                fe(slice.f as u64),
                fe(slice.g as u64),
                fe(slice.w1 as u64),
                fe(slice.w14 as u64),
            ];
        }
    }

    pub_inputs.v2_round_aux = round_aux;
    pub_inputs.v2_slice_rows = slice_rows;
    pub_inputs
}

fn eval_sha2_exact_v2_transition<E: FieldElement + From<BaseElement>>(
    current: &[E],
    next: &[E],
    periodic_values: &[E],
    initial_state: &[BaseElement; 8],
    result: &mut [E],
) {
    let one = E::ONE;
    let zero = E::ZERO;
    let active = current[V2_COL_ACTIVE];
    let inactive = one - active;
    let last_micro = periodic_values[0];
    let micro_value = periodic_values[1];
    let not_last_micro = one - last_micro;
    let cross_flag = active * last_micro;
    let hold_flag = active * not_last_micro;
    let two64 = E::from(BaseElement::new(1u128 << 64));
    let mut idx = 0usize;

    result[idx] = active * (active - one); idx += 1;
    result[idx] = current[V2_COL_LAST_ROUND] * (current[V2_COL_LAST_ROUND] - one); idx += 1;
    result[idx] = current[V2_COL_SCHEDULE_ACTIVE] * (current[V2_COL_SCHEDULE_ACTIVE] - one); idx += 1;
    result[idx] = active * (current[V2_COL_MICRO] - micro_value); idx += 1;
    result[idx] = hold_flag * (next[V2_COL_ROUND] - current[V2_COL_ROUND]); idx += 1;
    result[idx] = hold_flag * (next[V2_COL_ACTIVE] - current[V2_COL_ACTIVE]); idx += 1;
    result[idx] = hold_flag * (next[V2_COL_MICRO] - (current[V2_COL_MICRO] + one)); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_ROUND] - (current[V2_COL_ROUND] + one)); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * next[V2_COL_MICRO]; idx += 1;
    result[idx] = cross_flag * current[V2_COL_LAST_ROUND] * (next[V2_COL_ACTIVE] - zero); idx += 1;
    result[idx] = cross_flag * current[V2_COL_LAST_ROUND] * (next[V2_COL_ROUND] - (current[V2_COL_ROUND] + one)); idx += 1;
    result[idx] = cross_flag * current[V2_COL_LAST_ROUND] * next[V2_COL_MICRO]; idx += 1;
    result[idx] = inactive * (next[V2_COL_ACTIVE] - current[V2_COL_ACTIVE]); idx += 1;
    result[idx] = inactive * (next[V2_COL_ROUND] - current[V2_COL_ROUND]); idx += 1;
    result[idx] = inactive * (next[V2_COL_MICRO] - current[V2_COL_MICRO]); idx += 1;
    result[idx] = active * carry_degree5(current[V2_COL_T1_CARRY]); idx += 1;
    result[idx] = active * current[V2_COL_T2_CARRY] * (current[V2_COL_T2_CARRY] - one); idx += 1;
    result[idx] = active * carry_degree4(current[V2_COL_SCHEDULE_CARRY]); idx += 1;
    result[idx] = active * current[V2_COL_STATE0_CARRY] * (current[V2_COL_STATE0_CARRY] - one); idx += 1;
    result[idx] = active * current[V2_COL_STATE4_CARRY] * (current[V2_COL_STATE4_CARRY] - one); idx += 1;
    result[idx] = active * (
        current[V2_COL_T1]
            + current[V2_COL_T1_CARRY] * two64
            - current[V2_COL_STATE_START + 7]
            - current[V2_COL_BIG_SIGMA1]
            - current[V2_COL_CH]
            - current[V2_COL_K]
            - current[V2_COL_WINDOW_START]
    ); idx += 1;
    result[idx] = active * (
        current[V2_COL_T2]
            + current[V2_COL_T2_CARRY] * two64
            - current[V2_COL_BIG_SIGMA0]
            - current[V2_COL_MAJ]
    ); idx += 1;
    result[idx] = hold_flag * (next[V2_COL_LAST_ROUND] - current[V2_COL_LAST_ROUND]); idx += 1;
    result[idx] = hold_flag * (next[V2_COL_SCHEDULE_ACTIVE] - current[V2_COL_SCHEDULE_ACTIVE]); idx += 1;

    for i in 0..8 {
        result[idx] = hold_flag * (next[V2_COL_STATE_START + i] - current[V2_COL_STATE_START + i]);
        idx += 1;
    }
    for i in 0..16 {
        result[idx] = hold_flag * (next[V2_COL_WINDOW_START + i] - current[V2_COL_WINDOW_START + i]);
        idx += 1;
    }
    for col in [
        V2_COL_K,
        V2_COL_BIG_SIGMA0,
        V2_COL_BIG_SIGMA1,
        V2_COL_CH,
        V2_COL_MAJ,
        V2_COL_T1,
        V2_COL_T2,
        V2_COL_T1_CARRY,
        V2_COL_T2_CARRY,
        V2_COL_SCHEDULE_CARRY,
        V2_COL_STATE0_CARRY,
        V2_COL_STATE4_CARRY,
    ] {
        result[idx] = hold_flag * (next[col] - current[col]);
        idx += 1;
    }

    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (
        next[V2_COL_STATE_START]
            - (current[V2_COL_T1] + current[V2_COL_T2]
                - current[V2_COL_STATE0_CARRY] * two64)
    ); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 1] - current[V2_COL_STATE_START]); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 2] - current[V2_COL_STATE_START + 1]); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 3] - current[V2_COL_STATE_START + 2]); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (
        next[V2_COL_STATE_START + 4]
            - (current[V2_COL_STATE_START + 3] + current[V2_COL_T1]
                - current[V2_COL_STATE4_CARRY] * two64)
    ); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 5] - current[V2_COL_STATE_START + 4]); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 6] - current[V2_COL_STATE_START + 5]); idx += 1;
    result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND]) * (next[V2_COL_STATE_START + 7] - current[V2_COL_STATE_START + 6]); idx += 1;

    result[idx] = cross_flag
        * (one - current[V2_COL_LAST_ROUND])
        * (one - current[V2_COL_SCHEDULE_ACTIVE])
        * next[V2_COL_WINDOW_START + 15];
    idx += 1;
    for i in 0..15 {
        result[idx] = cross_flag * (one - current[V2_COL_LAST_ROUND])
            * (next[V2_COL_WINDOW_START + i] - current[V2_COL_WINDOW_START + i + 1]);
        idx += 1;
    }
    for col in [
        V2_COL_K,
        V2_COL_BIG_SIGMA0,
        V2_COL_BIG_SIGMA1,
        V2_COL_CH,
        V2_COL_MAJ,
        V2_COL_T1,
        V2_COL_T2,
        V2_COL_T1_CARRY,
        V2_COL_T2_CARRY,
        V2_COL_SCHEDULE_CARRY,
        V2_COL_STATE0_CARRY,
        V2_COL_STATE4_CARRY,
    ] {
        result[idx] = cross_flag * current[V2_COL_LAST_ROUND] * next[col];
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = inactive * (next[V2_COL_STATE_START + i] - current[V2_COL_STATE_START + i]);
        idx += 1;
    }
    for i in 0..16 {
        result[idx] = inactive * (next[V2_COL_WINDOW_START + i] - current[V2_COL_WINDOW_START + i]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = inactive
            * (
                current[V2_COL_DIGEST_START + i]
                    + current[V2_COL_DIGEST_CARRY_START + i] * two64
                    - current[V2_COL_STATE_START + i]
                    - E::from(initial_state[i])
            );
        idx += 1;
    }
    while idx < SHA2_EXACT_V2_TRANSITION_CONSTRAINTS {
        result[idx] = E::ZERO;
        idx += 1;
    }
}

fn debug_validate_sha2_exact_air_v2(
    trace: &TraceTable<BaseElement>,
    pub_inputs: &Sha2ExactPublicInputs,
) -> Option<(usize, usize, BaseElement)> {
    let mut last_micro = vec![BaseElement::ZERO; SHA2_EXACT_V2_PERIOD];
    last_micro[SHA2_EXACT_V2_MICRO_STEPS - 1] = BaseElement::ONE;
    let micro_values = (0..SHA2_EXACT_V2_PERIOD).map(|i| fe(i as u64)).collect::<Vec<_>>();
    for row in 0..(trace.length() - 1) {
        let current = trace_row_values(trace, row);
        let next = trace_row_values(trace, row + 1);
        let periodic = [last_micro[row % SHA2_EXACT_V2_PERIOD], micro_values[row % SHA2_EXACT_V2_PERIOD]];
        let mut result = vec![BaseElement::ZERO; SHA2_EXACT_V2_TRANSITION_CONSTRAINTS];
        eval_sha2_exact_v2_transition(&current, &next, &periodic, &pub_inputs.initial_state, &mut result);
        for (constraint, value) in result.into_iter().enumerate() {
            if value != BaseElement::ZERO {
                return Some((row, constraint, value));
            }
        }
    }
    None
}

fn build_sha2_exact_trace_v1(skeleton: &Sha2ExactTraceSkeletonV1) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(SHA2_EXACT_TRACE_WIDTH, SHA2_EXACT_TRACE_LENGTH);
    trace.fill(
        |state| {
            let row = &skeleton.round_rows[0];
            let (_, t1_carry) = split_u128_mod_2_64(
                (row.state_in[7] as u128)
                    + (big_sigma1(row.state_in[4]) as u128)
                    + (sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u128)
                    + (row.k as u128)
                    + (row.w as u128),
            );
            let (_, t2_carry) = split_u128_mod_2_64(
                (big_sigma0(row.state_in[0]) as u128)
                    + (sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u128),
            );
            let schedule_sum = (skeleton.schedule_words[0] as u128)
                + (skeleton.schedule_words[9] as u128)
                + (small_sigma0(skeleton.schedule_words[1]) as u128)
                + (small_sigma1(skeleton.schedule_words[14]) as u128);
            let (_, schedule_carry) = split_u128_mod_2_64(schedule_sum);

            state[COL_ROUND] = BaseElement::ZERO;
            state[COL_ACTIVE] = BaseElement::ONE;
            for i in 0..8 {
                state[COL_STATE_START + i] = fe(skeleton.round_states[0][i]);
            }
            for i in 0..16 {
                state[COL_WINDOW_START + i] = fe(skeleton.schedule_words[i]);
            }
            state[COL_K] = fe(row.k);
            state[COL_BIG_SIGMA0] = fe(big_sigma0(row.state_in[0]));
            state[COL_BIG_SIGMA1] = fe(big_sigma1(row.state_in[4]));
            state[COL_CH] = fe(sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]));
            state[COL_MAJ] = fe(sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]));
            state[COL_T1] = fe(row.t1);
            state[COL_T2] = fe(row.t2);
            state[COL_T1_CARRY] = fe(t1_carry);
            state[COL_T2_CARRY] = fe(t2_carry);
            state[COL_SCHEDULE_CARRY] = fe(schedule_carry);
            for i in 0..8 {
                state[COL_DIGEST_START + i] = fe(skeleton.digest_state[i]);
                state[COL_DIGEST_CARRY_START + i] =
                    fe(((skeleton.final_state[i] as u128 + skeleton.initial_state[i] as u128) >> 64) as u64);
            }
            for i in 0..64 {
                state[COL_A_BITS_START + i] = bit(row.state_in[0], i);
                state[COL_B_BITS_START + i] = bit(row.state_in[1], i);
                state[COL_C_BITS_START + i] = bit(row.state_in[2], i);
                state[COL_E_BITS_START + i] = bit(row.state_in[4], i);
                state[COL_F_BITS_START + i] = bit(row.state_in[5], i);
                state[COL_G_BITS_START + i] = bit(row.state_in[6], i);
                state[COL_W1_BITS_START + i] = bit(skeleton.schedule_words[1], i);
                state[COL_W14_BITS_START + i] = bit(skeleton.schedule_words[14], i);
            }
        },
        |step, state| {
            let row_idx = step + 1;
            let next_round = if row_idx < SHA512_ROUNDS { row_idx as u64 } else { SHA512_ROUNDS as u64 };
            let active = if row_idx < SHA512_ROUNDS { 1u64 } else { 0u64 };
            state[COL_ROUND] = fe(next_round);
            state[COL_ACTIVE] = fe(active);
            let state_words = if row_idx < SHA512_ROUNDS { skeleton.round_states[row_idx] } else { skeleton.final_state };
            for i in 0..8 {
                state[COL_STATE_START + i] = fe(state_words[i]);
            }
            if row_idx < SHA512_ROUNDS {
                let row = &skeleton.round_rows[row_idx];
                let (_, t1_carry) = split_u128_mod_2_64(
                    (row.state_in[7] as u128)
                        + (big_sigma1(row.state_in[4]) as u128)
                        + (sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u128)
                        + (row.k as u128)
                        + (row.w as u128),
                );
                let (_, t2_carry) = split_u128_mod_2_64(
                    (big_sigma0(row.state_in[0]) as u128)
                        + (sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u128),
                );
                let schedule_carry = if row_idx <= 63 {
                    ((skeleton.schedule_words[row_idx] as u128)
                        + (skeleton.schedule_words[row_idx + 9] as u128)
                        + (small_sigma0(skeleton.schedule_words[row_idx + 1]) as u128)
                        + (small_sigma1(skeleton.schedule_words[row_idx + 14]) as u128))
                        >> 64
                } else {
                    0
                };
                for i in 0..16 {
                    let idx = row_idx + i;
                    state[COL_WINDOW_START + i] = if idx < SHA512_ROUNDS {
                        fe(skeleton.schedule_words[idx])
                    } else {
                        BaseElement::ZERO
                    };
                }
                state[COL_K] = fe(row.k);
                state[COL_BIG_SIGMA0] = fe(big_sigma0(row.state_in[0]));
                state[COL_BIG_SIGMA1] = fe(big_sigma1(row.state_in[4]));
                state[COL_CH] = fe(sha512_ch(row.state_in[4], row.state_in[5], row.state_in[6]));
                state[COL_MAJ] = fe(sha512_maj(row.state_in[0], row.state_in[1], row.state_in[2]));
                state[COL_T1] = fe(row.t1);
                state[COL_T2] = fe(row.t2);
                state[COL_T1_CARRY] = fe(t1_carry);
                state[COL_T2_CARRY] = fe(t2_carry);
                state[COL_SCHEDULE_CARRY] = fe(schedule_carry as u64);
                let w1 = if row_idx + 1 < SHA512_ROUNDS { skeleton.schedule_words[row_idx + 1] } else { 0 };
                let w14 = if row_idx + 14 < SHA512_ROUNDS { skeleton.schedule_words[row_idx + 14] } else { 0 };
                for i in 0..64 {
                    state[COL_A_BITS_START + i] = bit(row.state_in[0], i);
                    state[COL_B_BITS_START + i] = bit(row.state_in[1], i);
                    state[COL_C_BITS_START + i] = bit(row.state_in[2], i);
                    state[COL_E_BITS_START + i] = bit(row.state_in[4], i);
                    state[COL_F_BITS_START + i] = bit(row.state_in[5], i);
                    state[COL_G_BITS_START + i] = bit(row.state_in[6], i);
                    state[COL_W1_BITS_START + i] = bit(w1, i);
                    state[COL_W14_BITS_START + i] = bit(w14, i);
                }
            } else {
                for i in 0..16 {
                    state[COL_WINDOW_START + i] = BaseElement::ZERO;
                }
                state[COL_K] = BaseElement::ZERO;
                state[COL_BIG_SIGMA0] = BaseElement::ZERO;
                state[COL_BIG_SIGMA1] = BaseElement::ZERO;
                state[COL_CH] = BaseElement::ZERO;
                state[COL_MAJ] = BaseElement::ZERO;
                state[COL_T1] = BaseElement::ZERO;
                state[COL_T2] = BaseElement::ZERO;
                state[COL_T1_CARRY] = BaseElement::ZERO;
                state[COL_T2_CARRY] = BaseElement::ZERO;
                state[COL_SCHEDULE_CARRY] = BaseElement::ZERO;
                for i in 0..64 {
                    state[COL_A_BITS_START + i] = BaseElement::ZERO;
                    state[COL_B_BITS_START + i] = BaseElement::ZERO;
                    state[COL_C_BITS_START + i] = BaseElement::ZERO;
                    state[COL_E_BITS_START + i] = BaseElement::ZERO;
                    state[COL_F_BITS_START + i] = BaseElement::ZERO;
                    state[COL_G_BITS_START + i] = BaseElement::ZERO;
                    state[COL_W1_BITS_START + i] = BaseElement::ZERO;
                    state[COL_W14_BITS_START + i] = BaseElement::ZERO;
                }
            }
            for i in 0..8 {
                state[COL_DIGEST_START + i] = fe(skeleton.digest_state[i]);
                state[COL_DIGEST_CARRY_START + i] =
                    fe(((skeleton.final_state[i] as u128 + skeleton.initial_state[i] as u128) >> 64) as u64);
            }
        },
    );
    trace
}

fn build_sha2_exact_public_inputs_v1(skeleton: &Sha2ExactTraceSkeletonV1) -> Sha2ExactPublicInputs {
    let mut initial_state = [BaseElement::ZERO; 8];
    let mut digest_state = [BaseElement::ZERO; 8];
    let mut schedule_words = [BaseElement::ZERO; SHA512_ROUNDS];
    for i in 0..8 {
        initial_state[i] = fe(skeleton.initial_state[i]);
        digest_state[i] = fe(skeleton.digest_state[i]);
    }
    for (i, word) in skeleton.schedule_words.iter().enumerate() {
        schedule_words[i] = fe(*word);
    }
    Sha2ExactPublicInputs {
        initial_state,
        digest_state,
        schedule_words,
        v2_round_aux: [[BaseElement::ZERO; SHA2_EXACT_V2_ROUND_AUX_WORDS]; SHA512_ROUNDS],
        v2_slice_rows: [[BaseElement::ZERO; SHA2_EXACT_V2_SLICE_COLUMNS]; SHA2_EXACT_V2_ACTIVE_ROWS],
    }
}

fn debug_validate_sha2_exact_trace_v1(
    trace: &TraceTable<BaseElement>,
    pub_inputs: &Sha2ExactPublicInputs,
) -> Option<(usize, usize, BaseElement)> {
    let two64 = BaseElement::new(1u128 << 64);
    for row in 0..(trace.length() - 1) {
        let active = trace.get(COL_ACTIVE, row);
        let inactive = BaseElement::ONE - active;
        let row_values = trace_row_values(trace, row);
        let mut idx = 0usize;

        let mut emit = |value: BaseElement| -> Option<(usize, usize, BaseElement)> {
            let out = if value != BaseElement::ZERO {
                Some((row, idx, value))
            } else {
                None
            };
            idx += 1;
            out
        };

        if let Some(v) = emit(active * (active - BaseElement::ONE)) { return Some(v); }
        if let Some(v) = emit(trace.get(COL_ROUND, row + 1) - (trace.get(COL_ROUND, row) + active)) { return Some(v); }
        if let Some(v) = emit(inactive * (trace.get(COL_ACTIVE, row + 1) - trace.get(COL_ACTIVE, row))) { return Some(v); }
        if let Some(v) = emit(
            trace.get(COL_T1_CARRY, row)
                * (trace.get(COL_T1_CARRY, row) - BaseElement::ONE)
                * (trace.get(COL_T1_CARRY, row) - fe(2))
                * (trace.get(COL_T1_CARRY, row) - fe(3))
                * (trace.get(COL_T1_CARRY, row) - fe(4)),
        ) { return Some(v); }
        if let Some(v) = emit(trace.get(COL_T2_CARRY, row) * (trace.get(COL_T2_CARRY, row) - BaseElement::ONE)) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_A_BITS_START) - trace.get(COL_STATE_START, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_B_BITS_START) - trace.get(COL_STATE_START + 1, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_C_BITS_START) - trace.get(COL_STATE_START + 2, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_E_BITS_START) - trace.get(COL_STATE_START + 4, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_F_BITS_START) - trace.get(COL_STATE_START + 5, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_G_BITS_START) - trace.get(COL_STATE_START + 6, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_BIG_SIGMA0, row) - xor_rot_word_from_bits(&row_values, COL_A_BITS_START, 28, 34, 39))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_BIG_SIGMA1, row) - xor_rot_word_from_bits(&row_values, COL_E_BITS_START, 14, 18, 41))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_CH, row) - binary_word_formula(&row_values, COL_E_BITS_START, COL_F_BITS_START, COL_G_BITS_START, ch_bits))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_MAJ, row) - binary_word_formula(&row_values, COL_A_BITS_START, COL_B_BITS_START, COL_C_BITS_START, maj_bits))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_W1_BITS_START) - trace.get(COL_WINDOW_START + 1, row))) { return Some(v); }
        if let Some(v) = emit(active * (word_from_bits_row(&row_values, COL_W14_BITS_START) - trace.get(COL_WINDOW_START + 14, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_T1, row) + trace.get(COL_T1_CARRY, row) * two64
            - trace.get(COL_STATE_START + 7, row) - trace.get(COL_BIG_SIGMA1, row)
            - trace.get(COL_CH, row) - trace.get(COL_K, row) - trace.get(COL_WINDOW_START, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_T2, row) + trace.get(COL_T2_CARRY, row) * two64
            - trace.get(COL_BIG_SIGMA0, row) - trace.get(COL_MAJ, row))) { return Some(v); }
        let schedule_flag = if row < 64 { BaseElement::ONE } else { BaseElement::ZERO };
        if let Some(v) = emit(schedule_flag * carry_degree4(trace.get(COL_SCHEDULE_CARRY, row))) { return Some(v); }
        if let Some(v) = emit(schedule_flag * (
            trace.get(COL_WINDOW_START + 15, row + 1)
                + trace.get(COL_SCHEDULE_CARRY, row) * two64
                - trace.get(COL_WINDOW_START, row)
                - trace.get(COL_WINDOW_START + 9, row)
                - small_sigma_word_from_bits(&row_values, COL_W1_BITS_START, 1, 8, 7)
                - small_sigma_word_from_bits(&row_values, COL_W14_BITS_START, 19, 61, 6)
        )) { return Some(v); }

        if let Some(v) = emit(active * (trace.get(COL_STATE_START, row + 1)
            - (trace.get(COL_T1, row) + trace.get(COL_T2, row)
                - (trace.get(COL_T1_CARRY, row) + trace.get(COL_T2_CARRY, row)) * two64))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 1, row + 1) - trace.get(COL_STATE_START, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 2, row + 1) - trace.get(COL_STATE_START + 1, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 3, row + 1) - trace.get(COL_STATE_START + 2, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 4, row + 1)
            - (trace.get(COL_STATE_START + 3, row) + trace.get(COL_T1, row) - trace.get(COL_T1_CARRY, row) * two64))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 5, row + 1) - trace.get(COL_STATE_START + 4, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 6, row + 1) - trace.get(COL_STATE_START + 5, row))) { return Some(v); }
        if let Some(v) = emit(active * (trace.get(COL_STATE_START + 7, row + 1) - trace.get(COL_STATE_START + 6, row))) { return Some(v); }

        for i in 0..8 {
            if let Some(v) = emit(inactive * (trace.get(COL_STATE_START + i, row + 1) - trace.get(COL_STATE_START + i, row))) { return Some(v); }
        }
        for i in 0..15 {
            if let Some(v) = emit(schedule_flag * (trace.get(COL_WINDOW_START + i, row + 1) - trace.get(COL_WINDOW_START + i + 1, row))) { return Some(v); }
        }
        for i in 0..8 {
            if let Some(v) = emit(inactive * (
                trace.get(COL_DIGEST_START + i, row)
                    + trace.get(COL_DIGEST_CARRY_START + i, row) * two64
                    - trace.get(COL_STATE_START + i, row)
                    - pub_inputs.initial_state[i]
            )) { return Some(v); }
        }
        for start in [
            COL_A_BITS_START,
            COL_B_BITS_START,
            COL_C_BITS_START,
            COL_E_BITS_START,
            COL_F_BITS_START,
            COL_G_BITS_START,
            COL_W1_BITS_START,
            COL_W14_BITS_START,
        ] {
            for i in 0..64 {
                if let Some(v) = emit(trace.get(start + i, row) * (trace.get(start + i, row) - BaseElement::ONE)) {
                    return Some(v);
                }
            }
        }
    }
    None
}

impl Air for Sha2ExactAir {
    type BaseField = BaseElement;
    type PublicInputs = Sha2ExactPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Sha2ExactPublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![SHA2_EXACT_PERIOD]);
            SHA2_EXACT_TRANSITION_CONSTRAINTS
        ];
        Self {
            context: AirContext::new(trace_info, degrees, SHA2_EXACT_BOUNDARY_ASSERTIONS, options),
            initial_state: pub_inputs.initial_state,
            digest_state: pub_inputs.digest_state,
            schedule_words: pub_inputs.schedule_words,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let one = E::ONE;
        let active = current[COL_ACTIVE];
        let inactive = one - active;
        let two64 = E::from(BaseElement::new(1u128 << 64));
        let schedule_flag = periodic_values[0];
        let mut idx = 0usize;

        result[idx] = active * (active - one); idx += 1;
        result[idx] = next[COL_ROUND] - (current[COL_ROUND] + active); idx += 1;
        result[idx] = inactive * (next[COL_ACTIVE] - current[COL_ACTIVE]); idx += 1;
        result[idx] = active * carry_degree4(current[COL_T1_CARRY]); idx += 1;
        result[idx] = active * current[COL_T2_CARRY] * (current[COL_T2_CARRY] - one); idx += 1;

        result[idx] = active * (word_from_bits_row_base(current, COL_A_BITS_START) - current[COL_STATE_START]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_B_BITS_START) - current[COL_STATE_START + 1]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_C_BITS_START) - current[COL_STATE_START + 2]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_E_BITS_START) - current[COL_STATE_START + 4]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_F_BITS_START) - current[COL_STATE_START + 5]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_G_BITS_START) - current[COL_STATE_START + 6]); idx += 1;
        result[idx] = active * (current[COL_BIG_SIGMA0] - xor_rot_word_from_bits(current, COL_A_BITS_START, 28, 34, 39)); idx += 1;
        result[idx] = active * (current[COL_BIG_SIGMA1] - xor_rot_word_from_bits(current, COL_E_BITS_START, 14, 18, 41)); idx += 1;
        result[idx] = active * (current[COL_CH] - binary_word_formula(current, COL_E_BITS_START, COL_F_BITS_START, COL_G_BITS_START, ch_bits)); idx += 1;
        result[idx] = active * (current[COL_MAJ] - binary_word_formula(current, COL_A_BITS_START, COL_B_BITS_START, COL_C_BITS_START, maj_bits)); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_W1_BITS_START) - current[COL_WINDOW_START + 1]); idx += 1;
        result[idx] = active * (word_from_bits_row_base(current, COL_W14_BITS_START) - current[COL_WINDOW_START + 14]); idx += 1;

        result[idx] = active * (current[COL_T1]
            + current[COL_T1_CARRY] * two64
            - current[COL_STATE_START + 7]
            - current[COL_BIG_SIGMA1]
            - current[COL_CH]
            - current[COL_K]
            - current[COL_WINDOW_START]); idx += 1;
        result[idx] = active * (current[COL_T2]
            + current[COL_T2_CARRY] * two64
            - current[COL_BIG_SIGMA0]
            - current[COL_MAJ]); idx += 1;
        result[idx] = schedule_flag * carry_degree4(current[COL_SCHEDULE_CARRY]); idx += 1;
        result[idx] = schedule_flag * (
            next[COL_WINDOW_START + 15]
                + current[COL_SCHEDULE_CARRY] * two64
                - current[COL_WINDOW_START]
                - current[COL_WINDOW_START + 9]
                - small_sigma_word_from_bits(current, COL_W1_BITS_START, 1, 8, 7)
                - small_sigma_word_from_bits(current, COL_W14_BITS_START, 19, 61, 6)
        ); idx += 1;

        result[idx] = active * (next[COL_STATE_START]
            - (current[COL_T1] + current[COL_T2]
                - (current[COL_T1_CARRY] + current[COL_T2_CARRY]) * two64)); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 1] - current[COL_STATE_START]); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 2] - current[COL_STATE_START + 1]); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 3] - current[COL_STATE_START + 2]); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 4]
            - (current[COL_STATE_START + 3] + current[COL_T1] - current[COL_T1_CARRY] * two64)); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 5] - current[COL_STATE_START + 4]); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 6] - current[COL_STATE_START + 5]); idx += 1;
        result[idx] = active * (next[COL_STATE_START + 7] - current[COL_STATE_START + 6]); idx += 1;

        for i in 0..8 {
            result[idx] = inactive * (next[COL_STATE_START + i] - current[COL_STATE_START + i]);
            idx += 1;
        }
        for i in 0..15 {
            result[idx] = schedule_flag * (next[COL_WINDOW_START + i] - current[COL_WINDOW_START + i + 1]);
            idx += 1;
        }
        for i in 0..8 {
            result[idx] = inactive * (
                current[COL_DIGEST_START + i]
                    + current[COL_DIGEST_CARRY_START + i] * two64
                    - current[COL_STATE_START + i]
                    - E::from(self.initial_state[i])
            );
            idx += 1;
        }
        for start in [
            COL_A_BITS_START,
            COL_B_BITS_START,
            COL_C_BITS_START,
            COL_E_BITS_START,
            COL_F_BITS_START,
            COL_G_BITS_START,
            COL_W1_BITS_START,
            COL_W14_BITS_START,
        ] {
            for i in 0..64 {
                result[idx] = active * current[start + i] * (current[start + i] - one);
                idx += 1;
            }
        }
        while idx < SHA2_EXACT_TRANSITION_CONSTRAINTS {
            result[idx] = E::ZERO;
            idx += 1;
        }
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut schedule_flag = vec![BaseElement::ZERO; SHA2_EXACT_PERIOD];
        for value in schedule_flag.iter_mut().take(64) {
            *value = BaseElement::ONE;
        }
        vec![schedule_flag]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = SHA2_EXACT_TRACE_LENGTH - 1;
        let done_row = SHA512_ROUNDS;
        let mut assertions = Vec::with_capacity(SHA2_EXACT_BOUNDARY_ASSERTIONS);
        assertions.push(Assertion::single(COL_ROUND, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_ROUND, done_row, fe(SHA512_ROUNDS as u64)));
        assertions.push(Assertion::single(COL_ACTIVE, 0, BaseElement::ONE));
        assertions.push(Assertion::single(COL_ACTIVE, done_row, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_ACTIVE, last_step, BaseElement::ZERO));
        for i in 0..8 {
            assertions.push(Assertion::single(COL_STATE_START + i, 0, self.initial_state[i]));
        }
        for i in 0..8 {
            assertions.push(Assertion::single(COL_DIGEST_START + i, 0, self.digest_state[i]));
            assertions.push(Assertion::single(COL_DIGEST_START + i, last_step, self.digest_state[i]));
        }
        for row in 0..SHA512_ROUNDS {
            assertions.push(Assertion::single(COL_K, row, fe(SHA512_K[row])));
            assertions.push(Assertion::single(COL_WINDOW_START, row, self.schedule_words[row]));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

impl Sha2ExactProver {
    fn new(options: ProofOptions, pub_inputs: Sha2ExactPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for Sha2ExactProver {
    type BaseField = BaseElement;
    type Air = Sha2ExactAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Sha2ExactPublicInputs {
        self.pub_inputs.clone()
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

impl Air for Sha2ExactAirV2 {
    type BaseField = BaseElement;
    type PublicInputs = Sha2ExactPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Sha2ExactPublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(6, vec![SHA2_EXACT_V2_PERIOD, SHA2_EXACT_V2_PERIOD]);
            SHA2_EXACT_V2_TRANSITION_CONSTRAINTS
        ];
        Self {
            context: AirContext::new(
                trace_info,
                degrees,
                SHA2_EXACT_V2_BOUNDARY_ASSERTIONS,
                options,
            ),
            initial_state: pub_inputs.initial_state,
            digest_state: pub_inputs.digest_state,
            schedule_words: pub_inputs.schedule_words,
            v2_round_aux: pub_inputs.v2_round_aux,
            v2_slice_rows: pub_inputs.v2_slice_rows,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        eval_sha2_exact_v2_transition(
            frame.current(),
            frame.next(),
            periodic_values,
            &self.initial_state,
            result,
        );
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut last_micro = vec![BaseElement::ZERO; SHA2_EXACT_V2_PERIOD];
        last_micro[SHA2_EXACT_V2_MICRO_STEPS - 1] = BaseElement::ONE;
        let micro_values = (0..SHA2_EXACT_V2_PERIOD)
            .map(|i| fe(i as u64))
            .collect::<Vec<_>>();
        vec![last_micro, micro_values]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = SHA2_EXACT_V2_TRACE_LENGTH - 1;
        let done_row = SHA2_EXACT_V2_ACTIVE_ROWS;
        let mut assertions = Vec::with_capacity(SHA2_EXACT_V2_BOUNDARY_ASSERTIONS);
        assertions.push(Assertion::single(V2_COL_ROUND, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(V2_COL_MICRO, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(V2_COL_ACTIVE, 0, BaseElement::ONE));
        assertions.push(Assertion::single(V2_COL_ACTIVE, done_row, BaseElement::ZERO));
        assertions.push(Assertion::single(V2_COL_ACTIVE, last_step, BaseElement::ZERO));
        assertions.push(Assertion::single(V2_COL_ROUND, done_row, fe(SHA512_ROUNDS as u64)));
        for i in 0..8 {
            assertions.push(Assertion::single(V2_COL_STATE_START + i, 0, self.initial_state[i]));
        }
        for i in 0..8 {
            assertions.push(Assertion::single(V2_COL_DIGEST_START + i, 0, self.digest_state[i]));
            assertions.push(Assertion::single(V2_COL_DIGEST_START + i, last_step, self.digest_state[i]));
        }
        for round in 0..SHA512_ROUNDS {
            let row = round * SHA2_EXACT_V2_MICRO_STEPS;
            assertions.push(Assertion::single(V2_COL_K, row, fe(SHA512_K[round])));
            for offset in 0..16 {
                let word = if round + offset < SHA512_ROUNDS {
                    self.schedule_words[round + offset]
                } else {
                    BaseElement::ZERO
                };
                assertions.push(Assertion::single(V2_COL_WINDOW_START + offset, row, word));
            }
            assertions.push(Assertion::single(V2_COL_BIG_SIGMA0, row, self.v2_round_aux[round][0]));
            assertions.push(Assertion::single(V2_COL_BIG_SIGMA1, row, self.v2_round_aux[round][1]));
            assertions.push(Assertion::single(V2_COL_CH, row, self.v2_round_aux[round][2]));
            assertions.push(Assertion::single(V2_COL_MAJ, row, self.v2_round_aux[round][3]));
            assertions.push(Assertion::single(V2_COL_T1, row, self.v2_round_aux[round][4]));
            assertions.push(Assertion::single(V2_COL_T2, row, self.v2_round_aux[round][5]));
            assertions.push(Assertion::single(V2_COL_T1_CARRY, row, self.v2_round_aux[round][6]));
            assertions.push(Assertion::single(V2_COL_T2_CARRY, row, self.v2_round_aux[round][7]));
            assertions.push(Assertion::single(V2_COL_SCHEDULE_CARRY, row, self.v2_round_aux[round][8]));
            assertions.push(Assertion::single(V2_COL_STATE0_CARRY, row, self.v2_round_aux[round][9]));
            assertions.push(Assertion::single(V2_COL_STATE4_CARRY, row, self.v2_round_aux[round][10]));
            assertions.push(Assertion::single(
                V2_COL_LAST_ROUND,
                row,
                fe((round + 1 == SHA512_ROUNDS) as u64),
            ));
            assertions.push(Assertion::single(
                V2_COL_SCHEDULE_ACTIVE,
                row,
                fe((round < 64) as u64),
            ));
        }
        for row in 0..SHA2_EXACT_V2_ACTIVE_ROWS {
            assertions.push(Assertion::single(V2_COL_A_SLICE, row, self.v2_slice_rows[row][0]));
            assertions.push(Assertion::single(V2_COL_B_SLICE, row, self.v2_slice_rows[row][1]));
            assertions.push(Assertion::single(V2_COL_C_SLICE, row, self.v2_slice_rows[row][2]));
            assertions.push(Assertion::single(V2_COL_E_SLICE, row, self.v2_slice_rows[row][3]));
            assertions.push(Assertion::single(V2_COL_F_SLICE, row, self.v2_slice_rows[row][4]));
            assertions.push(Assertion::single(V2_COL_G_SLICE, row, self.v2_slice_rows[row][5]));
            assertions.push(Assertion::single(V2_COL_W1_SLICE, row, self.v2_slice_rows[row][6]));
            assertions.push(Assertion::single(V2_COL_W14_SLICE, row, self.v2_slice_rows[row][7]));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

impl Sha2ExactProverV2 {
    fn new(options: ProofOptions, pub_inputs: Sha2ExactPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for Sha2ExactProverV2 {
    type BaseField = BaseElement;
    type Air = Sha2ExactAirV2;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Sha2ExactPublicInputs {
        self.pub_inputs.clone()
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
pub unsafe extern "C" fn spx_p2_rust_run_sha2_thash_exact_v1(
    out_stats: *mut SpxThashBenchStatsV1,
    inst: *const SpxThashBenchInstanceRawV1,
) -> i32 {
    if out_stats.is_null() || inst.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }

    let inst_ref = &*inst;
    if inst_ref.inblocks == 1 {
        return crate::thash_sha2_f_exact::run_sha2_f_exact(out_stats, inst);
    }
    if inst_ref.backend_id != SPX_THASH_BENCH_BACKEND_SHA2_V1
        || inst_ref.mode != SPX_THASH_BENCH_MODE_SHA2_EXACT_V1
        || inst_ref.inblocks != 2
        || inst_ref.pub_seed.is_null()
        || inst_ref.addr.is_null()
        || inst_ref.input.is_null()
        || inst_ref.expected_output.is_null()
        || inst_ref.input_len != 2 * SPX_N
    {
        return SPX_P2_RUST_ERR_INPUT;
    }

    let pub_seed_slice = std::slice::from_raw_parts(inst_ref.pub_seed, SPX_N);
    let input_slice = std::slice::from_raw_parts(inst_ref.input, 2 * SPX_N);
    let expected_output = std::slice::from_raw_parts(inst_ref.expected_output, SPX_N);
    let addr_slice = std::slice::from_raw_parts(inst_ref.addr, SPX_ADDR_WORDS);

    let mut pub_seed = [0u8; SPX_N];
    pub_seed.copy_from_slice(pub_seed_slice);
    let mut input = [0u8; 2 * SPX_N];
    input.copy_from_slice(input_slice);
    let mut addr_words = [0u32; SPX_ADDR_WORDS];
    addr_words.copy_from_slice(addr_slice);

    let prepared = prepare_sha2_thash_192s_inblocks2(&pub_seed, &addr_words, &input);
    let skeleton = build_sha2_trace_skeleton_192s_inblocks2(&pub_seed, &addr_words, &input);
    let model_output = sha2_digest_prefix_192s(&skeleton.digest_state);
    if model_output != expected_output {
        eprintln!(
            "[sha2_exact] skeleton/output mismatch: model={:02x?} expected={:02x?}",
            model_output, expected_output
        );
        return SPX_P2_RUST_ERR_INPUT;
    }
    let trace = build_sha2_exact_trace_v2(&skeleton);
    if let Some((row, col, want, got)) = debug_validate_sha2_exact_trace_v2(&trace, &skeleton) {
        eprintln!(
            "[sha2_exact] V2 trace self-check failed: row={} col={} want={:?} got={:?}",
            row, col, want, got
        );
        return SPX_P2_RUST_ERR_PROVE;
    }
    let pub_inputs = build_sha2_exact_public_inputs_v2(&skeleton);
    if let Some((row, constraint, value)) = debug_validate_sha2_exact_air_v2(&trace, &pub_inputs) {
        eprintln!(
            "[sha2_exact] V2 AIR self-check failed: row={} constraint={} value={:?}",
            row, constraint, value
        );
        return SPX_P2_RUST_ERR_PROVE;
    }
    let options = sha2_exact_proof_options();
    let prover = Sha2ExactProverV2::new(options.clone(), pub_inputs.clone());
    let prove_start = Instant::now();
    let proof = match prover.prove(trace) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("[sha2_exact] V2 prove failed: {:?}", err);
            return SPX_P2_RUST_ERR_PROVE;
        }
    };
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = proof.to_bytes();
    let verify_start = Instant::now();
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
    if let Err(err) = winterfell::verify::<
        Sha2ExactAirV2,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    {
        eprintln!("[sha2_exact] V2 verify failed: {:?}", err);
        return SPX_P2_RUST_ERR_PROVE;
    }
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let stats = &mut *out_stats;
    *stats = SpxThashBenchStatsV1 {
        backend_id: inst_ref.backend_id,
        mode: inst_ref.mode,
        inblocks: inst_ref.inblocks,
        rounds: SHA512_ROUNDS as u32,
        trace_width: SHA2_EXACT_V2_TRACE_WIDTH as u32,
        trace_length: SHA2_EXACT_V2_TRACE_LENGTH as u32,
        transition_constraints: SHA2_EXACT_V2_TRANSITION_CONSTRAINTS as u32,
        boundary_assertions: SHA2_EXACT_V2_BOUNDARY_ASSERTIONS as u32,
        constraint_eval_total: (SHA2_EXACT_V2_TRACE_LENGTH as u64)
            * (SHA2_EXACT_V2_TRANSITION_CONSTRAINTS as u64),
        proof_bytes: proof_bytes.len() as u64,
        prove_ms,
        verify_ms,
        exact_primitive_calls: 1,
        exact_round_rows: (SHA512_ROUNDS * SHA2_EXACT_V2_MICRO_STEPS) as u32,
        input_mix: sha2_mix_bytes(&[prepared.msg_bytes.as_slice(), &pub_seed]) as u64,
        output_mix: sha2_mix_bytes(&[&model_output]) as u64,
        result_tag: skeleton.digest_state[0],
    };
    SPX_P2_RUST_OK
}

pub(crate) fn sha512_round_step(
    state: [u64; 8],
    w: u64,
    k: u64,
) -> [u64; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    let t1 = h
        .wrapping_add(big_sigma1(e))
        .wrapping_add(sha512_ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = big_sigma0(a).wrapping_add(sha512_maj(a, b, c));
    [
        t1.wrapping_add(t2),
        a,
        b,
        c,
        d.wrapping_add(t1),
        e,
        f,
        g,
    ]
}
