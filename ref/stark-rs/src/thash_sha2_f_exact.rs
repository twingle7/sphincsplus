use std::time::Instant;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::{
    thash_sha2_exact::{SpxThashBenchInstanceRawV1, SpxThashBenchStatsV1},
    SPX_P2_RUST_ERR_INPUT, SPX_P2_RUST_ERR_NULL, SPX_P2_RUST_ERR_PROVE, SPX_P2_RUST_OK,
};

const SPX_THASH_BENCH_BACKEND_SHA2_V1: u32 = 1;
const SPX_THASH_BENCH_MODE_SHA2_EXACT_V1: u32 = 2;
const SPX_N: usize = 24;
const SPX_ADDR_WORDS: usize = 8;
const SPX_SHA256_ADDR_BYTES: usize = 22;
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_WORDS: usize = 16;
const SHA256_ROUNDS: usize = 64;

const SHA256_F_EXACT_MICRO_STEPS: usize = 4;
const SHA256_F_EXACT_BITS_PER_ROW: usize = 8;
const SHA256_F_EXACT_ACTIVE_ROWS: usize = SHA256_ROUNDS * SHA256_F_EXACT_MICRO_STEPS;
const SHA256_F_EXACT_TRACE_LENGTH: usize = 512;
const SHA256_F_EXACT_TRACE_WIDTH: usize = 65;
const SHA256_F_EXACT_PERIOD: usize = 4;
const SHA256_F_EXACT_ROUND_AUX_WORDS: usize = 11;
const SHA256_F_EXACT_SLICE_COLUMNS: usize = 8;
const SHA256_F_EXACT_TRANSITION_CONSTRAINTS: usize = 112;
const SHA256_F_EXACT_BOUNDARY_ASSERTIONS: usize = 3998;

const COL_ROUND: usize = 0;
const COL_MICRO: usize = 1;
const COL_ACTIVE: usize = 2;
const COL_STATE_START: usize = 3;
const COL_WINDOW_START: usize = 11;
const COL_K: usize = 27;
const COL_BIG_SIGMA0: usize = 28;
const COL_BIG_SIGMA1: usize = 29;
const COL_CH: usize = 30;
const COL_MAJ: usize = 31;
const COL_T1: usize = 32;
const COL_T2: usize = 33;
const COL_T1_CARRY: usize = 34;
const COL_T2_CARRY: usize = 35;
const COL_SCHEDULE_CARRY: usize = 36;
const COL_STATE0_CARRY: usize = 37;
const COL_STATE4_CARRY: usize = 38;
const COL_DIGEST_START: usize = 39;
const COL_DIGEST_CARRY_START: usize = 47;
const COL_LAST_ROUND: usize = 55;
const COL_SCHEDULE_ACTIVE: usize = 56;
const COL_A_SLICE: usize = 57;
const COL_B_SLICE: usize = 58;
const COL_C_SLICE: usize = 59;
const COL_E_SLICE: usize = 60;
const COL_F_SLICE: usize = 61;
const COL_G_SLICE: usize = 62;
const COL_W1_SLICE: usize = 63;
const COL_W14_SLICE: usize = 64;

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; SHA256_ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

#[derive(Clone)]
struct Sha256FExactPreparedV1 {
    msg_bytes: [u8; SPX_SHA256_ADDR_BYTES + SPX_N],
    schedule_words: [u32; SHA256_ROUNDS],
    initial_state: [u32; 8],
}

#[derive(Clone, Copy, Default)]
struct Sha256FExactRoundRowV1 {
    state_in: [u32; 8],
    w: u32,
    k: u32,
    t1: u32,
    t2: u32,
    state_out: [u32; 8],
}

#[derive(Clone)]
struct Sha256FExactTraceSkeletonV1 {
    initial_state: [u32; 8],
    schedule_words: [u32; SHA256_ROUNDS],
    round_rows: [Sha256FExactRoundRowV1; SHA256_ROUNDS],
    round_states: [[u32; 8]; SHA256_ROUNDS + 1],
    final_state: [u32; 8],
    digest_state: [u32; 8],
}

#[derive(Clone)]
struct Sha256FExactPublicInputs {
    initial_state: [BaseElement; 8],
    digest_state: [BaseElement; 8],
    schedule_words: [BaseElement; SHA256_ROUNDS],
    round_aux: [[BaseElement; SHA256_F_EXACT_ROUND_AUX_WORDS]; SHA256_ROUNDS],
    slice_rows: [[BaseElement; SHA256_F_EXACT_SLICE_COLUMNS]; SHA256_F_EXACT_ACTIVE_ROWS],
}

impl ToElements<BaseElement> for Sha256FExactPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = Vec::with_capacity(
            16
                + SHA256_ROUNDS
                + SHA256_ROUNDS * SHA256_F_EXACT_ROUND_AUX_WORDS
                + SHA256_F_EXACT_ACTIVE_ROWS * SHA256_F_EXACT_SLICE_COLUMNS,
        );
        out.extend_from_slice(&self.initial_state);
        out.extend_from_slice(&self.digest_state);
        out.extend_from_slice(&self.schedule_words);
        for row in &self.round_aux {
            out.extend_from_slice(row);
        }
        for row in &self.slice_rows {
            out.extend_from_slice(row);
        }
        out
    }
}

struct Sha256FExactAir {
    context: AirContext<BaseElement>,
    initial_state: [BaseElement; 8],
    digest_state: [BaseElement; 8],
    schedule_words: [BaseElement; SHA256_ROUNDS],
    round_aux: [[BaseElement; SHA256_F_EXACT_ROUND_AUX_WORDS]; SHA256_ROUNDS],
    slice_rows: [[BaseElement; SHA256_F_EXACT_SLICE_COLUMNS]; SHA256_F_EXACT_ACTIVE_ROWS],
}

struct Sha256FExactProver {
    options: winterfell::ProofOptions,
    pub_inputs: Sha256FExactPublicInputs,
}

#[derive(Clone, Copy, Debug, Default)]
struct Sha256FBitSliceWitnessV1 {
    a: u8,
    b: u8,
    c: u8,
    e: u8,
    f: u8,
    g: u8,
    w1: u8,
    w14: u8,
}

fn proof_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
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

fn fe(value: u32) -> BaseElement {
    BaseElement::new(value as u128)
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

fn load_be_u32(bytes: &[u8]) -> u32 {
    let mut acc = 0u32;
    for &byte in bytes {
        acc = (acc << 8) | byte as u32;
    }
    acc
}

fn store_be_u32(dst: &mut [u8], value: u32) {
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
fn rotr32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

#[inline(always)]
fn sha256_big_sigma0(x: u32) -> u32 {
    rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)
}

#[inline(always)]
fn sha256_big_sigma1(x: u32) -> u32 {
    rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)
}

#[inline(always)]
fn sha256_small_sigma0(x: u32) -> u32 {
    rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
}

#[inline(always)]
fn sha256_small_sigma1(x: u32) -> u32 {
    rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)
}

#[inline(always)]
fn sha256_ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

#[inline(always)]
fn sha256_maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sha256_round_step(state: [u32; 8], w: u32, k: u32) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h] = state;
    let t1 = h
        .wrapping_add(sha256_big_sigma1(e))
        .wrapping_add(sha256_ch(e, f, g))
        .wrapping_add(k)
        .wrapping_add(w);
    let t2 = sha256_big_sigma0(a).wrapping_add(sha256_maj(a, b, c));
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

fn sha256_compress_block(initial_state: [u32; 8], block: &[u8; SHA256_BLOCK_BYTES]) -> [u32; 8] {
    let mut schedule_words = [0u32; SHA256_ROUNDS];
    let mut round_state = initial_state;
    for i in 0..SHA256_WORDS {
        let start = i * 4;
        schedule_words[i] = load_be_u32(&block[start..start + 4]);
    }
    for i in SHA256_WORDS..SHA256_ROUNDS {
        schedule_words[i] = sha256_small_sigma1(schedule_words[i - 2])
            .wrapping_add(schedule_words[i - 7])
            .wrapping_add(sha256_small_sigma0(schedule_words[i - 15]))
            .wrapping_add(schedule_words[i - 16]);
    }
    for round in 0..SHA256_ROUNDS {
        round_state = sha256_round_step(round_state, schedule_words[round], SHA256_K[round]);
    }
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = round_state[i].wrapping_add(initial_state[i]);
    }
    out
}

fn build_seeded_sha256_initial_state(pub_seed: &[u8; SPX_N]) -> [u32; 8] {
    let mut block = [0u8; SHA256_BLOCK_BYTES];
    block[..SPX_N].copy_from_slice(pub_seed);
    sha256_compress_block(SHA256_IV, &block)
}

fn prepare_sha256_f_thash_192s_inblocks1(
    pub_seed: &[u8; SPX_N],
    addr_words: &[u32; SPX_ADDR_WORDS],
    input: &[u8; SPX_N],
) -> Sha256FExactPreparedV1 {
    let addr_bytes = u32_words_as_le_bytes(addr_words);
    let mut msg_bytes = [0u8; SPX_SHA256_ADDR_BYTES + SPX_N];
    let mut padded_block = [0u8; SHA256_BLOCK_BYTES];
    let mut schedule_words = [0u32; SHA256_ROUNDS];
    let bit_len = ((SHA256_BLOCK_BYTES + msg_bytes.len()) as u64) * 8;

    msg_bytes[..SPX_SHA256_ADDR_BYTES].copy_from_slice(&addr_bytes[..SPX_SHA256_ADDR_BYTES]);
    msg_bytes[SPX_SHA256_ADDR_BYTES..].copy_from_slice(input);

    padded_block[..msg_bytes.len()].copy_from_slice(&msg_bytes);
    padded_block[msg_bytes.len()] = 0x80;
    padded_block[SHA256_BLOCK_BYTES - 8..].copy_from_slice(&bit_len.to_be_bytes());

    for i in 0..SHA256_WORDS {
        let start = i * 4;
        schedule_words[i] = load_be_u32(&padded_block[start..start + 4]);
    }
    for i in SHA256_WORDS..SHA256_ROUNDS {
        schedule_words[i] = sha256_small_sigma1(schedule_words[i - 2])
            .wrapping_add(schedule_words[i - 7])
            .wrapping_add(sha256_small_sigma0(schedule_words[i - 15]))
            .wrapping_add(schedule_words[i - 16]);
    }

    Sha256FExactPreparedV1 {
        msg_bytes,
        schedule_words,
        initial_state: build_seeded_sha256_initial_state(pub_seed),
    }
}

fn build_sha256_f_trace_skeleton_192s_inblocks1(
    pub_seed: &[u8; SPX_N],
    addr_words: &[u32; SPX_ADDR_WORDS],
    input: &[u8; SPX_N],
) -> Sha256FExactTraceSkeletonV1 {
    let prepared = prepare_sha256_f_thash_192s_inblocks1(pub_seed, addr_words, input);
    let mut round_rows = [Sha256FExactRoundRowV1::default(); SHA256_ROUNDS];
    let mut round_states = [[0u32; 8]; SHA256_ROUNDS + 1];
    round_states[0] = prepared.initial_state;
    for round in 0..SHA256_ROUNDS {
        let state_in = round_states[round];
        let [a, b, c, _d, e, f, g, h] = state_in;
        let w = prepared.schedule_words[round];
        let k = SHA256_K[round];
        let t1 = h
            .wrapping_add(sha256_big_sigma1(e))
            .wrapping_add(sha256_ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let t2 = sha256_big_sigma0(a).wrapping_add(sha256_maj(a, b, c));
        let state_out = sha256_round_step(state_in, w, k);
        round_rows[round] = Sha256FExactRoundRowV1 {
            state_in,
            w,
            k,
            t1,
            t2,
            state_out,
        };
        round_states[round + 1] = state_out;
    }
    let final_state = round_states[SHA256_ROUNDS];
    let mut digest_state = [0u32; 8];
    for i in 0..8 {
        digest_state[i] = final_state[i].wrapping_add(prepared.initial_state[i]);
    }
    Sha256FExactTraceSkeletonV1 {
        initial_state: prepared.initial_state,
        schedule_words: prepared.schedule_words,
        round_rows,
        round_states,
        final_state,
        digest_state,
    }
}

fn sha256_digest_prefix_192s(digest_state: &[u32; 8]) -> [u8; SPX_N] {
    let mut out = [0u8; SPX_N];
    for i in 0..6 {
        store_be_u32(&mut out[i * 4..(i + 1) * 4], digest_state[i]);
    }
    out
}

#[inline(always)]
fn round_of_row(row: usize) -> usize {
    row / SHA256_F_EXACT_MICRO_STEPS
}

#[inline(always)]
fn micro_of_row(row: usize) -> usize {
    row % SHA256_F_EXACT_MICRO_STEPS
}

#[inline(always)]
fn bit_base(micro: usize) -> usize {
    micro * SHA256_F_EXACT_BITS_PER_ROW
}

#[inline(always)]
fn slice_u8(value: u32, bit_base: usize) -> u8 {
    ((value >> bit_base) & 0xff) as u8
}

fn bit_slice_witness(
    row: &Sha256FExactRoundRowV1,
    w1: u32,
    w14: u32,
    micro: usize,
) -> Sha256FBitSliceWitnessV1 {
    let bit_base = bit_base(micro);
    Sha256FBitSliceWitnessV1 {
        a: slice_u8(row.state_in[0], bit_base),
        b: slice_u8(row.state_in[1], bit_base),
        c: slice_u8(row.state_in[2], bit_base),
        e: slice_u8(row.state_in[4], bit_base),
        f: slice_u8(row.state_in[5], bit_base),
        g: slice_u8(row.state_in[6], bit_base),
        w1: slice_u8(w1, bit_base),
        w14: slice_u8(w14, bit_base),
    }
}

fn fill_row(state: &mut [BaseElement], skeleton: &Sha256FExactTraceSkeletonV1, row_idx: usize) {
    let active = row_idx < SHA256_F_EXACT_ACTIVE_ROWS;
    let round = if active { round_of_row(row_idx) } else { SHA256_ROUNDS };
    let micro = if active { micro_of_row(row_idx) } else { 0 };
    let state_words = if round < SHA256_ROUNDS {
        skeleton.round_states[round]
    } else {
        skeleton.final_state
    };

    state[COL_ROUND] = fe(round as u32);
    state[COL_MICRO] = fe(micro as u32);
    state[COL_ACTIVE] = fe(active as u32);

    for i in 0..8 {
        state[COL_STATE_START + i] = fe(state_words[i]);
        state[COL_DIGEST_START + i] = fe(skeleton.digest_state[i]);
        state[COL_DIGEST_CARRY_START + i] =
            fe(((skeleton.final_state[i] as u64 + skeleton.initial_state[i] as u64) >> 32) as u32);
    }

    if !active {
        for i in 0..16 {
            state[COL_WINDOW_START + i] = BaseElement::ZERO;
        }
        for col in [
            COL_K, COL_BIG_SIGMA0, COL_BIG_SIGMA1, COL_CH, COL_MAJ, COL_T1, COL_T2,
            COL_T1_CARRY, COL_T2_CARRY, COL_SCHEDULE_CARRY, COL_STATE0_CARRY, COL_STATE4_CARRY,
            COL_LAST_ROUND, COL_SCHEDULE_ACTIVE, COL_A_SLICE, COL_B_SLICE, COL_C_SLICE,
            COL_E_SLICE, COL_F_SLICE, COL_G_SLICE, COL_W1_SLICE, COL_W14_SLICE,
        ] {
            state[col] = BaseElement::ZERO;
        }
        return;
    }

    let row = &skeleton.round_rows[round];
    let (_, t1_carry) = split_u64_mod_2_32(
        (row.state_in[7] as u64)
            + (sha256_big_sigma1(row.state_in[4]) as u64)
            + (sha256_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u64)
            + (row.k as u64)
            + (row.w as u64),
    );
    let (_, t2_carry) = split_u64_mod_2_32(
        (sha256_big_sigma0(row.state_in[0]) as u64)
            + (sha256_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u64),
    );
    let schedule_carry = if round < 48 {
        ((skeleton.schedule_words[round] as u64)
            + (skeleton.schedule_words[round + 9] as u64)
            + (sha256_small_sigma0(skeleton.schedule_words[round + 1]) as u64)
            + (sha256_small_sigma1(skeleton.schedule_words[round + 14]) as u64))
            >> 32
    } else {
        0
    };
    let state0_carry = (((row.t1 as u64) + (row.t2 as u64)) >> 32) as u32;
    let state4_carry = (((row.state_in[3] as u64) + (row.t1 as u64)) >> 32) as u32;

    for i in 0..16 {
        let idx = round + i;
        state[COL_WINDOW_START + i] = if idx < SHA256_ROUNDS {
            fe(skeleton.schedule_words[idx])
        } else {
            BaseElement::ZERO
        };
    }

    let w1 = if round + 1 < SHA256_ROUNDS {
        skeleton.schedule_words[round + 1]
    } else {
        0
    };
    let w14 = if round + 14 < SHA256_ROUNDS {
        skeleton.schedule_words[round + 14]
    } else {
        0
    };
    let slice = bit_slice_witness(row, w1, w14, micro);

    state[COL_K] = fe(row.k);
    state[COL_BIG_SIGMA0] = fe(sha256_big_sigma0(row.state_in[0]));
    state[COL_BIG_SIGMA1] = fe(sha256_big_sigma1(row.state_in[4]));
    state[COL_CH] = fe(sha256_ch(row.state_in[4], row.state_in[5], row.state_in[6]));
    state[COL_MAJ] = fe(sha256_maj(row.state_in[0], row.state_in[1], row.state_in[2]));
    state[COL_T1] = fe(row.t1);
    state[COL_T2] = fe(row.t2);
    state[COL_T1_CARRY] = fe(t1_carry);
    state[COL_T2_CARRY] = fe(t2_carry);
    state[COL_SCHEDULE_CARRY] = fe(schedule_carry as u32);
    state[COL_STATE0_CARRY] = fe(state0_carry);
    state[COL_STATE4_CARRY] = fe(state4_carry);
    state[COL_LAST_ROUND] = fe((round + 1 == SHA256_ROUNDS) as u32);
    state[COL_SCHEDULE_ACTIVE] = fe((round < 48) as u32);
    state[COL_A_SLICE] = fe(slice.a as u32);
    state[COL_B_SLICE] = fe(slice.b as u32);
    state[COL_C_SLICE] = fe(slice.c as u32);
    state[COL_E_SLICE] = fe(slice.e as u32);
    state[COL_F_SLICE] = fe(slice.f as u32);
    state[COL_G_SLICE] = fe(slice.g as u32);
    state[COL_W1_SLICE] = fe(slice.w1 as u32);
    state[COL_W14_SLICE] = fe(slice.w14 as u32);
}

fn build_trace(skeleton: &Sha256FExactTraceSkeletonV1) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(SHA256_F_EXACT_TRACE_WIDTH, SHA256_F_EXACT_TRACE_LENGTH);
    trace.fill(
        |state| fill_row(state, skeleton, 0),
        |step, state| fill_row(state, skeleton, step + 1),
    );
    trace
}

fn build_public_inputs(skeleton: &Sha256FExactTraceSkeletonV1) -> Sha256FExactPublicInputs {
    let mut initial_state = [BaseElement::ZERO; 8];
    let mut digest_state = [BaseElement::ZERO; 8];
    let mut schedule_words = [BaseElement::ZERO; SHA256_ROUNDS];
    let mut round_aux = [[BaseElement::ZERO; SHA256_F_EXACT_ROUND_AUX_WORDS]; SHA256_ROUNDS];
    let mut slice_rows = [[BaseElement::ZERO; SHA256_F_EXACT_SLICE_COLUMNS]; SHA256_F_EXACT_ACTIVE_ROWS];

    for i in 0..8 {
        initial_state[i] = fe(skeleton.initial_state[i]);
        digest_state[i] = fe(skeleton.digest_state[i]);
    }
    for i in 0..SHA256_ROUNDS {
        schedule_words[i] = fe(skeleton.schedule_words[i]);
    }
    for round in 0..SHA256_ROUNDS {
        let row = &skeleton.round_rows[round];
        let (_, t1_carry) = split_u64_mod_2_32(
            (row.state_in[7] as u64)
                + (sha256_big_sigma1(row.state_in[4]) as u64)
                + (sha256_ch(row.state_in[4], row.state_in[5], row.state_in[6]) as u64)
                + (row.k as u64)
                + (row.w as u64),
        );
        let (_, t2_carry) = split_u64_mod_2_32(
            (sha256_big_sigma0(row.state_in[0]) as u64)
                + (sha256_maj(row.state_in[0], row.state_in[1], row.state_in[2]) as u64),
        );
        let schedule_carry = if round < 48 {
            ((skeleton.schedule_words[round] as u64)
                + (skeleton.schedule_words[round + 9] as u64)
                + (sha256_small_sigma0(skeleton.schedule_words[round + 1]) as u64)
                + (sha256_small_sigma1(skeleton.schedule_words[round + 14]) as u64))
                >> 32
        } else {
            0
        };
        let state0_carry = (((row.t1 as u64) + (row.t2 as u64)) >> 32) as u32;
        let state4_carry = (((row.state_in[3] as u64) + (row.t1 as u64)) >> 32) as u32;
        round_aux[round] = [
            fe(sha256_big_sigma0(row.state_in[0])),
            fe(sha256_big_sigma1(row.state_in[4])),
            fe(sha256_ch(row.state_in[4], row.state_in[5], row.state_in[6])),
            fe(sha256_maj(row.state_in[0], row.state_in[1], row.state_in[2])),
            fe(row.t1),
            fe(row.t2),
            fe(t1_carry),
            fe(t2_carry),
            fe(schedule_carry as u32),
            fe(state0_carry),
            fe(state4_carry),
        ];

        let w1 = if round + 1 < SHA256_ROUNDS {
            skeleton.schedule_words[round + 1]
        } else {
            0
        };
        let w14 = if round + 14 < SHA256_ROUNDS {
            skeleton.schedule_words[round + 14]
        } else {
            0
        };
        for micro in 0..SHA256_F_EXACT_MICRO_STEPS {
            let row_idx = round * SHA256_F_EXACT_MICRO_STEPS + micro;
            let slice = bit_slice_witness(row, w1, w14, micro);
            slice_rows[row_idx] = [
                fe(slice.a as u32),
                fe(slice.b as u32),
                fe(slice.c as u32),
                fe(slice.e as u32),
                fe(slice.f as u32),
                fe(slice.g as u32),
                fe(slice.w1 as u32),
                fe(slice.w14 as u32),
            ];
        }
    }

    Sha256FExactPublicInputs {
        initial_state,
        digest_state,
        schedule_words,
        round_aux,
        slice_rows,
    }
}

fn split_u64_mod_2_32(sum: u64) -> (u32, u32) {
    ((sum & 0xffff_ffff) as u32, (sum >> 32) as u32)
}

fn trace_row_values(trace: &TraceTable<BaseElement>, row: usize) -> Vec<BaseElement> {
    (0..trace.width()).map(|col| trace.get(col, row)).collect()
}

fn eval_transition<E: FieldElement + From<BaseElement>>(
    current: &[E],
    next: &[E],
    periodic_values: &[E],
    initial_state: &[BaseElement; 8],
    result: &mut [E],
) {
    let one = E::ONE;
    let active = current[COL_ACTIVE];
    let inactive = one - active;
    let last_micro = periodic_values[0];
    let micro_value = periodic_values[1];
    let not_last_micro = one - last_micro;
    let cross_flag = active * last_micro;
    let hold_flag = active * not_last_micro;
    let two32 = E::from(BaseElement::new(1u128 << 32));
    let mut idx = 0usize;

    result[idx] = active * (active - one); idx += 1;
    result[idx] = current[COL_LAST_ROUND] * (current[COL_LAST_ROUND] - one); idx += 1;
    result[idx] = current[COL_SCHEDULE_ACTIVE] * (current[COL_SCHEDULE_ACTIVE] - one); idx += 1;
    result[idx] = active * (current[COL_MICRO] - micro_value); idx += 1;
    result[idx] = hold_flag * (next[COL_ROUND] - current[COL_ROUND]); idx += 1;
    result[idx] = hold_flag * (next[COL_ACTIVE] - current[COL_ACTIVE]); idx += 1;
    result[idx] = hold_flag * (next[COL_MICRO] - (current[COL_MICRO] + one)); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_ROUND] - (current[COL_ROUND] + one)); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * next[COL_MICRO]; idx += 1;
    result[idx] = cross_flag * current[COL_LAST_ROUND] * next[COL_ACTIVE]; idx += 1;
    result[idx] = cross_flag * current[COL_LAST_ROUND] * (next[COL_ROUND] - (current[COL_ROUND] + one)); idx += 1;
    result[idx] = cross_flag * current[COL_LAST_ROUND] * next[COL_MICRO]; idx += 1;
    result[idx] = inactive * (next[COL_ACTIVE] - current[COL_ACTIVE]); idx += 1;
    result[idx] = inactive * (next[COL_ROUND] - current[COL_ROUND]); idx += 1;
    result[idx] = inactive * (next[COL_MICRO] - current[COL_MICRO]); idx += 1;
    result[idx] = active
        * current[COL_T1_CARRY]
        * (current[COL_T1_CARRY] - one)
        * (current[COL_T1_CARRY] - E::from(fe(2)))
        * (current[COL_T1_CARRY] - E::from(fe(3)))
        * (current[COL_T1_CARRY] - E::from(fe(4))); idx += 1;
    result[idx] = active * current[COL_T2_CARRY] * (current[COL_T2_CARRY] - one); idx += 1;
    result[idx] = active
        * current[COL_SCHEDULE_CARRY]
        * (current[COL_SCHEDULE_CARRY] - one)
        * (current[COL_SCHEDULE_CARRY] - E::from(fe(2)))
        * (current[COL_SCHEDULE_CARRY] - E::from(fe(3))); idx += 1;
    result[idx] = active * current[COL_STATE0_CARRY] * (current[COL_STATE0_CARRY] - one); idx += 1;
    result[idx] = active * current[COL_STATE4_CARRY] * (current[COL_STATE4_CARRY] - one); idx += 1;
    result[idx] = active * (
        current[COL_T1]
            + current[COL_T1_CARRY] * two32
            - current[COL_STATE_START + 7]
            - current[COL_BIG_SIGMA1]
            - current[COL_CH]
            - current[COL_K]
            - current[COL_WINDOW_START]
    ); idx += 1;
    result[idx] = active * (
        current[COL_T2]
            + current[COL_T2_CARRY] * two32
            - current[COL_BIG_SIGMA0]
            - current[COL_MAJ]
    ); idx += 1;
    result[idx] = hold_flag * (next[COL_LAST_ROUND] - current[COL_LAST_ROUND]); idx += 1;
    result[idx] = hold_flag * (next[COL_SCHEDULE_ACTIVE] - current[COL_SCHEDULE_ACTIVE]); idx += 1;

    for i in 0..8 {
        result[idx] = hold_flag * (next[COL_STATE_START + i] - current[COL_STATE_START + i]);
        idx += 1;
    }
    for i in 0..16 {
        result[idx] = hold_flag * (next[COL_WINDOW_START + i] - current[COL_WINDOW_START + i]);
        idx += 1;
    }
    for col in [
        COL_K, COL_BIG_SIGMA0, COL_BIG_SIGMA1, COL_CH, COL_MAJ, COL_T1, COL_T2, COL_T1_CARRY,
        COL_T2_CARRY, COL_SCHEDULE_CARRY, COL_STATE0_CARRY, COL_STATE4_CARRY,
    ] {
        result[idx] = hold_flag * (next[col] - current[col]);
        idx += 1;
    }

    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (
        next[COL_STATE_START]
            - (current[COL_T1] + current[COL_T2] - current[COL_STATE0_CARRY] * two32)
    ); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 1] - current[COL_STATE_START]); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 2] - current[COL_STATE_START + 1]); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 3] - current[COL_STATE_START + 2]); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (
        next[COL_STATE_START + 4]
            - (current[COL_STATE_START + 3] + current[COL_T1] - current[COL_STATE4_CARRY] * two32)
    ); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 5] - current[COL_STATE_START + 4]); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 6] - current[COL_STATE_START + 5]); idx += 1;
    result[idx] = cross_flag * (one - current[COL_LAST_ROUND]) * (next[COL_STATE_START + 7] - current[COL_STATE_START + 6]); idx += 1;

    result[idx] = cross_flag
        * (one - current[COL_LAST_ROUND])
        * (one - current[COL_SCHEDULE_ACTIVE])
        * next[COL_WINDOW_START + 15];
    idx += 1;
    for i in 0..15 {
        result[idx] = cross_flag * (one - current[COL_LAST_ROUND])
            * (next[COL_WINDOW_START + i] - current[COL_WINDOW_START + i + 1]);
        idx += 1;
    }
    for col in [
        COL_K, COL_BIG_SIGMA0, COL_BIG_SIGMA1, COL_CH, COL_MAJ, COL_T1, COL_T2, COL_T1_CARRY,
        COL_T2_CARRY, COL_SCHEDULE_CARRY, COL_STATE0_CARRY, COL_STATE4_CARRY,
    ] {
        result[idx] = cross_flag * current[COL_LAST_ROUND] * next[col];
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = inactive * (next[COL_STATE_START + i] - current[COL_STATE_START + i]);
        idx += 1;
    }
    for i in 0..8 {
        result[idx] = inactive
            * (
                current[COL_DIGEST_START + i]
                    + current[COL_DIGEST_CARRY_START + i] * two32
                    - current[COL_STATE_START + i]
                    - E::from(initial_state[i])
            );
        idx += 1;
    }
    while idx < SHA256_F_EXACT_TRANSITION_CONSTRAINTS {
        result[idx] = E::ZERO;
        idx += 1;
    }
}

fn debug_validate_trace(
    trace: &TraceTable<BaseElement>,
    skeleton: &Sha256FExactTraceSkeletonV1,
) -> Option<(usize, usize, BaseElement, BaseElement)> {
    for row in 0..trace.length() {
        let mut expected = vec![BaseElement::ZERO; SHA256_F_EXACT_TRACE_WIDTH];
        fill_row(&mut expected, skeleton, row);
        for (col, want) in expected.iter().enumerate() {
            let got = trace.get(col, row);
            if got != *want {
                return Some((row, col, *want, got));
            }
        }
    }
    None
}

fn debug_validate_air(
    trace: &TraceTable<BaseElement>,
    pub_inputs: &Sha256FExactPublicInputs,
) -> Option<(usize, usize, BaseElement)> {
    let mut last_micro = vec![BaseElement::ZERO; SHA256_F_EXACT_PERIOD];
    last_micro[SHA256_F_EXACT_MICRO_STEPS - 1] = BaseElement::ONE;
    let micro_values = (0..SHA256_F_EXACT_PERIOD)
        .map(|i| fe(i as u32))
        .collect::<Vec<_>>();
    for row in 0..(trace.length() - 1) {
        let current = trace_row_values(trace, row);
        let next = trace_row_values(trace, row + 1);
        let periodic = [last_micro[row % SHA256_F_EXACT_PERIOD], micro_values[row % SHA256_F_EXACT_PERIOD]];
        let mut result = vec![BaseElement::ZERO; SHA256_F_EXACT_TRANSITION_CONSTRAINTS];
        eval_transition(&current, &next, &periodic, &pub_inputs.initial_state, &mut result);
        for (constraint, value) in result.into_iter().enumerate() {
            if value != BaseElement::ZERO {
                return Some((row, constraint, value));
            }
        }
    }
    None
}

impl Air for Sha256FExactAir {
    type BaseField = BaseElement;
    type PublicInputs = Sha256FExactPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Sha256FExactPublicInputs, options: winterfell::ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(6, vec![SHA256_F_EXACT_PERIOD, SHA256_F_EXACT_PERIOD]);
            SHA256_F_EXACT_TRANSITION_CONSTRAINTS
        ];
        Self {
            context: AirContext::new(trace_info, degrees, SHA256_F_EXACT_BOUNDARY_ASSERTIONS, options),
            initial_state: pub_inputs.initial_state,
            digest_state: pub_inputs.digest_state,
            schedule_words: pub_inputs.schedule_words,
            round_aux: pub_inputs.round_aux,
            slice_rows: pub_inputs.slice_rows,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        eval_transition(
            frame.current(),
            frame.next(),
            periodic_values,
            &self.initial_state,
            result,
        );
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut last_micro = vec![BaseElement::ZERO; SHA256_F_EXACT_PERIOD];
        last_micro[SHA256_F_EXACT_MICRO_STEPS - 1] = BaseElement::ONE;
        let micro_values = (0..SHA256_F_EXACT_PERIOD).map(|i| fe(i as u32)).collect::<Vec<_>>();
        vec![last_micro, micro_values]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = SHA256_F_EXACT_TRACE_LENGTH - 1;
        let done_row = SHA256_F_EXACT_ACTIVE_ROWS;
        let mut assertions = Vec::with_capacity(SHA256_F_EXACT_BOUNDARY_ASSERTIONS);
        assertions.push(Assertion::single(COL_ROUND, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_MICRO, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_ACTIVE, 0, BaseElement::ONE));
        assertions.push(Assertion::single(COL_ACTIVE, done_row, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_ACTIVE, last_step, BaseElement::ZERO));
        assertions.push(Assertion::single(COL_ROUND, done_row, fe(SHA256_ROUNDS as u32)));
        for i in 0..8 {
            assertions.push(Assertion::single(COL_STATE_START + i, 0, self.initial_state[i]));
            assertions.push(Assertion::single(COL_DIGEST_START + i, 0, self.digest_state[i]));
            assertions.push(Assertion::single(COL_DIGEST_START + i, last_step, self.digest_state[i]));
        }
        for round in 0..SHA256_ROUNDS {
            let row = round * SHA256_F_EXACT_MICRO_STEPS;
            assertions.push(Assertion::single(COL_K, row, fe(SHA256_K[round])));
            for offset in 0..16 {
                let word = if round + offset < SHA256_ROUNDS {
                    self.schedule_words[round + offset]
                } else {
                    BaseElement::ZERO
                };
                assertions.push(Assertion::single(COL_WINDOW_START + offset, row, word));
            }
            assertions.push(Assertion::single(COL_BIG_SIGMA0, row, self.round_aux[round][0]));
            assertions.push(Assertion::single(COL_BIG_SIGMA1, row, self.round_aux[round][1]));
            assertions.push(Assertion::single(COL_CH, row, self.round_aux[round][2]));
            assertions.push(Assertion::single(COL_MAJ, row, self.round_aux[round][3]));
            assertions.push(Assertion::single(COL_T1, row, self.round_aux[round][4]));
            assertions.push(Assertion::single(COL_T2, row, self.round_aux[round][5]));
            assertions.push(Assertion::single(COL_T1_CARRY, row, self.round_aux[round][6]));
            assertions.push(Assertion::single(COL_T2_CARRY, row, self.round_aux[round][7]));
            assertions.push(Assertion::single(COL_SCHEDULE_CARRY, row, self.round_aux[round][8]));
            assertions.push(Assertion::single(COL_STATE0_CARRY, row, self.round_aux[round][9]));
            assertions.push(Assertion::single(COL_STATE4_CARRY, row, self.round_aux[round][10]));
            assertions.push(Assertion::single(COL_LAST_ROUND, row, fe((round + 1 == SHA256_ROUNDS) as u32)));
            assertions.push(Assertion::single(COL_SCHEDULE_ACTIVE, row, fe((round < 48) as u32)));
        }
        for row in 0..SHA256_F_EXACT_ACTIVE_ROWS {
            assertions.push(Assertion::single(COL_A_SLICE, row, self.slice_rows[row][0]));
            assertions.push(Assertion::single(COL_B_SLICE, row, self.slice_rows[row][1]));
            assertions.push(Assertion::single(COL_C_SLICE, row, self.slice_rows[row][2]));
            assertions.push(Assertion::single(COL_E_SLICE, row, self.slice_rows[row][3]));
            assertions.push(Assertion::single(COL_F_SLICE, row, self.slice_rows[row][4]));
            assertions.push(Assertion::single(COL_G_SLICE, row, self.slice_rows[row][5]));
            assertions.push(Assertion::single(COL_W1_SLICE, row, self.slice_rows[row][6]));
            assertions.push(Assertion::single(COL_W14_SLICE, row, self.slice_rows[row][7]));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

impl Sha256FExactProver {
    fn new(options: winterfell::ProofOptions, pub_inputs: Sha256FExactPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for Sha256FExactProver {
    type BaseField = BaseElement;
    type Air = Sha256FExactAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Sha256FExactPublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &winterfell::ProofOptions {
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

pub(crate) unsafe fn run_sha2_f_exact(
    out_stats: *mut SpxThashBenchStatsV1,
    inst: *const SpxThashBenchInstanceRawV1,
) -> i32 {
    if out_stats.is_null() || inst.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }

    let inst_ref = &*inst;
    if inst_ref.backend_id != SPX_THASH_BENCH_BACKEND_SHA2_V1
        || inst_ref.mode != SPX_THASH_BENCH_MODE_SHA2_EXACT_V1
        || inst_ref.inblocks != 1
        || inst_ref.pub_seed.is_null()
        || inst_ref.addr.is_null()
        || inst_ref.input.is_null()
        || inst_ref.expected_output.is_null()
        || inst_ref.input_len != SPX_N
    {
        return SPX_P2_RUST_ERR_INPUT;
    }

    let pub_seed_slice = std::slice::from_raw_parts(inst_ref.pub_seed, SPX_N);
    let input_slice = std::slice::from_raw_parts(inst_ref.input, SPX_N);
    let expected_output = std::slice::from_raw_parts(inst_ref.expected_output, SPX_N);
    let addr_slice = std::slice::from_raw_parts(inst_ref.addr, SPX_ADDR_WORDS);

    let mut pub_seed = [0u8; SPX_N];
    pub_seed.copy_from_slice(pub_seed_slice);
    let mut input = [0u8; SPX_N];
    input.copy_from_slice(input_slice);
    let mut addr_words = [0u32; SPX_ADDR_WORDS];
    addr_words.copy_from_slice(addr_slice);

    let prepared = prepare_sha256_f_thash_192s_inblocks1(&pub_seed, &addr_words, &input);
    let skeleton = build_sha256_f_trace_skeleton_192s_inblocks1(&pub_seed, &addr_words, &input);
    let model_output = sha256_digest_prefix_192s(&skeleton.digest_state);
    if model_output != expected_output {
        eprintln!(
            "[sha2_exact_f] skeleton/output mismatch: model={:02x?} expected={:02x?}",
            model_output, expected_output
        );
        return SPX_P2_RUST_ERR_INPUT;
    }

    let trace = build_trace(&skeleton);
    if let Some((row, col, want, got)) = debug_validate_trace(&trace, &skeleton) {
        eprintln!(
            "[sha2_exact_f] trace self-check failed: row={} col={} want={:?} got={:?}",
            row, col, want, got
        );
        return SPX_P2_RUST_ERR_PROVE;
    }

    let pub_inputs = build_public_inputs(&skeleton);
    if let Some((row, constraint, value)) = debug_validate_air(&trace, &pub_inputs) {
        eprintln!(
            "[sha2_exact_f] AIR self-check failed: row={} constraint={} value={:?}",
            row, constraint, value
        );
        return SPX_P2_RUST_ERR_PROVE;
    }

    let prover = Sha256FExactProver::new(proof_options(), pub_inputs.clone());
    let prove_start = Instant::now();
    let proof = match prover.prove(trace) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("[sha2_exact_f] prove failed: {:?}", err);
            return SPX_P2_RUST_ERR_PROVE;
        }
    };
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = proof.to_bytes();
    let verify_start = Instant::now();
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
    if let Err(err) = winterfell::verify::<
        Sha256FExactAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    {
        eprintln!("[sha2_exact_f] verify failed: {:?}", err);
        return SPX_P2_RUST_ERR_PROVE;
    }
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let stats = &mut *out_stats;
    *stats = SpxThashBenchStatsV1 {
        backend_id: inst_ref.backend_id,
        mode: inst_ref.mode,
        inblocks: inst_ref.inblocks,
        rounds: SHA256_ROUNDS as u32,
        trace_width: SHA256_F_EXACT_TRACE_WIDTH as u32,
        trace_length: SHA256_F_EXACT_TRACE_LENGTH as u32,
        transition_constraints: SHA256_F_EXACT_TRANSITION_CONSTRAINTS as u32,
        boundary_assertions: SHA256_F_EXACT_BOUNDARY_ASSERTIONS as u32,
        constraint_eval_total: (SHA256_F_EXACT_TRACE_LENGTH as u64)
            * (SHA256_F_EXACT_TRANSITION_CONSTRAINTS as u64),
        proof_bytes: proof_bytes.len() as u64,
        prove_ms,
        verify_ms,
        exact_primitive_calls: 1,
        exact_round_rows: SHA256_F_EXACT_ACTIVE_ROWS as u32,
        input_mix: sha2_mix_bytes(&[prepared.msg_bytes.as_slice(), &pub_seed]),
        output_mix: sha2_mix_bytes(&[&model_output]),
        result_tag: skeleton.digest_state[0] as u64,
    };
    SPX_P2_RUST_OK
}
