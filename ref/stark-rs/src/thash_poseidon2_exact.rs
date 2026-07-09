use std::time::Instant;

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
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

const SPX_THASH_BENCH_BACKEND_POSEIDON2_V1: u32 = 2;
const SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1: u32 = 1;

const SPX_N: usize = 24;
const SPX_ADDR_WORDS: usize = 8;
const SPX_ADDR_BYTES: usize = SPX_ADDR_WORDS * 4;
const POSEIDON2_T: usize = 12;
const POSEIDON2_RATE_WORDS: usize = 6;
const POSEIDON2_RATE_BYTES: usize = POSEIDON2_RATE_WORDS * 8;
pub(crate) const POSEIDON2_ROUNDS: usize = 30;
const POSEIDON2_TRACE_WIDTH: usize = 15;
const POSEIDON2_TRANSITION_CONSTRAINTS: usize = 17;
const POSEIDON2_BOUNDARY_ASSERTIONS: usize = 21;
const POSEIDON2_PERIOD: usize = 32;
const GOLDILOCKS_HALF: u64 = 0x7fffffff80000001;
const GOLDILOCKS_P: u64 = 0xffffffff00000001;

// This module expects the C reference in `ref/poseidon2.c` to use exact
// Goldilocks arithmetic modulo p = 2^64 - 2^32 + 1 so that the Rust witness
// model, the C backend, and Winterfell `f64::BaseElement` all share the same
// primitive semantics.

extern "C" {
    #[link_name = "SPX_poseidon2_permute"]
    fn poseidon2_permute_c(state: *mut u64);
}

pub(crate) const P2_INTERNAL_DIAG_12: [u64; POSEIDON2_T] = [
    0xc3b6c08e23ba9300, 0xd84b5de94a324fb6, 0x0d0c371c5b35b84f, 0x7964f570e7188037,
    0x5daf18bbd996604b, 0x6743bc47b9595257, 0x5528b9362c59bb70, 0xac45e25b7127b68b,
    0xa2077d7dfbb606b5, 0xf3faac6faee378ae, 0x0c6388b51545e883, 0xd27dbb6944917b60,
];

pub(crate) const P2_ROUND_CONSTANTS: [[u64; POSEIDON2_T]; POSEIDON2_ROUNDS] = [
    [0x615dc2abaa0ab5d7, 0x45d05516c0b791b5, 0x77fea9cf2cd85ef8, 0xb2cabe81e93d91bf, 0x5fd23bdc8e61f633, 0xe7e4af990295310e, 0x69617bad4a6647ed, 0xaaa9696e40634855, 0x6b97fab65990bc8c, 0x44cb13e2a9d2ada6, 0x02a914451e61e9a9, 0xad5ef3321ec74ce5],
    [0x5e42e6d638b4eece, 0xf0dec325577f2984, 0x84c49196cbc7197b, 0xc759b66ba945a5b8, 0x41e50b3f48d9f039, 0x7ac3567502cbdecd, 0x0cd4768f705c003b, 0xd7d5d675c5945a03, 0x13c8002c09a1579d, 0x98e077b78ce5091d, 0xe27eb84f637ee44b, 0xf39a0b6dbd5c1d82],
    [0x09e72ca7823c236a, 0xb9adf0b67ddb9496, 0xec8af086f99a60aa, 0x175e0f05a7bbd90e, 0xfe0478c66357fee6, 0x9d9e39624ee357ca, 0xe4b3e1e52281bdb6, 0xce5ef98210c415fc, 0x90d9d332495673a4, 0x4c294905450d8a75, 0x0c1205c382657deb, 0xd51adf0c55d0d057],
    [0xb120673d1b739d97, 0x0590c505c71518f1, 0xc70d8b6174f5dc65, 0x6ddef79be2529700, 0x20a50c001c7984ed, 0xffedcb01a2484c68, 0x4d6f9f3ca97c5dd8, 0xed5857eb0900fbe1, 0x65421d9cb53b96da, 0x4b54929c63cefcc9, 0xb3defe060e5058ab, 0x989914d47532804b],
    [0xb9675df0e7517f34, 0x35f704c31f10b8d6, 0xb0d7829d7a2a1e95, 0x5e551127fd4dd497, 0xb8d458a2d27940db, 0x7b578ca295a17560, 0xb7df3ba47cf84687, 0xcd476710739ac498, 0x300bc21969c8e1a8, 0x92bf573ce07627d9, 0xe6735bf0d996306b, 0xb23d84089cf859b9],
    [0x35f67913afbb54fe, 0x52c356a71159aff4, 0xafc01ac52b804e62, 0xd6b9ba69f91152ab, 0x395e1e7cb9f77a2d, 0x4e063888353d91bf, 0x7d82f3160b8a2633, 0x3aceae1ddddb1d12, 0xdfe54e09a720adfd, 0x0e2ebc3264b1871b, 0x9a375b4a8840c5e5, 0x4e24c0eb5ff10c78],
    [0xd9549158066276c3, 0x3e88dd41a9e6cb86, 0xc458e083ca1ec9cb, 0xec6235483fa9ffbe, 0x46f33d3b970cb5b9, 0xa28b19d7bae196b8, 0xdcf84e68e0fefb49, 0xd4267a5874a314c8, 0xc045fa784373ca94, 0xca21fdd23a191ffc, 0x18b8808f41af4a08, 0x3cb4cf9130f1d2dd],
    [0xae0b30903d6a52c2, 0xa4befd848d483032, 0x8ce72df6511f23b7, 0xd65646bbe36f72e9, 0x7c6cebf727065953, 0xcfe2e4d4e181e1eb, 0xf687f41d549c4901, 0x3e7d4ec68a9c0812, 0x160b1df18a6f672b, 0x938d7e3f91362813, 0x537591db90a60c95, 0x1350d0633ccfe047],
    [0xe1253f9bceb06903, 0xa5ae0b43995b82cb, 0x8c46241038b6734e, 0x92449f16ccce83a1, 0x1df2784b7d7264d1, 0x6aebd071217618b9, 0x782268d7f4ff66b5, 0xcd58b0abb76088b1, 0xfe12fe6c3980a00b, 0x4ed91304f25f5b04, 0xebb27dd3ee03d8f5, 0x4901a2ff7f42894e],
    [0x4cd92ae5edb29841, 0x534e4d874ff1d093, 0x0df403f78b72da93, 0x62438405d8afe09f, 0xdb79a695282da812, 0x638b8f698b343521, 0xc895986820cf7b39, 0xf73d8f6c6d4a7a94, 0x2f55992a06319942, 0x591265dd575ba305, 0xafb044a7299107e3, 0x0aa2b81dab72ea93],
    [0x5aad504b1bf6924b, 0x861e528ec4cc5977, 0xaca158b06900c9eb, 0x538bf3cf7c715fae, 0xa73e256e99eea0cd, 0x3d56c06b73e28fc2, 0xb8910c75d4e9bdb2, 0x614250426015b85d, 0x7637030dbfbc2b33, 0xe5f5cab65ec9f387, 0x7d4c7a282fc762d7, 0xe4dc1fcd81875502],
    [0x3135cf7416c99fa2, 0x7b896285efbf87f5, 0xae9501395cd793c2, 0x35f8e63199f5b84c, 0xbd4d5c6d95f6fc0a, 0xfa88dd6cb66f22b1, 0x91d97e17791bd3b1, 0xdd5dd6c01dbea4e3, 0xd570a4f89741031b, 0x5c7958d275b6deb7, 0x284ee1070e17ba8f, 0xc5d53916ad289569],
    [0x88f453232bf3da67, 0xfa8d3a87c683757e, 0x0c33438c8a186776, 0x93b24e95eb0194e7, 0xf932e418270833c1, 0xfef89a5b44c8eca6, 0x8e6cd9358dd881e8, 0xd599b8e2a231c156, 0xf1abc078c91a2f12, 0x0a153d618658d402, 0x363b8a44b515cfc6, 0x4af5591a6c8bd490],
    [0xee75a3030f2686e8, 0x5e40ef41c8bb75b3, 0xf90e18d3f831ddf9, 0xf6030495a240f06b, 0xe1647ff8c9b03a67, 0x007952185a18ea01, 0x2c4597f6e9d10ddc, 0x592524fc4a7db73c, 0x7ea2954ebe348e7e, 0xd6ff7b83111021e1, 0xed28494a3f7d39eb, 0xdb2d883f16656fdc],
    [0xb54866154482d5d9, 0x60c56c4457b8882e, 0xd48a1abbaa395332, 0xb7a26820aae09c3c, 0x67eedae7bb5b1c93, 0x47ea024889ed42c7, 0xfd1264a5149aa46d, 0xfdd606e967a5557d, 0x5428c52b33df6d52, 0x6865dba0d89151cb, 0xa3d972318a4a226c, 0xf27c2bf676c6c356],
    [0x32e0a7d0a326bf48, 0x8ac83d6233b5995a, 0xe67e05dbcb85b9b8, 0x4bdce4a16ac2ce0c, 0x7179444d541b3b42, 0xf073493526d5f89a, 0x4759e45799779989, 0xcf3a6c63830be7f7, 0x74bf6e15e3f3d96e, 0x7fc2d375bc59d1c7, 0xf75744475ae42f5e, 0x3c08249928b4d106],
    [0xd478f5fc2d6c4630, 0x459cc93ed0373e04, 0xf70792295c853c2a, 0x6bedbd34b3d45deb, 0xb5cbb0cd22d25cb6, 0x0ddc12df2e1eb05f, 0x9a8cec3b377f7d31, 0x229268802065f582, 0xea789cbe6cf514c8, 0xcfbd28a53602b9b3, 0x5878b1936a66f8e5, 0x4c962b0dbfe0a612],
    [0x67ad8190120f6361, 0x5dce1524107e7add, 0x6a0463f6c8d3ca73, 0x17d8d313e5800283, 0x6e501e8fb7db8ab5, 0x95905e2db5be288a, 0x9baade450c75e6eb, 0x976792873e3b2784, 0xb95af4b8194834f2, 0x202d42fc06f09b4d, 0x8eeceb3b043fc34a, 0x7c0e6e67eefd9f87],
    [0x6d17545d51b984a4, 0xd5ac43f2ceed975e, 0x8c94442896e24aae, 0x9f48b78a26a0d753, 0x95a542585160666f, 0x2f2a7ae47fe5183b, 0xef7485274bbeee38, 0x75d23590909cedbe, 0x354dd6d365f17a73, 0x14bad66c2df59bee, 0x9127a724d290a108, 0xe7186f8c80b107b9],
    [0xf414508490821f10, 0xa6e24f7ac3a2f53d, 0xc3fd9aba0508f05b, 0x66ecaa13623944ed, 0xc866e032ccee66d8, 0x8072925e4eec155b, 0x4732ccef042e8691, 0xa50233cf9b57b49f, 0xe994707611908f1f, 0x1a98a4d84921dcbe, 0xbc7bccf86ac5668b, 0x2a45d5fb6e6eed07],
    [0x4ec75f2afd0583b1, 0x67e8e4ac9ba5f7ae, 0xd02fdc09caf5d408, 0xcea4953482f5028f, 0xb6ab10d4d1d070a8, 0x8ed8f592f9f17101, 0xd0407325bd561888, 0x988b1b96e819b207, 0xd001a380f714922a, 0x2ab09b5c76c02dfc, 0x2cc21ca3847f8406, 0x7cae14dee0de722b],
    [0x368fda7791c75da2, 0x9e025c5863347d81, 0xa53e15a8b15febdc, 0x33423c467a8e47f0, 0x1cd857ee2e998789, 0xb770371e6385f876, 0xefc05de50e99c294, 0xcef3b545c8894f7d, 0x1b212f168beadd7c, 0x3c294af9ffc1a82d, 0x4d562c758e6a84eb, 0x5dafdec2ffbd9f52],
    [0xa1cef48ab74c5558, 0x2e26fa73db1c7863, 0xc0ba6441ea876185, 0xb69985c66954851c, 0x5fc5f07bb8cb4278, 0x6b86b4da0dc285d3, 0x9290fbe110ec0540, 0xf3a71f576e8b874b, 0x201aac9efb37fd7e, 0xc981bae4857ea69d, 0x6508c4c259766d75, 0x49fe93ae5d873e67],
    [0x60ac1e9fbd113ad3, 0xb008a1642211e7ac, 0x68bab9db5992d787, 0x08d79982d57729c8, 0x63ec6fabfee2153b, 0x9ffaa4ffd0acede0, 0x55ed74205d7328dd, 0xdd27e05c719a8baa, 0x5c4e9a9b4ea06fe2, 0x1c83f60ab4ca43c5, 0x9c8b2e4110f37d0f, 0xa7e797aa354f36b1],
    [0xeca179bb4ad7a873, 0x8d98457e2008f924, 0xe93177d3eceab6f2, 0x15bc8b272f02cccb, 0x4b176dd68166a72b, 0x900e9e2bba5bf172, 0xdba2ff24066ed4d5, 0x13664509798ef3b8, 0x949a319c6a09b425, 0xaad6f14eb6709d69, 0x3fdc834e7889e591, 0xf3e677894e4b6df8],
    [0x76f35eb327d50d75, 0x0ba6584dd2128264, 0xa727f0af606432bd, 0x5c5ebb1c033478ed, 0xb3df78499e05fc9d, 0x5416f30335dfe9ac, 0x448e4f2c04e2cf39, 0x6b916df85796b1c3, 0x4c4665834b86d9bd, 0xbd21500fcdb5b0af, 0x7d338fab9b0d74d1, 0xed52e4e2fa56e827],
    [0xbefa698c0e7e198b, 0xf2bcde6dec51f416, 0xb3d75514a20b7fed, 0x3aabedf5a7b98c80, 0x4ad4f39fef2be7ad, 0x583277553bc4f041, 0x9d2d8e23cb2d093e, 0x51296016a86c653d, 0xbd10421045a8cd73, 0x1819fc2151a0a62f, 0x5e23d5a4a34c77db, 0x99c04d2432370e8d],
    [0xac22893f98c8c631, 0x9262c0472c57921c, 0x3d9ec14eb35c11c6, 0x5188f59edb76d269, 0xe752de5697233186, 0x2ae76af0d9d481cc, 0xada4c123a36ee308, 0x54ec8e5cd06e0e62, 0x7748103b19307e9e, 0x4a2380e7b141cf90, 0xa8d87f1970f57a6a, 0x56867b0caf4a0ccf],
    [0x73991b725be81991, 0x9f3fa4e3a8e1ab84, 0xe0fe270710c52fd4, 0x869dcec8905b8355, 0xc1933693086966c5, 0x55feac758a9cd0cd, 0x0c3c8f85e5bb5d4d, 0x0b16be550ed9ccc8, 0x314a59d5e9865c0e, 0x7a8a21d59b290464, 0xa9e910ac1b626d16, 0x5ae384e9364a37f6],
    [0xb344380c7235f775, 0xc722cc91c135dd0e, 0x39f13da79952f6b2, 0xfc051f4dc14bcbba, 0x665c81d0e418b811, 0xe698a606d80bbf66, 0xf910fdb37a6d81e3, 0xc89e3a28cf2303d0, 0xc89f0fb58dbaa990, 0x238f93ee41e17c24, 0xf095a19b3a0ad02a, 0x81c2f9d58e28cdc9],
];

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

#[derive(Clone)]
struct Poseidon2ExactPublicInputs {
    input_mix: BaseElement,
    output_mix: BaseElement,
    output_row: BaseElement,
    final_perm_idx: BaseElement,
    initial_state: [BaseElement; POSEIDON2_T],
    block2: [BaseElement; POSEIDON2_RATE_WORDS],
    block3: [BaseElement; POSEIDON2_RATE_WORDS],
    output_lanes: [BaseElement; 3],
}

impl ToElements<BaseElement> for Poseidon2ExactPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![self.input_mix, self.output_mix, self.output_row, self.final_perm_idx];
        out.extend_from_slice(&self.initial_state);
        out.extend_from_slice(&self.block2);
        out.extend_from_slice(&self.block3);
        out.extend_from_slice(&self.output_lanes);
        out
    }
}

struct Poseidon2ExactAir {
    context: AirContext<BaseElement>,
    output_row: usize,
    final_perm_idx: BaseElement,
    initial_state: [BaseElement; POSEIDON2_T],
    block2: [BaseElement; POSEIDON2_RATE_WORDS],
    block3: [BaseElement; POSEIDON2_RATE_WORDS],
    output_lanes: [BaseElement; 3],
}

struct Poseidon2ExactProver {
    options: ProofOptions,
    pub_inputs: Poseidon2ExactPublicInputs,
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(32, 32, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}

fn mix_bytes(parts: &[&[u8]]) -> BaseElement {
    let mut acc = 0xcbf29ce484222325u64;
    for part in parts {
        for &b in *part {
            acc ^= b as u64;
            acc = acc.rotate_left(7).wrapping_mul(0x100000001b3);
        }
    }
    BaseElement::new(acc)
}

fn u32_words_as_bytes(addr: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addr.len() * 4);
    for word in addr {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn load_lane(bytes: &[u8]) -> BaseElement {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (8 * i);
    }
    BaseElement::new(value)
}

pub(crate) fn round_kind(round: usize) -> (bool, bool) {
    if round < 4 || round >= 26 {
        (true, false)
    } else {
        (false, true)
    }
}

#[inline(always)]
fn pow7_base(x: BaseElement) -> BaseElement {
    x.exp7()
}

#[inline(always)]
fn pow7_ext<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    (x4 * x2) * x
}

pub(crate) fn poseidon2_round(state: &mut [BaseElement; POSEIDON2_T], round: usize) {
    let mut tmp = [BaseElement::ZERO; POSEIDON2_T];
    for i in 0..POSEIDON2_T {
        tmp[i] = state[i] + BaseElement::new(P2_ROUND_CONSTANTS[round][i]);
    }
    let (is_full, _) = round_kind(round);
    if is_full {
        let mut sum = BaseElement::ZERO;
        for i in 0..POSEIDON2_T {
            tmp[i] = pow7_base(tmp[i]);
            sum += tmp[i];
        }
        for i in 0..POSEIDON2_T {
            state[i] = sum + tmp[i];
        }
    } else {
        tmp[0] = pow7_base(tmp[0]);
        let mut sum = BaseElement::ZERO;
        for value in &tmp {
            sum += *value;
        }
        for i in 0..POSEIDON2_T {
            state[i] = sum + BaseElement::new(P2_INTERNAL_DIAG_12[i]) * tmp[i];
        }
    }
}

fn poseidon2_required_rows(final_perm_idx: usize) -> usize {
    32 * (final_perm_idx + 1)
}

fn poseidon2_done_row(final_perm_idx: usize) -> usize {
    poseidon2_required_rows(final_perm_idx) - 1
}

fn poseidon2_output_row(final_perm_idx: usize) -> usize {
    poseidon2_done_row(final_perm_idx)
}

fn poseidon2_exact_work_units(final_perm_idx: usize) -> (u32, u32) {
    let primitive_calls = (final_perm_idx + 1) as u32;
    (primitive_calls, primitive_calls * POSEIDON2_ROUNDS as u32)
}

fn gold_add_u64(a: u64, b: u64) -> u64 {
    let mut sum = a.wrapping_add(b);
    if sum < a || sum >= GOLDILOCKS_P {
        sum = sum.wrapping_sub(GOLDILOCKS_P);
    }
    sum
}

fn gold_mul_u64(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    (prod % (GOLDILOCKS_P as u128)) as u64
}

fn gold_pow7_u64(x: u64) -> u64 {
    let x2 = gold_mul_u64(x, x);
    let x4 = gold_mul_u64(x2, x2);
    gold_mul_u64(gold_mul_u64(x4, x2), x)
}

pub(crate) fn poseidon2_round_u64(state: &mut [u64; POSEIDON2_T], round: usize) {
    let mut tmp = [0u64; POSEIDON2_T];
    for i in 0..POSEIDON2_T {
        tmp[i] = gold_add_u64(state[i], P2_ROUND_CONSTANTS[round][i]);
    }
    let (is_full, _) = round_kind(round);
    if is_full {
        let mut sum = 0u64;
        for i in 0..POSEIDON2_T {
            tmp[i] = gold_pow7_u64(tmp[i]);
            sum = gold_add_u64(sum, tmp[i]);
        }
        for i in 0..POSEIDON2_T {
            state[i] = gold_add_u64(sum, tmp[i]);
        }
    } else {
        tmp[0] = gold_pow7_u64(tmp[0]);
        let mut sum = 0u64;
        for value in &tmp {
            sum = gold_add_u64(sum, *value);
        }
        for i in 0..POSEIDON2_T {
            state[i] = gold_add_u64(sum, gold_mul_u64(P2_INTERNAL_DIAG_12[i], tmp[i]));
        }
    }
}

fn reference_states(pub_inputs: &Poseidon2ExactPublicInputs) -> Vec<[u64; POSEIDON2_T]> {
    let perm_count = pub_inputs.final_perm_idx.as_int() as usize + 1;
    let mut out = vec![[0u64; POSEIDON2_T]; perm_count];
    let mut state = [0u64; POSEIDON2_T];
    for i in 0..POSEIDON2_RATE_WORDS {
        state[i] = pub_inputs.initial_state[i].as_int();
    }
    unsafe {
        poseidon2_permute_c(state.as_mut_ptr());
    }
    out[0] = state;
    if perm_count >= 2 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] = gold_add_u64(state[i], pub_inputs.block2[i].as_int());
        }
        unsafe {
            poseidon2_permute_c(state.as_mut_ptr());
        }
        out[1] = state;
    }
    if perm_count >= 3 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] = gold_add_u64(state[i], pub_inputs.block3[i].as_int());
        }
        unsafe {
            poseidon2_permute_c(state.as_mut_ptr());
        }
        out[2] = state;
    }
    out
}

fn model_states_u64(pub_inputs: &Poseidon2ExactPublicInputs) -> Vec<[u64; POSEIDON2_T]> {
    let perm_count = pub_inputs.final_perm_idx.as_int() as usize + 1;
    let mut out = vec![[0u64; POSEIDON2_T]; perm_count];
    let mut state = [0u64; POSEIDON2_T];
    for i in 0..POSEIDON2_RATE_WORDS {
        state[i] = pub_inputs.initial_state[i].as_int();
    }
    for round in 0..POSEIDON2_ROUNDS {
        poseidon2_round_u64(&mut state, round);
    }
    out[0] = state;
    if perm_count >= 2 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] = gold_add_u64(state[i], pub_inputs.block2[i].as_int());
        }
        for round in 0..POSEIDON2_ROUNDS {
            poseidon2_round_u64(&mut state, round);
        }
        out[1] = state;
    }
    if perm_count >= 3 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] = gold_add_u64(state[i], pub_inputs.block3[i].as_int());
        }
        for round in 0..POSEIDON2_ROUNDS {
            poseidon2_round_u64(&mut state, round);
        }
        out[2] = state;
    }
    out
}

fn model_states_field(pub_inputs: &Poseidon2ExactPublicInputs) -> Vec<[u64; POSEIDON2_T]> {
    let perm_count = pub_inputs.final_perm_idx.as_int() as usize + 1;
    let mut out = vec![[0u64; POSEIDON2_T]; perm_count];
    let mut state = [BaseElement::ZERO; POSEIDON2_T];
    state[..POSEIDON2_RATE_WORDS].copy_from_slice(&pub_inputs.initial_state[..POSEIDON2_RATE_WORDS]);
    for round in 0..POSEIDON2_ROUNDS {
        poseidon2_round(&mut state, round);
    }
    for i in 0..POSEIDON2_T {
        out[0][i] = state[i].as_int();
    }
    if perm_count >= 2 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] += pub_inputs.block2[i];
        }
        for round in 0..POSEIDON2_ROUNDS {
            poseidon2_round(&mut state, round);
        }
        for i in 0..POSEIDON2_T {
            out[1][i] = state[i].as_int();
        }
    }
    if perm_count >= 3 {
        for i in 0..POSEIDON2_RATE_WORDS {
            state[i] += pub_inputs.block3[i];
        }
        for round in 0..POSEIDON2_ROUNDS {
            poseidon2_round(&mut state, round);
        }
        for i in 0..POSEIDON2_T {
            out[2][i] = state[i].as_int();
        }
    }
    out
}

fn derive_public_inputs(inst: &SpxThashBenchInstanceRawV1) -> Option<Poseidon2ExactPublicInputs> {
    if inst.backend_id != SPX_THASH_BENCH_BACKEND_POSEIDON2_V1 ||
        inst.mode != SPX_THASH_BENCH_MODE_POSEIDON2_EXACT_V1 ||
        !(inst.inblocks == 1 || inst.inblocks == 2) ||
        inst.pub_seed.is_null() ||
        inst.addr.is_null() ||
        inst.input.is_null() ||
        inst.expected_output.is_null() ||
        inst.input_len != inst.inblocks as usize * SPX_N ||
        !inst.rounds.is_power_of_two()
    {
        return None;
    }

    let pub_seed = unsafe { std::slice::from_raw_parts(inst.pub_seed, SPX_N) };
    let addr_words = unsafe { std::slice::from_raw_parts(inst.addr, SPX_ADDR_WORDS) };
    let input = unsafe { std::slice::from_raw_parts(inst.input, inst.input_len) };
    let expected_output = unsafe { std::slice::from_raw_parts(inst.expected_output, SPX_N) };
    let addr_bytes = u32_words_as_bytes(addr_words);

    let mut stream = Vec::with_capacity(1 + SPX_N + SPX_ADDR_BYTES + inst.input_len);
    stream.push(match inst.inblocks {
        1 => 0x11,
        2 => 0x12,
        _ => return None,
    });
    stream.extend_from_slice(pub_seed);
    stream.extend_from_slice(&addr_bytes);
    stream.extend_from_slice(input);

    let mut blocks = Vec::<[BaseElement; POSEIDON2_RATE_WORDS]>::new();
    let mut offset = 0usize;
    while offset + POSEIDON2_RATE_BYTES <= stream.len() {
        let mut block = [BaseElement::ZERO; POSEIDON2_RATE_WORDS];
        for lane in 0..POSEIDON2_RATE_WORDS {
            let start = offset + lane * 8;
            block[lane] = load_lane(&stream[start..start + 8]);
        }
        blocks.push(block);
        offset += POSEIDON2_RATE_BYTES;
    }

    let rem = &stream[offset..];
    let mut final_block = [0u8; POSEIDON2_RATE_BYTES];
    final_block[..rem.len()].copy_from_slice(rem);
    final_block[rem.len()] ^= 0x01;
    final_block[POSEIDON2_RATE_BYTES - 1] ^= 0x80;
    let mut padded = [BaseElement::ZERO; POSEIDON2_RATE_WORDS];
    for lane in 0..POSEIDON2_RATE_WORDS {
        padded[lane] = load_lane(&final_block[lane * 8..lane * 8 + 8]);
    }
    blocks.push(padded);

    if !(blocks.len() == 2 || blocks.len() == 3) {
        return None;
    }
    let final_perm_idx = blocks.len() - 1;
    if inst.rounds < poseidon2_required_rows(final_perm_idx) as u32 {
        return None;
    }

    let mut initial_state = [BaseElement::ZERO; POSEIDON2_T];
    initial_state[..POSEIDON2_RATE_WORDS].copy_from_slice(&blocks[0]);
    let block2 = blocks[1];
    let block3 = if blocks.len() == 3 {
        blocks[2]
    } else {
        [BaseElement::ZERO; POSEIDON2_RATE_WORDS]
    };

    let mut output_lanes = [BaseElement::ZERO; 3];
    for lane in 0..3 {
        output_lanes[lane] = load_lane(&expected_output[lane * 8..lane * 8 + 8]);
    }

    Some(Poseidon2ExactPublicInputs {
        input_mix: mix_bytes(&[input]),
        output_mix: mix_bytes(&[expected_output]),
        output_row: BaseElement::new(poseidon2_output_row(final_perm_idx) as u64),
        final_perm_idx: BaseElement::new(final_perm_idx as u64),
        initial_state,
        block2,
        block3,
        output_lanes,
    })
}

fn build_trace(pub_inputs: &Poseidon2ExactPublicInputs, trace_len: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(POSEIDON2_TRACE_WIDTH, trace_len);
    trace.fill(
        |state| {
            state[..POSEIDON2_T].copy_from_slice(&pub_inputs.initial_state);
            state[12] = BaseElement::ZERO;
            state[13] = BaseElement::ZERO;
            state[14] = BaseElement::ZERO;
        },
        |_, state| {
            if state[14] == BaseElement::ONE {
                return;
            }
            let phase = state[13].as_int() as usize;
            let final_perm_idx = pub_inputs.final_perm_idx.as_int();
            if phase < POSEIDON2_ROUNDS {
                let mut lanes = [BaseElement::ZERO; POSEIDON2_T];
                lanes.copy_from_slice(&state[..POSEIDON2_T]);
                poseidon2_round(&mut lanes, phase);
                state[..POSEIDON2_T].copy_from_slice(&lanes);
                state[13] += BaseElement::ONE;
            } else if phase == POSEIDON2_ROUNDS {
                if state[12] == BaseElement::ZERO {
                    for lane in 0..POSEIDON2_RATE_WORDS {
                        state[lane] += pub_inputs.block2[lane];
                    }
                    state[12] = BaseElement::ONE;
                } else if state[12] == BaseElement::ONE && final_perm_idx == 2 {
                    for lane in 0..POSEIDON2_RATE_WORDS {
                        state[lane] += pub_inputs.block3[lane];
                    }
                    state[12] = BaseElement::new(2);
                } else {
                    state[14] = BaseElement::ONE;
                }
                state[13] += BaseElement::ONE;
            } else {
                state[13] = BaseElement::ZERO;
            }
        },
    );
    trace
}

fn validate_trace(trace: &TraceTable<BaseElement>, pub_inputs: &Poseidon2ExactPublicInputs) -> Result<(), String> {
    let output_row = pub_inputs.output_row.as_int() as usize;
    let final_perm_idx = pub_inputs.final_perm_idx.as_int() as usize;
    let done_row = poseidon2_done_row(final_perm_idx);
    if trace.length() <= output_row {
        return Err(format!(
            "trace too short: len={} output_row={}",
            trace.length(),
            output_row
        ));
    }

    for lane in 0..POSEIDON2_T {
        let got = trace.get(lane, 0);
        let want = pub_inputs.initial_state[lane];
        if got != want {
            return Err(format!("boundary init mismatch lane={} got={} want={}", lane, got, want));
        }
    }
    if trace.get(12, 0) != BaseElement::ZERO {
        return Err(format!("boundary init perm_idx mismatch got={}", trace.get(12, 0)));
    }
    if trace.get(13, 0) != BaseElement::ZERO {
        return Err(format!("boundary init phase mismatch got={}", trace.get(13, 0)));
    }
    if trace.get(14, 0) != BaseElement::ZERO {
        return Err(format!("boundary init done mismatch got={}", trace.get(14, 0)));
    }
    if trace.get(12, output_row) != pub_inputs.final_perm_idx {
        return Err(format!(
            "boundary output perm_idx mismatch row={} got={}",
            output_row,
            trace.get(12, output_row)
        ));
    }
    if trace.get(13, output_row) != BaseElement::new(31) {
        return Err(format!(
            "boundary output phase mismatch row={} got={}",
            output_row,
            trace.get(13, output_row)
        ));
    }
    if trace.get(14, done_row) != BaseElement::ONE {
        return Err(format!(
            "boundary done mismatch row={} got={}",
            done_row,
            trace.get(14, done_row)
        ));
    }
    let ref_states = reference_states(pub_inputs);
    let model_states = model_states_u64(pub_inputs);
    let field_states = model_states_field(pub_inputs);
    let ref_rows = (0..=final_perm_idx)
        .map(|perm_idx| 30usize + perm_idx * 32usize)
        .collect::<Vec<_>>();
    for (perm_idx, _) in ref_rows.iter().enumerate() {
        for lane in 0..POSEIDON2_T {
            if model_states[perm_idx][lane] != ref_states[perm_idx][lane] {
                return Err(format!(
                    "u64 model mismatch perm={} lane={} model={} c_ref={}",
                    perm_idx + 1,
                    lane,
                    model_states[perm_idx][lane],
                    ref_states[perm_idx][lane]
                ));
            }
            if field_states[perm_idx][lane] != ref_states[perm_idx][lane] {
                return Err(format!(
                    "field model mismatch perm={} lane={} field={} c_ref={}",
                    perm_idx + 1,
                    lane,
                    field_states[perm_idx][lane],
                    ref_states[perm_idx][lane]
                ));
            }
        }
    }
    for (perm_idx, row) in ref_rows.iter().enumerate() {
        for lane in 0..POSEIDON2_T {
            let got = trace.get(lane, *row).as_int();
            let want = ref_states[perm_idx][lane];
            if got != want {
                return Err(format!(
                    "reference permutation mismatch perm={} row={} lane={} got={} want={}",
                    perm_idx + 1,
                    row,
                    lane,
                    got,
                    want
                ));
            }
        }
    }

    for lane in 0..3 {
        let got = trace.get(lane, output_row);
        let want = pub_inputs.output_lanes[lane];
        if got != want {
            return Err(format!(
                "boundary output mismatch lane={} row={} got={} want={}",
                lane, output_row, got, want
            ));
        }
    }

    let periodic = Poseidon2ExactAir {
        context: AirContext::new(
            TraceInfo::new(POSEIDON2_TRACE_WIDTH, trace.length()),
            vec![TransitionConstraintDegree::new(1); POSEIDON2_TRANSITION_CONSTRAINTS],
            POSEIDON2_BOUNDARY_ASSERTIONS,
            proof_options(),
        ),
        output_row,
        final_perm_idx: pub_inputs.final_perm_idx,
        initial_state: pub_inputs.initial_state,
        block2: pub_inputs.block2,
        block3: pub_inputs.block3,
        output_lanes: pub_inputs.output_lanes,
    }
    .get_periodic_column_values();

    for row in 0..(trace.length() - 1) {
        let full_flag = periodic[0][row % POSEIDON2_PERIOD];
        let internal_flag = periodic[1][row % POSEIDON2_PERIOD];
        let absorb_flag = periodic[2][row % POSEIDON2_PERIOD];
        let idle_flag = BaseElement::ONE - full_flag - internal_flag - absorb_flag;
        let one = BaseElement::ONE;
        let two = BaseElement::new(2);
        let half = BaseElement::new(GOLDILOCKS_HALF);
        let perm = trace.get(12, row);
        let phase = trace.get(13, row);
        let done = trace.get(14, row);
        let next_done = trace.get(14, row + 1);
        let sel0 = (perm - one) * (perm - two) * half;
        let sel1 = BaseElement::ZERO - perm * (perm - two);
        let sel2 = perm * (perm - one) * half;
        let use_block3 = if final_perm_idx == 2 {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };
        let absorb_increment = sel0 + use_block3 * sel1;
        let done_selector = sel2 + (BaseElement::ONE - use_block3) * sel1;

        for lane in 0..POSEIDON2_T {
            let cur = trace.get(lane, row);
            let next = trace.get(lane, row + 1);
            let mut full_sum = BaseElement::ZERO;
            let mut internal_sum = BaseElement::ZERO;
            let mut full_s = [BaseElement::ZERO; POSEIDON2_T];
            let mut internal_s = [BaseElement::ZERO; POSEIDON2_T];
            for j in 0..POSEIDON2_T {
                let t = trace.get(j, row) + periodic[3 + j][row % POSEIDON2_PERIOD];
                full_s[j] = pow7_base(t);
                full_sum += full_s[j];
                internal_s[j] = t;
            }
            internal_s[0] = pow7_base(internal_s[0]);
            for value in &internal_s {
                internal_sum += *value;
            }
            let full_next = full_sum + full_s[lane];
            let internal_next =
                internal_sum + periodic[15 + lane][row % POSEIDON2_PERIOD] * internal_s[lane];
            let absorb_delta = if lane < POSEIDON2_RATE_WORDS {
                sel0 * pub_inputs.block2[lane] + sel1 * pub_inputs.block3[lane]
            } else {
                BaseElement::ZERO
            };
            let normal = full_flag * full_next
                + internal_flag * internal_next
                + absorb_flag * (cur + absorb_delta)
                + idle_flag * cur;
            let expect = done * cur + (one - done) * normal;
            if next != expect {
                return Err(format!(
                    "transition mismatch row={} lane={} got={} want={} flags=({}, {}, {}) perm={} done={}",
                    row, lane, next, expect, full_flag, internal_flag, absorb_flag, perm, done
                ));
            }
        }

        let next_perm = trace.get(12, row + 1);
        let expect_perm = done * perm + (one - done) * (perm + absorb_flag * absorb_increment);
        if next_perm != expect_perm {
            return Err(format!(
                "perm_idx mismatch row={} got={} want={} absorb_flag={} perm={} done={}",
                row, next_perm, expect_perm, absorb_flag, perm, done
            ));
        }
        let poly = perm * (perm - one) * (perm - two);
        if poly != BaseElement::ZERO {
            return Err(format!("perm_idx domain mismatch row={} perm={}", row, perm));
        }
        let next_phase = trace.get(13, row + 1);
        let normal_phase = if idle_flag == BaseElement::ONE {
            BaseElement::ZERO
        } else {
            phase + BaseElement::ONE
        };
        let expect_phase = done * phase + (one - done) * normal_phase;
        if next_phase != expect_phase {
            return Err(format!(
                "phase mismatch row={} got={} want={} flags=({}, {}, {}) done={}",
                row, next_phase, expect_phase, full_flag, internal_flag, absorb_flag, done
            ));
        }
        let expect_done = done + (one - done) * absorb_flag * done_selector;
        if next_done != expect_done {
            return Err(format!(
                "done mismatch row={} got={} want={} absorb_flag={} perm={}",
                row, next_done, expect_done, absorb_flag, perm
            ));
        }
        if done * (done - one) != BaseElement::ZERO {
            return Err(format!("done domain mismatch row={} done={}", row, done));
        }
    }

    Ok(())
}

impl Air for Poseidon2ExactAir {
    type BaseField = BaseElement;
    type PublicInputs = Poseidon2ExactPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Poseidon2ExactPublicInputs, options: ProofOptions) -> Self {
        // Use intentionally conservative degree bounds to rule out any residual
        // underestimation in periodic-column multiplicities as a source of OOD mismatch.
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(16, vec![POSEIDON2_PERIOD; 16]),
            TransitionConstraintDegree::with_cycles(8, vec![POSEIDON2_PERIOD; 8]),
            TransitionConstraintDegree::with_cycles(8, vec![POSEIDON2_PERIOD; 8]),
            TransitionConstraintDegree::with_cycles(8, vec![POSEIDON2_PERIOD; 8]),
            TransitionConstraintDegree::with_cycles(8, vec![POSEIDON2_PERIOD; 8]),
            TransitionConstraintDegree::new(2),
        ];
        Self {
            context: AirContext::new(trace_info, degrees, POSEIDON2_BOUNDARY_ASSERTIONS, options),
            output_row: pub_inputs.output_row.as_int() as usize,
            final_perm_idx: pub_inputs.final_perm_idx,
            initial_state: pub_inputs.initial_state,
            block2: pub_inputs.block2,
            block3: pub_inputs.block3,
            output_lanes: pub_inputs.output_lanes,
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
        let full_flag = periodic_values[0];
        let internal_flag = periodic_values[1];
        let absorb_flag = periodic_values[2];
        let idle_flag = E::ONE - full_flag - internal_flag - absorb_flag;
        let one = E::ONE;
        let two = E::from(BaseElement::new(2));
        let half = E::from(BaseElement::new(GOLDILOCKS_HALF));
        let use_block3 = E::from(self.final_perm_idx - BaseElement::ONE);
        let perm = current[12];
        let phase = current[13];
        let done = current[14];
        let sel0 = (perm - one) * (perm - two) * half;
        let sel1 = E::ZERO - perm * (perm - two);
        let sel2 = perm * (perm - one) * half;

        let mut tmp = [E::ZERO; POSEIDON2_T];
        for i in 0..POSEIDON2_T {
            tmp[i] = current[i] + periodic_values[3 + i];
        }

        let mut full_s = [E::ZERO; POSEIDON2_T];
        let mut full_sum = E::ZERO;
        for i in 0..POSEIDON2_T {
            full_s[i] = pow7_ext(tmp[i]);
            full_sum += full_s[i];
        }

        let mut internal_s = tmp;
        internal_s[0] = pow7_ext(internal_s[0]);
        let mut internal_sum = E::ZERO;
        for value in &internal_s {
            internal_sum += *value;
        }

        for i in 0..POSEIDON2_T {
            let full_next = full_sum + full_s[i];
            let internal_next = internal_sum + periodic_values[15 + i] * internal_s[i];
            let absorb_delta = if i < POSEIDON2_RATE_WORDS {
                sel0 * E::from(self.block2[i]) + use_block3 * sel1 * E::from(self.block3[i])
            } else {
                E::ZERO
            };
            let absorb_next = current[i] + absorb_delta;
            let normal = full_flag * full_next
                + internal_flag * internal_next
                + absorb_flag * absorb_next
                + idle_flag * current[i];
            result[i] = done * (next[i] - current[i]) + (E::ONE - done) * (next[i] - normal);
        }

        let absorb_increment = sel0 + use_block3 * sel1;
        let done_selector = sel2 + (E::ONE - use_block3) * sel1;
        result[12] = done * (next[12] - perm)
            + (E::ONE - done) * (next[12] - (perm + absorb_flag * absorb_increment));
        result[13] = perm * (perm - one) * (perm - two);
        let normal_phase = idle_flag * E::ZERO + (E::ONE - idle_flag) * (phase + E::ONE);
        result[14] = done * (next[13] - phase) + (E::ONE - done) * (next[13] - normal_phase);
        result[15] = next[14] - (done + (E::ONE - done) * absorb_flag * done_selector);
        result[16] = done * (done - one);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let done_row = poseidon2_done_row(self.final_perm_idx.as_int() as usize);
        let mut assertions = Vec::new();
        for lane in 0..POSEIDON2_T {
            assertions.push(Assertion::single(lane, 0, self.initial_state[lane]));
        }
        assertions.push(Assertion::single(12, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(12, self.output_row, self.final_perm_idx));
        assertions.push(Assertion::single(13, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(13, self.output_row, BaseElement::new(31)));
        assertions.push(Assertion::single(14, 0, BaseElement::ZERO));
        assertions.push(Assertion::single(14, done_row, BaseElement::ONE));
        assertions.push(Assertion::single(0, self.output_row, self.output_lanes[0]));
        assertions.push(Assertion::single(1, self.output_row, self.output_lanes[1]));
        assertions.push(Assertion::single(2, self.output_row, self.output_lanes[2]));
        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut columns = vec![vec![BaseElement::ZERO; POSEIDON2_PERIOD]; 27];
        for row in 0..POSEIDON2_PERIOD {
            if row < POSEIDON2_ROUNDS {
                let (is_full, is_internal) = round_kind(row);
                columns[0][row] = BaseElement::new(if is_full { 1 } else { 0 });
                columns[1][row] = BaseElement::new(if is_internal { 1 } else { 0 });
                for lane in 0..POSEIDON2_T {
                    columns[3 + lane][row] = BaseElement::new(P2_ROUND_CONSTANTS[row][lane]);
                    columns[15 + lane][row] = BaseElement::new(P2_INTERNAL_DIAG_12[lane]);
                }
            } else if row == POSEIDON2_ROUNDS {
                columns[2][row] = BaseElement::ONE;
            }
        }
        columns
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

impl Poseidon2ExactProver {
    fn new(options: ProofOptions, pub_inputs: Poseidon2ExactPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for Poseidon2ExactProver {
    type BaseField = BaseElement;
    type Air = Poseidon2ExactAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Poseidon2ExactPublicInputs {
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
pub unsafe extern "C" fn spx_p2_rust_run_poseidon2_thash_exact_v1(
    out_stats: *mut SpxThashBenchStatsV1,
    inst: *const SpxThashBenchInstanceRawV1,
) -> i32 {
    if out_stats.is_null() || inst.is_null() {
        return SPX_P2_RUST_ERR_NULL;
    }

    let inst_ref = &*inst;
    let pub_inputs = match derive_public_inputs(inst_ref) {
        Some(v) => v,
        None => return SPX_P2_RUST_ERR_INPUT,
    };
    let trace_len = inst_ref.rounds as usize;
    let trace = build_trace(&pub_inputs, trace_len);
    if let Err(msg) = validate_trace(&trace, &pub_inputs) {
        eprintln!("[poseidon2_exact] trace validation failed: {msg}");
        return SPX_P2_RUST_ERR_INPUT;
    }

    let prove_begin = Instant::now();
    let proof = match Poseidon2ExactProver::new(proof_options(), pub_inputs.clone()).prove(trace) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("[poseidon2_exact] prove failed: {err}");
            return SPX_P2_RUST_ERR_PROVE;
        }
    };
    let prove_ms = prove_begin.elapsed().as_secs_f64() * 1000.0;

    let proof_bytes = proof.to_bytes();
    let proof_len = proof_bytes.len() as u64;
    let proof_obj = match Proof::from_bytes(&proof_bytes) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("[poseidon2_exact] proof deserialize failed: {err}");
            return SPX_P2_RUST_ERR_PROVE;
        }
    };

    let verify_begin = Instant::now();
    let min_opts = AcceptableOptions::MinConjecturedSecurity(63);
    if winterfell::verify::<
        Poseidon2ExactAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof_obj, pub_inputs.clone(), &min_opts)
    .map_err(|err| {
        eprintln!("[poseidon2_exact] verify failed: {err}");
        err
    })
    .is_err() {
        return SPX_P2_RUST_ERR_VERIFY;
    }
    let verify_ms = verify_begin.elapsed().as_secs_f64() * 1000.0;
    let stats = &mut *out_stats;
    let (exact_primitive_calls, exact_round_rows) =
        poseidon2_exact_work_units(pub_inputs.final_perm_idx.as_int() as usize);

    *stats = SpxThashBenchStatsV1 {
        backend_id: inst_ref.backend_id,
        mode: inst_ref.mode,
        inblocks: inst_ref.inblocks,
        rounds: exact_round_rows,
        trace_width: POSEIDON2_TRACE_WIDTH as u32,
        trace_length: trace_len as u32,
        transition_constraints: POSEIDON2_TRANSITION_CONSTRAINTS as u32,
        boundary_assertions: POSEIDON2_BOUNDARY_ASSERTIONS as u32,
        constraint_eval_total: POSEIDON2_TRANSITION_CONSTRAINTS as u64 * (trace_len as u64 - 1)
            + POSEIDON2_BOUNDARY_ASSERTIONS as u64,
        proof_bytes: proof_len,
        prove_ms,
        verify_ms,
        exact_primitive_calls,
        exact_round_rows,
        input_mix: pub_inputs.input_mix.as_int(),
        output_mix: pub_inputs.output_mix.as_int(),
        result_tag: pub_inputs.output_lanes[0].as_int(),
    };
    SPX_P2_RUST_OK
}

#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn SPX_poseidon2_permute(_state: *mut u64) {}
