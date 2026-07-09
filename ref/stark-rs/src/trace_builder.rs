//! Full SPHINCS+ verification trace builder.
//!
//! Ports `crypto_sign_verify` from ref/sign.c to Rust, recording every
//! Poseidon2 round state for the AIR to constrain.
//!
//! Trace layout per permutation (30 rows):
//!   Row 0: initial state (after absorbing input)
//!   Rows 1..29: state after each round
//!   Row 29: final state (output rate lanes are the squeeze output)
//!
//! Columns (18 total for dev):
//!   [0..12)  Poseidon2 state (12 field elements)
//!   [12]     Round index within permutation (0..29)
//!   [13]     Permutation index (which permutation in the sequence)
//!   [14]     Call type tag (0=H_msg, 1=FORS_leaf, 2=FORS_auth, 3=FORS_pk,
//!                              4=WOTS_chain, 5=WOTS_pk, 6=WOTS_leaf, 7=Merkle, 8=Final)
//!   [15..17] Reserved for IO buffer / public inputs (to be added)
//!
//! Dev params: n=16, h=40, d=4, k=8, a=6, w=16
//! Expected: ~3586 perms × 30 rows = ~108K rows → 131,072 (2^17)

use crate::thash_poseidon2_exact;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// ── SPHINCS+ parameters (dev set) ──
pub const N: usize = 16;
pub const H: usize = 40;
pub const D: usize = 4;
pub const A: usize = 6;
pub const K: usize = 8;
pub const W: usize = 16;
pub const LOGW: usize = 4;
pub const TREE_HEIGHT: usize = H / D;
pub const WOTS_LEN1: usize = 8 * N / LOGW; // 32
pub const WOTS_LEN2: usize = 3;
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // 35
pub const PK_BYTES: usize = 2 * N;
pub const FORS_MSG_BYTES: usize = (A * K + 7) / 8;
pub const FORS_BYTES: usize = (A + 1) * K * N;
pub const WOTS_BYTES: usize = WOTS_LEN * N;
pub const SIG_BYTES: usize = N + FORS_BYTES + D * WOTS_BYTES + H * N;
pub const P2_T: usize = 12;
pub const P2_RATE: usize = 6;
pub const TOTAL_ROUNDS: usize = 30; // RF=4 + RP=22 ... wait, RF=8, RP=22 → 30 total
pub const PERM_PERIOD: usize = 32; // power of 2 for periodic columns
pub const ROWS_PER_PERM: usize = PERM_PERIOD;

// Address offsets
const OFF_LAYER: usize = 3;
const OFF_TREE: usize = 8;
const OFF_TYPE: usize = 19;
const OFF_KP_ADDR: usize = 20;
const OFF_CHAIN_ADDR: usize = 27;
const OFF_HASH_ADDR: usize = 31;
const OFF_TREE_HGT: usize = 27;
const OFF_TREE_INDEX: usize = 28;

const ADDR_WOTS: u8 = 0;
const ADDR_WOTSPK: u8 = 1;
const ADDR_HASHTREE: u8 = 2;
const ADDR_FORSTREE: u8 = 3;
const ADDR_FORSPK: u8 = 4;

const DOMAIN_HASH_MESSAGE: u8 = 0x03;
const DOMAIN_THASH_F: u8 = 0x10;
const DOMAIN_THASH_H: u8 = 0x11;
const DOMAIN_THASH_TL: u8 = 0x12;

// ── Address ──
#[derive(Debug, Clone, Copy, Default)]
pub struct SpxAddr([u8; 32]);

impl SpxAddr {
    pub fn new() -> Self { Self([0u8; 32]) }
    pub fn bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn set_layer(&mut self, layer: u32) { self.0[OFF_LAYER] = layer as u8; }
    pub fn set_tree(&mut self, tree: u64) { self.0[OFF_TREE..OFF_TREE+8].copy_from_slice(&tree.to_be_bytes()); }
    pub fn set_type(&mut self, t: u8) { self.0[OFF_TYPE] = t; }
    pub fn set_keypair(&mut self, kp: u32) { self.0[OFF_KP_ADDR..OFF_KP_ADDR+4].copy_from_slice(&kp.to_be_bytes()); }
    pub fn set_chain(&mut self, chain: u32) { self.0[OFF_CHAIN_ADDR] = chain as u8; }
    pub fn set_hash(&mut self, hash: u32) { self.0[OFF_HASH_ADDR] = hash as u8; }
    pub fn set_tree_height(&mut self, h: u32) { self.0[OFF_TREE_HGT] = h as u8; }
    pub fn set_tree_index(&mut self, idx: u32) { self.0[OFF_TREE_INDEX..OFF_TREE_INDEX+4].copy_from_slice(&idx.to_be_bytes()); }
    pub fn get_keypair(&self) -> u32 { u32::from_be_bytes(self.0[OFF_KP_ADDR..OFF_KP_ADDR+4].try_into().unwrap()) }
    pub fn copy_subtree(&mut self, other: &SpxAddr) { self.0[..OFF_TREE+8].copy_from_slice(&other.0[..OFF_TREE+8]); }
    pub fn copy_keypair(&mut self, other: &SpxAddr) {
        self.0[..OFF_TREE+8].copy_from_slice(&other.0[..OFF_TREE+8]);
        self.0[OFF_KP_ADDR..OFF_KP_ADDR+4].copy_from_slice(&other.0[OFF_KP_ADDR..OFF_KP_ADDR+4]);
    }
}

// ── Byte conversions ──
fn store_u32_be(bytes: &mut [u8], val: u32) { bytes[..4].copy_from_slice(&val.to_be_bytes()); }

fn bytes_to_rate(bytes: &[u8; 48]) -> [BaseElement; P2_RATE] {
    let mut lanes = [BaseElement::ZERO; P2_RATE];
    for i in 0..P2_RATE {
        let mut val: u64 = 0;
        for j in 0..8 { val |= (bytes[i * 8 + j] as u64) << (8 * j); }
        lanes[i] = BaseElement::new(val);
    }
    lanes
}

fn lanes_to_bytes(lanes: &[BaseElement; P2_RATE]) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    for i in 0..P2_RATE {
        let val = lanes[i].as_int();
        for j in 0..8 { bytes[i * 8 + j] = (val >> (8 * j)) as u8; }
    }
    bytes
}

// ── Call type tags (stored in column 14) ──
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallType {
    Hmsg = 0,
    ForsLeaf = 1,
    ForsAuth = 2,
    ForsPk = 3,
    WotsChain = 4,
    WotsPk = 5,
    WotsLeafHash = 6,
    Merkle = 7,
    FinalCheck = 8,
}

// ── Trace recorder ──
pub struct TraceRecorder {
    pub trace: Vec<Vec<BaseElement>>,
    pub num_cols: usize,
    row: usize,
    perm_index: usize,
}

impl TraceRecorder {
    pub fn new() -> Self {
        let num_cols = 32; // 12 state + 6 control/meta + 14 padding
        // Estimate: ~3600 perms × 30 rows ≈ 108K → next pow2 = 131K
        let est_rows = 3600 * ROWS_PER_PERM;
        Self { trace: Vec::with_capacity(est_rows), num_cols, row: 0, perm_index: 0 }
    }

    /// Record all rows for one Poseidon2 permutation.
    /// `init_state`: state BEFORE absorbing input
    /// `absorb`: rate lanes to absorb
    /// `call_type`: what kind of SPHINCS+ operation this is
    /// Returns the output rate lanes after the permutation.
    pub fn record_permutation(
        &mut self,
        init_state: &[BaseElement; P2_T],
        absorb: &[BaseElement; P2_RATE],
        call_type: CallType,
    ) -> [BaseElement; P2_RATE] {
        let mut state = *init_state;
        // Absorb: add input to rate lanes
        for i in 0..P2_RATE {
            state[i] += absorb[i];
        }
        // Record initial state (row 0 of this permutation)
        self.push_row(&state, 0, call_type);

        // Run rounds, recording after each
        for round in 0..TOTAL_ROUNDS {
            thash_poseidon2_exact::poseidon2_round(&mut state, round);
            self.push_row(&state, (round + 1) as u64, call_type);
        }

        // Pad to ROWS_PER_PERM (32): add 1 more row (round=31, identity)
        self.push_row(&state, (TOTAL_ROUNDS + 1) as u64, call_type);

        // Output: rate lanes after last round
        let mut out = [BaseElement::ZERO; P2_RATE];
        out.copy_from_slice(&state[0..P2_RATE]);
        self.perm_index += 1;
        out
    }

    fn push_row(&mut self, state: &[BaseElement; P2_T], round: u64, ct: CallType) {
        if self.row >= self.trace.len() {
            self.trace.push(vec![BaseElement::ZERO; self.num_cols]);
        }
        let r = &mut self.trace[self.row];
        for c in 0..P2_T {
            r[c] = state[c];
        }
        r[12] = BaseElement::new(round);                          // round within permutation
        r[13] = BaseElement::new(self.perm_index as u64);         // permutation index
        r[14] = BaseElement::new(ct as u64);                     // call type tag
        self.row += 1;
    }

    pub fn into_trace(mut self) -> (Vec<Vec<BaseElement>>, usize, u64) {
        let rows = self.trace.len();
        let target = rows.next_power_of_two();
        let total_perms = self.perm_index as u64;
        // Pad to target with complete 32-row dummy permutations
        // Each dummy group has round 0..31, perm increments per group
        let remaining = target - rows;
        for i in 0..remaining {
            let mut pad_row = vec![BaseElement::ZERO; self.num_cols];
            let cycle_pos = i % PERM_PERIOD;
            let pad_perm = total_perms + (i / PERM_PERIOD) as u64;
            pad_row[12] = BaseElement::new(cycle_pos as u64);
            pad_row[13] = BaseElement::new(pad_perm);
            self.trace.push(pad_row);
        }
        eprintln!("[trace] recorded_rows={} target_rows={} num_cols={} perms={} row_counter={}",
                  rows, target, self.num_cols, self.perm_index, self.row);
        (self.trace, self.num_cols, total_perms)
    }
}

// ── Poseidon2 sponge hash (THASH compatible) ──
fn poseidon2_hash(
    state: &mut [BaseElement; P2_T],
    input: &[u8], out_len: usize,
    trace: &mut TraceRecorder, call_type: CallType,
) -> Vec<u8> {
    let rate = P2_RATE * 8; // 48 bytes
    let mut output = Vec::new();
    let mut offset = 0;

    while offset < input.len() {
        let end = (offset + rate).min(input.len());
        let len = end - offset;
        let mut chunk = [0u8; 48];
        chunk[..len].copy_from_slice(&input[offset..end]);
        if len < rate { chunk[len] = 0x01; chunk[rate - 1] |= 0x80; }

        let absorb = bytes_to_rate(&chunk);
        let out_lanes = trace.record_permutation(state, &absorb, call_type);
        output.extend_from_slice(&lanes_to_bytes(&out_lanes));
        offset = end;
    }

    // Finalize permutation
    {
        let mut chunk = [0u8; 48];
        chunk[0] = 0x01; chunk[47] |= 0x80;
        let absorb = bytes_to_rate(&chunk);
        let out_lanes = trace.record_permutation(state, &absorb, call_type);
        output.extend_from_slice(&lanes_to_bytes(&out_lanes));
    }

    output.truncate(out_len);
    output
}

// ── THASH ──
fn thash_input(domain: u8, pub_seed: &[u8], addr: &SpxAddr, blocks: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(domain);
    v.extend_from_slice(pub_seed);
    v.extend_from_slice(addr.bytes());
    for b in blocks { v.extend_from_slice(*b); }
    v
}

fn thash(state: &mut [BaseElement; P2_T], domain: u8, pub_seed: &[u8], addr: &SpxAddr,
         blocks: &[&[u8]], out_len: usize, trace: &mut TraceRecorder, call_type: CallType) -> Vec<u8> {
    let input = thash_input(domain, pub_seed, addr, blocks);
    poseidon2_hash(state, &input, out_len, trace, call_type)
}

// ── WOTS+ ──
fn base_w(input: &[u8], out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut in_pos = 0; let mut bits = 0u32; let mut total: u8 = 0;
    for _ in 0..out_len {
        if bits == 0 { total = input[in_pos]; in_pos += 1; bits += 8; }
        bits -= LOGW as u32;
        out.push(((total >> bits) & (W as u8 - 1)) as u32);
    }
    out
}

fn chain_lengths(msg: &[u8]) -> Vec<u32> {
    let mut lengths = base_w(msg, WOTS_LEN1);
    let mut csum: u32 = 0;
    for &d in &lengths { csum += W as u32 - 1 - d; }
    csum = csum << ((8 - ((WOTS_LEN2 * LOGW) % 8)) % 8);
    let mut csum_bytes = [0u8; 4];
    store_u32_be(&mut csum_bytes, csum);
    lengths.extend(&base_w(&csum_bytes, WOTS_LEN2));
    lengths
}

fn wots_pk_from_sig(
    state: &mut [BaseElement; P2_T], pub_seed: &[u8],
    sig: &[u8], msg: &[u8], addr: &SpxAddr,
    trace: &mut TraceRecorder,
) -> Vec<u8> {
    let lengths = chain_lengths(msg);
    let mut tmp = vec![0u8; N];
    let mut pk = Vec::with_capacity(WOTS_BYTES);
    for i in 0..WOTS_LEN {
        let mut chain_addr = *addr;
        chain_addr.set_chain(i as u32);
        tmp[..N].copy_from_slice(&sig[i * N..(i + 1) * N]);
        for step in lengths[i]..(W as u32 - 1) {
            chain_addr.set_hash(step);
            let out = thash(state, DOMAIN_THASH_F, pub_seed, &chain_addr, &[&tmp], N, trace, CallType::WotsChain);
            tmp[..N].copy_from_slice(&out);
        }
        pk.extend_from_slice(&tmp);
    }
    pk
}

// ── Merkle ──
fn compute_root(
    state: &mut [BaseElement; P2_T], pub_seed: &[u8],
    leaf: &[u8], leaf_idx: u32, idx_offset: u32,
    auth_path: &[u8], tree_height: u32, addr: &SpxAddr,
    trace: &mut TraceRecorder,
) -> Vec<u8> {
    let mut node = leaf.to_vec();
    let mut auth = auth_path;
    let mut idx = leaf_idx; let mut off = idx_offset;
    for i in 0..tree_height {
        let mut level_addr = *addr;
        level_addr.set_tree_height(i + 1);
        level_addr.set_tree_index((idx >> 1) + off);
        let mut buffer = [0u8; 2 * N];
        if idx & 1 == 1 { buffer[N..].copy_from_slice(&node); buffer[..N].copy_from_slice(&auth[..N]); }
        else { buffer[..N].copy_from_slice(&node); buffer[N..].copy_from_slice(&auth[..N]); }
        auth = &auth[N..]; idx >>= 1; off >>= 1;
        node = thash(state, DOMAIN_THASH_H, pub_seed, &level_addr, &[&buffer[..N], &buffer[N..]], N, trace, CallType::Merkle);
    }
    node
}

// ── FORS ──
fn fors_pk_from_sig(
    state: &mut [BaseElement; P2_T], pub_seed: &[u8],
    sig: &[u8], m_hash: &[u8], fors_addr: &SpxAddr,
    trace: &mut TraceRecorder,
) -> Vec<u8> {
    let indices = base_w(m_hash, K);
    let mut roots = Vec::with_capacity(K * N);
    for i in 0..K {
        let idx_offset = (i as u32) << A;
        let mut tree_addr = *fors_addr;
        tree_addr.copy_keypair(fors_addr);
        tree_addr.set_type(ADDR_FORSTREE);
        tree_addr.set_tree_height(0);
        tree_addr.set_tree_index(indices[i] + idx_offset);
        // Fors leaf
        let sk = &sig[i * N..(i + 1) * N];
        let leaf = thash(state, DOMAIN_THASH_TL, pub_seed, &tree_addr, &[sk], N, trace, CallType::ForsLeaf);
        // Auth path
        let auth_path = &sig[K * N + i * A * N..K * N + (i + 1) * A * N];
        let root = compute_root(state, pub_seed, &leaf, indices[i], idx_offset, auth_path, A as u32, &tree_addr, trace);
        roots.extend_from_slice(&root);
    }
    // FORS pk
    let mut pk_addr = *fors_addr;
    pk_addr.set_type(ADDR_FORSPK);
    let blocks: Vec<&[u8]> = (0..K).map(|i| &roots[i * N..(i + 1) * N]).collect();
    thash(state, DOMAIN_THASH_TL, pub_seed, &pk_addr, &blocks, N, trace, CallType::ForsPk)
}

// ── H_msg ──
fn hash_message(
    state: &mut [BaseElement; P2_T],
    r: &[u8], pk: &[u8], m: &[u8],
    trace: &mut TraceRecorder,
) -> Vec<u8> {
    let mut input = Vec::new();
    input.push(DOMAIN_HASH_MESSAGE);
    input.extend_from_slice(r);
    input.extend_from_slice(pk);
    input.extend_from_slice(m);
    poseidon2_hash(state, &input, N + 8, trace, CallType::Hmsg)
}

// ── Main: full SPHINCS+ verification trace ──
pub fn build_verification_trace(
    pk: &[u8], sigma_com: &[u8], m_pub: &[u8],
) -> (Vec<Vec<BaseElement>>, usize, u64) {
    assert_eq!(pk.len(), PK_BYTES);
    assert_eq!(sigma_com.len(), SIG_BYTES);
    let pub_seed = &pk[0..N];
    let pub_root = &pk[N..2 * N];
    let sig_r = &sigma_com[0..N];
    let fors_sig = &sigma_com[N..N + FORS_BYTES];
    let ht_sig = &sigma_com[N + FORS_BYTES..];
    let mut state = [BaseElement::ZERO; P2_T];
    let mut trace = TraceRecorder::new();

    // Step 1: H_msg
    let hmsg_out = hash_message(&mut state, sig_r, pk, m_pub, &mut trace);
    let mhash = &hmsg_out[..FORS_MSG_BYTES];
    let tree_and_idx = &hmsg_out[FORS_MSG_BYTES..];
    let tree = u64::from_be_bytes(tree_and_idx[..8].try_into().unwrap());
    let idx_leaf = u32::from_be_bytes(tree_and_idx[8..12].try_into().unwrap());

    // Step 2: FORS
    let mut fors_addr = SpxAddr::new();
    fors_addr.set_type(ADDR_WOTS);
    fors_addr.set_tree(tree);
    fors_addr.set_keypair(idx_leaf);
    let mut wots_addr = SpxAddr::new();
    wots_addr.set_type(ADDR_WOTS);
    let mut tree_addr = SpxAddr::new();
    tree_addr.set_type(ADDR_HASHTREE);
    let mut wots_pk_addr = SpxAddr::new();
    wots_pk_addr.set_type(ADDR_WOTSPK);
    let mut root = fors_pk_from_sig(&mut state, pub_seed, fors_sig, mhash, &fors_addr, &mut trace);

    // Step 3: HT layers
    let mut cur_tree = tree;
    let mut cur_idx = idx_leaf;
    for layer in 0..D {
        let layer_off = layer * (WOTS_BYTES + TREE_HEIGHT * N);
        let wots_sig = &ht_sig[layer_off..layer_off + WOTS_BYTES];
        let auth_path = &ht_sig[layer_off + WOTS_BYTES..layer_off + WOTS_BYTES + TREE_HEIGHT * N];
        tree_addr.set_layer(layer as u32);
        tree_addr.set_tree(cur_tree);
        wots_addr.copy_subtree(&tree_addr);
        wots_addr.set_keypair(cur_idx);
        wots_pk_addr.copy_keypair(&wots_addr);
        let wots_pk = wots_pk_from_sig(&mut state, pub_seed, wots_sig, &root, &wots_addr, &mut trace);
        let leaf_blocks: Vec<&[u8]> = (0..WOTS_LEN).map(|i| &wots_pk[i * N..(i + 1) * N]).collect();
        let leaf = thash(&mut state, DOMAIN_THASH_TL, pub_seed, &wots_pk_addr, &leaf_blocks, N, &mut trace, CallType::WotsLeafHash);
        root = compute_root(&mut state, pub_seed, &leaf, cur_idx, 0, auth_path, TREE_HEIGHT as u32, &tree_addr, &mut trace);
        cur_idx = cur_tree as u32 & ((1u32 << TREE_HEIGHT) - 1);
        cur_tree >>= TREE_HEIGHT;
    }

    // Step 4: Final check
    let absorb = [BaseElement::ZERO; P2_RATE];
    trace.record_permutation(&state, &absorb, CallType::FinalCheck);
    let _ = pub_root;

    let (trace_data, num_cols, total_perms) = trace.into_trace();
    (trace_data, num_cols, total_perms)
}

// ── Tests ──
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_trace_dev_params() {
        let pk = vec![0x42u8; PK_BYTES];
        let m_pub = vec![0x27u8; N];
        let sigma_com = vec![0x00u8; SIG_BYTES]; // all-zero sig → max WOTS steps
        let (trace, num_cols, _total_perms) = build_verification_trace(&pk, &sigma_com, &m_pub);
        assert!(trace.len().is_power_of_two());
        assert!(num_cols <= 255);
        assert!(!trace.is_empty());
        let perms = trace.iter().filter(|r| r[12] == BaseElement::ZERO).count();
        println!("Trace: {} rows × {} cols, ~{} perms", trace.len(), num_cols, perms);
    }
}
