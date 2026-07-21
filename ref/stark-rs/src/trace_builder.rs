//! Full SPHINCS+ verification trace builder.
//! Dev params: n=16, h=40, d=4, k=8, a=6, w=16
//!
//! Trace columns (64):
//!   [0..12)  Poseidon2 state at current row
//!   [12]     Round index (0..31)
//!   [13]     Permutation index
//!   [14]     Call type tag
//!   [15]     Padding flag (0=real, 1=pad)
//!   [16..28) Expected next state (pre-computed via poseidon2_round)
//!   [28..64) Reserved (zero-padded)

use crate::thash_poseidon2_exact;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// ── SPHINCS+ parameters (configurable) ──

#[derive(Debug, Clone, Copy)]
pub struct SpxParams {
    pub n: usize, pub h: usize, pub d: usize, pub k: usize, pub a: usize, pub w: usize,
}

impl SpxParams {
    pub fn logw(&self) -> usize { if self.w == 256 { 8 } else { 4 } }
    pub fn wots_len1(&self) -> usize { 8 * self.n / self.logw() }
    pub fn wots_len2(&self) -> usize { if self.w == 16 && self.n <= 136 { 3 } else { 2 } }
    pub fn wots_len(&self) -> usize { self.wots_len1() + self.wots_len2() }
    pub fn tree_height(&self) -> usize { self.h / self.d }
    pub fn pk_bytes(&self) -> usize { 2 * self.n }
    pub fn fors_bytes(&self) -> usize { (self.a + 1) * self.k * self.n }
    pub fn wots_bytes(&self) -> usize { self.wots_len() * self.n }
    pub fn sig_bytes(&self) -> usize {
        self.n + self.fors_bytes() + self.d * self.wots_bytes() + self.h * self.n
    }
    pub fn fors_msg_bytes(&self) -> usize { (self.a * self.k + 7) / 8 }
}

// Dev params (fast iteration, no security claims)
pub const PARAMS_DEV: SpxParams = SpxParams { n: 16, h: 40, d: 4, k: 8, a: 6, w: 16 };

// Candidate 13: balanced (recommended for paper)
pub const PARAMS_C13: SpxParams = SpxParams { n: 16, h: 60, d: 6, k: 14, a: 12, w: 16 };

// Prove-fast variant (d=4, fewer layers → faster proving)
pub const PARAMS_FAST: SpxParams = SpxParams { n: 16, h: 60, d: 4, k: 14, a: 12, w: 16 };

// Default: dev params (fast iteration, no security claims)
pub const N: usize = 16; pub const H: usize = 40; pub const D: usize = 4;
pub const A: usize = 6; pub const K: usize = 8; pub const W: usize = 16; pub const LOGW: usize = 4;
pub const TREE_HEIGHT: usize = H / D;
pub const WOTS_LEN1: usize = 8 * N / LOGW; pub const WOTS_LEN2: usize = 3;
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2;
pub const PK_BYTES: usize = 2 * N; pub const FORS_BYTES: usize = (A + 1) * K * N;
pub const WOTS_BYTES: usize = WOTS_LEN * N;
pub const SIG_BYTES: usize = N + FORS_BYTES + D * WOTS_BYTES + H * N;
pub const FORS_MSG_BYTES: usize = (A * K + 7) / 8;
pub const P2_T: usize = 12; pub const P2_RATE: usize = 6;
pub const TOTAL_ROUNDS: usize = 30; pub const PERM_PERIOD: usize = 32;
pub const TRACE_COLS: usize = 64;

// Address offsets
const OFF_LAYER: usize = 3; const OFF_TREE: usize = 8; const OFF_TYPE: usize = 19;
const OFF_KP_ADDR: usize = 20; const OFF_CHAIN_ADDR: usize = 27; const OFF_HASH_ADDR: usize = 31;
const OFF_TREE_HGT: usize = 27; const OFF_TREE_INDEX: usize = 28;
const ADDR_WOTS: u8 = 0; const ADDR_WOTSPK: u8 = 1; const ADDR_HASHTREE: u8 = 2;
const ADDR_FORSTREE: u8 = 3; const ADDR_FORSPK: u8 = 4;
const DOMAIN_HASH_MESSAGE: u8 = 0x03; const DOMAIN_THASH_F: u8 = 0x11;
const DOMAIN_THASH_H: u8 = 0x12; const DOMAIN_THASH_TL: u8 = 0x13;
const DOMAIN_COMMIT: u8 = 0x20; const DOMAIN_CUSTOM: u8 = 0xFF;

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

fn store_u32_be(bytes: &mut [u8], val: u32) { bytes[..4].copy_from_slice(&val.to_be_bytes()); }
fn bytes_to_rate(bytes: &[u8; 48]) -> [BaseElement; P2_RATE] {
    let mut lanes = [BaseElement::ZERO; P2_RATE];
    for i in 0..P2_RATE { let mut val: u64 = 0; for j in 0..8 { val |= (bytes[i*8+j] as u64) << (8*j); } lanes[i] = BaseElement::new(val); }
    lanes
}
fn lanes_to_bytes(lanes: &[BaseElement; P2_RATE]) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    for i in 0..P2_RATE { let val = lanes[i].as_int(); for j in 0..8 { bytes[i*8+j] = (val >> (8*j)) as u8; } }
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CallType { Hmsg=0, ForsLeaf=1, ForsAuth=2, ForsPk=3, WotsChain=4, WotsPk=5, WotsLeafHash=6, Merkle=7, FinalCheck=8, Commit=9, Encrypt=10 }

// ── Trace Recorder ──
pub struct TraceRecorder {
    trace: Vec<Vec<BaseElement>>, num_cols: usize, row: usize, perm_index: usize,
}

impl TraceRecorder {
    pub fn new() -> Self {
        Self { trace: Vec::with_capacity(4000*PERM_PERIOD), num_cols: TRACE_COLS, row: 0, perm_index: 0 }
    }

    fn push_row(&mut self, state: &[BaseElement; P2_T], expected_next: &[BaseElement; P2_T],
                 round: u64, ct: CallType, absorb: &[BaseElement; P2_RATE],
                 domain_tag: u8, addr: &SpxAddr,
                 carries_from_prev: bool, carries_to_next: bool,
                 init_state: &[BaseElement; P2_T]) {
        if self.row >= self.trace.len() { self.trace.push(vec![BaseElement::ZERO; self.num_cols]); }
        let r = &mut self.trace[self.row];
        for c in 0..P2_T { r[c] = state[c]; }
        r[12] = BaseElement::new(round);
        r[13] = BaseElement::new(self.perm_index as u64);
        r[14] = BaseElement::new(ct as u64);
        for c in 0..P2_T { r[16 + c] = expected_next[c]; }
        // carries flags at every row (needed for continuity constraints at is_last)
        r[39] = BaseElement::new(if carries_from_prev { 1 } else { 0 });
        r[40] = BaseElement::new(if carries_to_next { 1 } else { 0 });
        if round == 0 {
            for i in 0..P2_RATE { r[28 + i] = absorb[i]; }
            // Store init_state in cols 41-52 (at row 0 only)
            for lane in 0..P2_T { r[41 + lane] = init_state[lane]; }
            r[34] = BaseElement::new(domain_tag as u64);
            let ab = addr.bytes();
            for w in 0..4 {
                let mut val: u64 = 0;
                for b in 0..8 { val |= (ab[w*8 + b] as u64) << (8 * b); }
                r[35 + w] = BaseElement::new(val);
            }
        }
        self.row += 1;
    }

    pub fn record_permutation(&mut self, init_state: &[BaseElement; P2_T],
                               absorb: &[BaseElement; P2_RATE], call_type: CallType,
                               domain_tag: u8, addr: &SpxAddr,
                               carries_from_prev: bool, carries_to_next: bool) -> [BaseElement; P2_T] {
        let mut state = *init_state;
        for i in 0..P2_RATE { state[i] += absorb[i]; }
        let zero_absorb = [BaseElement::ZERO; P2_RATE];
        let zero_addr = SpxAddr::new();
        // Row 0: initial state. Expected next = after round 0.
        let mut after_r0 = state;
        thash_poseidon2_exact::poseidon2_round(&mut after_r0, 0);
        self.push_row(&state, &after_r0, 0, call_type, absorb, domain_tag, addr,
                      carries_from_prev, carries_to_next, init_state);
        state = after_r0;

        // Rows 1..29
        for round in 1..TOTAL_ROUNDS {
            let mut next_state = state;
            thash_poseidon2_exact::poseidon2_round(&mut next_state, round);
            self.push_row(&state, &next_state, round as u64, call_type, &zero_absorb, 0, &zero_addr,
                          carries_from_prev, carries_to_next, init_state);
            state = next_state;
        }
        // Row 30: identity pad
        self.push_row(&state, &state, TOTAL_ROUNDS as u64, call_type, &zero_absorb, 0, &zero_addr,
                      carries_from_prev, carries_to_next, init_state);
        // Row 31: terminating pad
        self.push_row(&state, &[BaseElement::ZERO; P2_T], (TOTAL_ROUNDS+1) as u64, call_type, &zero_absorb, 0, &zero_addr,
                      carries_from_prev, carries_to_next, init_state);

        let mut out = [BaseElement::ZERO; P2_T];
        out.copy_from_slice(&state);
        self.perm_index += 1;
        out
    }

    pub fn into_trace(mut self) -> (Vec<Vec<BaseElement>>, usize, u64) {
        let rows = self.trace.len(); let target = rows.next_power_of_two();
        let total_perms = self.perm_index as u64;
        let remaining = target - rows;
        for i in 0..remaining {
            let mut pad_row = vec![BaseElement::ZERO; self.num_cols];
            let cycle_pos = i % PERM_PERIOD;
            let pad_perm = total_perms + (i / PERM_PERIOD) as u64;
            pad_row[12] = BaseElement::new(cycle_pos as u64);
            pad_row[13] = BaseElement::new(pad_perm);
            pad_row[15] = BaseElement::ONE;
            self.trace.push(pad_row);
        }
        (self.trace, self.num_cols, total_perms)
    }
}

// ── Poseidon2 hash (matches C poseidon2_hash_bytes_domain sponge semantics) ──
fn poseidon2_hash(state: &mut [BaseElement; P2_T], input: &[u8], out_len: usize,
                  trace: &mut TraceRecorder, call_type: CallType,
                  domain_tag: u8, addr: &SpxAddr) -> Vec<u8> {
    let rate = P2_RATE * 8;
    // Each hash operation starts from ZERO (matches C poseidon2_inc_init)
    let mut sponge = [BaseElement::ZERO; P2_T];
    let mut output = Vec::new();
    let mut offset = 0;

    // Process full 48-byte blocks (no padding — matches C absorb full blocks)
    while offset + rate <= input.len() {
        let chunk: &[u8; 48] = input[offset..offset + rate].try_into().unwrap();
        let absorb = bytes_to_rate(chunk);
        let carries_from_prev = offset > 0;
        let carries_to_next = true; // always more blocks follow (data or final pad)
        let out_st = trace.record_permutation(&sponge, &absorb, call_type, domain_tag, addr,
                                               carries_from_prev, carries_to_next);
        sponge = out_st;
        let mut rate_lanes = [BaseElement::ZERO; P2_RATE];
        rate_lanes.copy_from_slice(&sponge[0..P2_RATE]);
        output.extend_from_slice(&lanes_to_bytes(&rate_lanes));
        offset += rate;
    }

    // Final block: always padded (matches C poseidon2_inc_finalize: pad10*1 then permute)
    let remaining = input.len() - offset;
    let mut chunk = [0u8; 48];
    chunk[..remaining].copy_from_slice(&input[offset..]);
    chunk[remaining] ^= 0x01;
    chunk[rate - 1] ^= 0x80;
    let absorb = bytes_to_rate(&chunk);
    let carries_from_prev = offset > 0;
    let carries_to_next = false; // last permutation in this hash chain
    sponge = trace.record_permutation(&sponge, &absorb, call_type, domain_tag, addr,
                                       carries_from_prev, carries_to_next);
    let mut rate_lanes = [BaseElement::ZERO; P2_RATE];
    rate_lanes.copy_from_slice(&sponge[0..P2_RATE]);
    output.extend_from_slice(&lanes_to_bytes(&rate_lanes));

    *state = sponge; // return final sponge state to caller
    output.truncate(out_len); output
}

// ── THASH ──
fn thash_input(domain: u8, pub_seed: &[u8], addr: &SpxAddr, blocks: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new(); v.push(domain); v.extend_from_slice(pub_seed); v.extend_from_slice(addr.bytes());
    for b in blocks { v.extend_from_slice(*b); } v
}
fn thash(state: &mut [BaseElement; P2_T], domain: u8, pub_seed: &[u8], addr: &SpxAddr,
         blocks: &[&[u8]], out_len: usize, trace: &mut TraceRecorder, call_type: CallType) -> Vec<u8> {
    let input = thash_input(domain, pub_seed, addr, blocks);
    poseidon2_hash(state, &input, out_len, trace, call_type, domain, addr)
}

// ── WOTS+, Merkle, FORS, H_msg (same as before, using CallType variants) ──
fn base_w(input: &[u8], out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len); let mut in_pos = 0; let mut bits = 0u32; let mut total: u8 = 0;
    for _ in 0..out_len {
        if bits == 0 { total = input[in_pos]; in_pos += 1; bits += 8; }
        bits -= LOGW as u32; out.push(((total >> bits) & (W as u8 - 1)) as u32);
    } out
}
fn chain_lengths(msg: &[u8]) -> Vec<u32> {
    let mut lengths = base_w(msg, WOTS_LEN1); let mut csum: u32 = 0;
    for &d in &lengths { csum += W as u32 - 1 - d; }
    csum = csum << ((8 - ((WOTS_LEN2 * LOGW) % 8)) % 8);
    let mut csum_bytes = [0u8; 4]; store_u32_be(&mut csum_bytes, csum);
    lengths.extend(&base_w(&csum_bytes, WOTS_LEN2)); lengths
}
fn wots_pk_from_sig(state: &mut [BaseElement; P2_T], pub_seed: &[u8], sig: &[u8], msg: &[u8],
                    addr: &SpxAddr, trace: &mut TraceRecorder) -> Vec<u8> {
    let lengths = chain_lengths(msg); let mut tmp = vec![0u8; N]; let mut pk = Vec::with_capacity(WOTS_BYTES);
    for i in 0..WOTS_LEN { let mut chain_addr = *addr; chain_addr.set_chain(i as u32);
        tmp[..N].copy_from_slice(&sig[i*N..(i+1)*N]);
        for step in lengths[i]..(W as u32 - 1) { chain_addr.set_hash(step);
            let out = thash(state, DOMAIN_THASH_F, pub_seed, &chain_addr, &[&tmp], N, trace, CallType::WotsChain);
            tmp[..N].copy_from_slice(&out); }
        pk.extend_from_slice(&tmp); } pk
}
fn compute_root(state: &mut [BaseElement; P2_T], pub_seed: &[u8], leaf: &[u8], leaf_idx: u32,
                idx_offset: u32, auth_path: &[u8], tree_height: u32, addr: &SpxAddr,
                trace: &mut TraceRecorder) -> Vec<u8> {
    let mut node = leaf.to_vec(); let mut auth = auth_path; let mut idx = leaf_idx; let mut off = idx_offset;
    for i in 0..tree_height { let mut level_addr = *addr; level_addr.set_tree_height(i+1);
        level_addr.set_tree_index((idx>>1)+off); let mut buffer = [0u8; 2*N];
        if idx&1==1 { buffer[N..].copy_from_slice(&node); buffer[..N].copy_from_slice(&auth[..N]); }
        else { buffer[..N].copy_from_slice(&node); buffer[N..].copy_from_slice(&auth[..N]); }
        auth=&auth[N..]; idx>>=1; off>>=1;
        node = thash(state, DOMAIN_THASH_H, pub_seed, &level_addr, &[&buffer[..N],&buffer[N..]], N, trace, CallType::Merkle); }
    node
}
fn fors_pk_from_sig(state: &mut [BaseElement; P2_T], pub_seed: &[u8], sig: &[u8], m_hash: &[u8],
                    fors_addr: &SpxAddr, trace: &mut TraceRecorder) -> Vec<u8> {
    let indices = base_w(m_hash, K); let mut roots = Vec::with_capacity(K*N);
    for i in 0..K { let idx_offset = (i as u32)<<A; let mut tree_addr = *fors_addr;
        tree_addr.copy_keypair(fors_addr); tree_addr.set_type(ADDR_FORSTREE);
        tree_addr.set_tree_height(0); tree_addr.set_tree_index(indices[i]+idx_offset);
        let sk = &sig[i*N..(i+1)*N];
        let leaf = thash(state, DOMAIN_THASH_TL, pub_seed, &tree_addr, &[sk], N, trace, CallType::ForsLeaf);
        let auth_path = &sig[K*N + i*A*N..K*N + (i+1)*A*N];
        let root = compute_root(state, pub_seed, &leaf, indices[i], idx_offset, auth_path, A as u32, &tree_addr, trace);
        roots.extend_from_slice(&root); }
    let mut pk_addr = *fors_addr; pk_addr.set_type(ADDR_FORSPK);
    let blocks: Vec<&[u8]> = (0..K).map(|i| &roots[i*N..(i+1)*N]).collect();
    thash(state, DOMAIN_THASH_TL, pub_seed, &pk_addr, &blocks, N, trace, CallType::ForsPk)
}
fn hash_message(state: &mut [BaseElement; P2_T], r: &[u8], pk: &[u8], msg: &[u8],
                trace: &mut TraceRecorder) -> (Vec<u8>, usize) {
    let mut input = Vec::new(); input.push(DOMAIN_HASH_MESSAGE); input.extend_from_slice(r);
    input.extend_from_slice(pk); input.extend_from_slice(msg);
    let out_len = FORS_MSG_BYTES + 16;
    let addr = SpxAddr::new(); // H_msg uses zero address
    (poseidon2_hash(state, &input, out_len, trace, CallType::Hmsg, DOMAIN_HASH_MESSAGE, &addr), out_len)
}

// ── Main (dev params, backward compat) ──
pub fn build_verification_trace(pk: &[u8], sigma_com: &[u8], m_pub: &[u8],
    m: &[u8], r: &[u8], pk_e: &[u8], omega2: &[u8]) -> (Vec<Vec<BaseElement>>, usize, u64, BaseElement, BaseElement, BaseElement, BaseElement) {
    assert_eq!(pk.len(), PK_BYTES); assert_eq!(sigma_com.len(), SIG_BYTES);
    let pub_seed = &pk[0..N]; let sig_r = &sigma_com[0..N];
    let fors_sig = &sigma_com[N..N+FORS_BYTES]; let ht_sig = &sigma_com[N+FORS_BYTES..];
    let mut state = [BaseElement::ZERO; P2_T]; let mut trace = TraceRecorder::new();

    // ── Commit: com = Poseidon2(domain=0x20, m || r) ──
    let mut com_input = Vec::new();
    com_input.push(DOMAIN_COMMIT);
    com_input.extend_from_slice(m);
    com_input.extend_from_slice(r);
    let addr = SpxAddr::new();
    let com_output = poseidon2_hash(&mut state, &com_input, N, &mut trace,
        CallType::Commit, DOMAIN_COMMIT, &addr);

    // H_msg signs com_output (the commitment), matching C's crypto_sign_verify(com, ...)
    let (hmsg_out, _hmsg_len) = hash_message(&mut state, sig_r, pk, &com_output, &mut trace);
    let mhash = &hmsg_out[..FORS_MSG_BYTES];
    // tree and idx_leaf extracted from hash output (exact format from C's hash_message)
    let tree = if hmsg_out.len() >= FORS_MSG_BYTES + 8 {
        u64::from_be_bytes(hmsg_out[FORS_MSG_BYTES..FORS_MSG_BYTES+8].try_into().unwrap_or([0;8]))
    } else { 0 };
    let idx_leaf = if hmsg_out.len() >= FORS_MSG_BYTES + 12 {
        u32::from_be_bytes(hmsg_out[FORS_MSG_BYTES+8..FORS_MSG_BYTES+12].try_into().unwrap_or([0;4]))
    } else { 0 };
    // Clamp to valid range
    let tree = tree & ((1u64 << (H - H/D)) - 1);
    let idx_leaf = idx_leaf & ((1u32 << TREE_HEIGHT) - 1);

    let mut fors_addr = SpxAddr::new(); fors_addr.set_type(ADDR_WOTS); fors_addr.set_tree(tree); fors_addr.set_keypair(idx_leaf);
    let mut wots_addr = SpxAddr::new(); wots_addr.set_type(ADDR_WOTS);
    let mut tree_addr = SpxAddr::new(); tree_addr.set_type(ADDR_HASHTREE);
    let mut wots_pk_addr = SpxAddr::new(); wots_pk_addr.set_type(ADDR_WOTSPK);
    let mut root = fors_pk_from_sig(&mut state, pub_seed, fors_sig, mhash, &fors_addr, &mut trace);

    let mut cur_tree = tree; let mut cur_idx = idx_leaf;
    for layer in 0..D {
        let layer_off = layer*(WOTS_BYTES + TREE_HEIGHT*N);
        let wots_sig = &ht_sig[layer_off..layer_off+WOTS_BYTES];
        let auth_path = &ht_sig[layer_off+WOTS_BYTES..layer_off+WOTS_BYTES+TREE_HEIGHT*N];
        tree_addr.set_layer(layer as u32); tree_addr.set_tree(cur_tree);
        wots_addr.copy_subtree(&tree_addr); wots_addr.set_keypair(cur_idx);
        wots_pk_addr.copy_keypair(&wots_addr);
        let wots_pk = wots_pk_from_sig(&mut state, pub_seed, wots_sig, &root, &wots_addr, &mut trace);
        let leaf_blocks: Vec<&[u8]> = (0..WOTS_LEN).map(|i| &wots_pk[i*N..(i+1)*N]).collect();
        let leaf = thash(&mut state, DOMAIN_THASH_TL, pub_seed, &wots_pk_addr, &leaf_blocks, N, &mut trace, CallType::WotsLeafHash);
        root = compute_root(&mut state, pub_seed, &leaf, cur_idx, 0, auth_path, TREE_HEIGHT as u32, &tree_addr, &mut trace);
        cur_idx = cur_tree as u32 & ((1u32<<TREE_HEIGHT)-1); cur_tree >>= TREE_HEIGHT;
    }
    // ── Encrypt: sigma_C_enc = Poseidon2(domain=0xFF, label || pk_e || com || sigma_com || omega2) ──
    let label = b"m20-pke-ct-v1";
    let mut enc_input = Vec::new();
    enc_input.push(DOMAIN_CUSTOM);
    enc_input.extend_from_slice(label);
    enc_input.extend_from_slice(pk_e);
    enc_input.extend_from_slice(&com_output);
    enc_input.extend_from_slice(sigma_com);
    enc_input.extend_from_slice(omega2);
    let addr_enc = SpxAddr::new();
    let _enc_output = poseidon2_hash(&mut state, &enc_input, N, &mut trace,
        CallType::Encrypt, DOMAIN_CUSTOM, &addr_enc);

    // Extract pk_root from the final HT root computation (2 BaseElements for N=16)
    let pk_root_l0 = BaseElement::new(u64::from_le_bytes(root[0..8].try_into().unwrap_or([0;8])));
    let pk_root_l1 = BaseElement::new(u64::from_le_bytes(root[8..16].try_into().unwrap_or([0;8])));
    // Extract com output (first 2 rate lanes = 16 bytes for N=16)
    let com_l0 = BaseElement::new(u64::from_le_bytes(com_output[0..8].try_into().unwrap_or([0;8])));
    let com_l1 = BaseElement::new(u64::from_le_bytes(com_output[8..16].try_into().unwrap_or([0;8])));
    let (trace_data, num_cols, total_perms) = trace.into_trace();
    (trace_data, num_cols, total_perms, pk_root_l0, pk_root_l1, com_l0, com_l1)
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn test_build_trace() {
        let pk = vec![0x42u8; PK_BYTES]; let m_pub = vec![0x27u8; N];
        let sigma_com = vec![0x00u8; SIG_BYTES];
        let (t, nc, tp, _, _, _, _) = build_verification_trace(&pk, &sigma_com, &m_pub, &[], &[], &[], &[]);
        assert!(t.len().is_power_of_two()); assert!(nc <= 255);
        eprintln!("Trace: {} rows × {} cols, {} perms", t.len(), nc, tp);
    }
}
