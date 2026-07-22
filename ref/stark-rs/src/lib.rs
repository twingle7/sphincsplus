#![allow(clippy::missing_safety_doc)]

pub mod air_engine;
pub mod thash_bench;
pub mod thash_poseidon2_exact;
pub mod thash_sha2_exact;
pub mod thash_sha2_f_exact;
pub mod trace_builder;

// ── FFI ABI types (shared with C via ffi.h) ──

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

// ── Shared error codes ──

pub const SPX_P2_RUST_OK: i32 = 0;
pub const SPX_P2_RUST_ERR_NULL: i32 = -1;
pub const SPX_P2_RUST_ERR_INPUT: i32 = -2;
pub const SPX_P2_RUST_ERR_BUFFER_SMALL: i32 = -3;
pub const SPX_P2_RUST_ERR_PROVE: i32 = -4;
pub const SPX_P2_RUST_ERR_VERIFY: i32 = -5;
pub const SPX_P2_RUST_ERR_FORMAT: i32 = -6;
