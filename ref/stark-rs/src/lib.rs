#![allow(clippy::missing_safety_doc)]

pub const SPX_P2_STARK_RUST_ABI_VERSION_V1: u32 = 1;

pub const SPX_P2_RUST_OK: i32 = 0;
pub const SPX_P2_RUST_ERR_NULL: i32 = -1;
pub const SPX_P2_RUST_ERR_NOT_IMPLEMENTED: i32 = -100;

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
    _out_proof: *mut SpxP2FfiBlobV1,
    _pub: *const SpxP2FfiPublicInputsV1,
    _wit: *const SpxP2FfiPrivateWitnessV1,
) -> i32 {
    SPX_P2_RUST_ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub unsafe extern "C" fn spx_p2_rust_verify_pi_f_v1(
    _proof: *const SpxP2FfiBlobV1,
    _pub: *const SpxP2FfiPublicInputsV1,
) -> i32 {
    SPX_P2_RUST_ERR_NOT_IMPLEMENTED
}
