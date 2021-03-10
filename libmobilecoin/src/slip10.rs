// Copyright 2018-2021 The MobileCoin Foundation

use crate::common::*;
use mc_util_ffi::*;

pub type McSlip10Indices = Vec<u32>;
impl_into_ffi!(Vec<u32>);

#[no_mangle]
pub extern "C" fn mc_slip10_indices_create() -> FfiOptOwnedPtr<McSlip10Indices> {
    ffi_boundary(Vec::new)
}

#[no_mangle]
pub extern "C" fn mc_slip10_indices_free(indices: FfiOptOwnedPtr<McSlip10Indices>) {
    ffi_boundary(|| {
        let _ = indices;
    })
}

#[no_mangle]
pub extern "C" fn mc_slip10_indices_add(indices: FfiMutPtr<McSlip10Indices>, index: u32) -> bool {
    ffi_boundary(|| {
        indices.into_mut().push(index);
    })
}

/// # Preconditions
///
/// * `out_key` - length must be >= 32.
#[no_mangle]
pub extern "C" fn mc_slip10_derive_ed25519_private_key(
    seed: FfiRefPtr<McBuffer>,
    path: FfiRefPtr<McSlip10Indices>,
    out_key: FfiMutPtr<McMutableBuffer>,
) -> bool {
    ffi_boundary(|| {
        let key = slip10_ed25519::derive_ed25519_private_key(&seed, &path);

        let out_key = out_key
            .into_mut()
            .as_slice_mut_of_len(key.len())
            .expect("out_key length is insufficient");

        out_key.copy_from_slice(&key);
    })
}
