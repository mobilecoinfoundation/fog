// Copyright 2018-2021 The MobileCoin Foundation

use crate::{common::*, LibMcError};
use bip39::{Language, Mnemonic};
use mc_util_ffi::*;

/// # Preconditions
///
/// * `mnemonic` - must be a nul-terminated C string containing valid UTF-8.
/// * `out_entropy` - length must be >= 32.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_bip39_entropy_from_mnemonic(
    mnemonic: FfiStr,
    out_entropy: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let mnemonic = String::try_from_ffi(mnemonic).expect("mnemonic is invalid");

        let mnemonic = Mnemonic::parse(mnemonic)
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid mnemonic: {}", err)))?;
        let entropy = mnemonic.to_entropy();

        let out_entropy = out_entropy
            .into_mut()
            .as_slice_mut_of_len(entropy.len())
            .expect("out_entropy length is insufficient");

        out_entropy.copy_from_slice(&entropy);

        Ok(())
    })
}

/// # Preconditions
///
/// * `entropy` - length must be 32.
#[no_mangle]
pub extern "C" fn mc_bip39_entropy_to_mnemonic(entropy: FfiRefPtr<McBuffer>) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let mnemonic =
            Mnemonic::from_entropy(&entropy).expect("entropy could not be converted to a mnemonic");
        FfiOwnedStr::ffi_try_from(mnemonic.to_string())
            .expect("mnemonic could not be converted to a C string")
    })
}

/// # Preconditions
///
/// * `mnemonic` - must be a nul-terminated C string containing valid UTF-8.
/// * `passphrase` - must be a nul-terminated C string containing valid UTF-8. Can be empty.
/// * `out_seed` - length must be >= 64.
///
/// # Errors
///
/// * `LibMcError::InvalidInput`
#[no_mangle]
pub extern "C" fn mc_bip39_get_seed(
    mnemonic: FfiStr,
    passphrase: FfiStr,
    out_seed: FfiMutPtr<McMutableBuffer>,
    out_error: FfiOptMutPtr<FfiOptOwnedPtr<McError>>,
) -> bool {
    ffi_boundary_with_error(out_error, || {
        let mnemonic = String::try_from_ffi(mnemonic).expect("mnemonic is invalid");
        let passphrase = String::try_from_ffi(passphrase).expect("passphrase is invalid");

        let mnemonic = Mnemonic::parse(mnemonic)
            .map_err(|err| LibMcError::InvalidInput(format!("Invalid mnemonic: {}", err)))?;
        let seed = mnemonic.to_seed(&passphrase);

        let out_seed = out_seed
            .into_mut()
            .as_slice_mut_of_len(seed.len())
            .expect("out_seed length is insufficient");

        out_seed.copy_from_slice(&seed);

        Ok(())
    })
}

/// # Preconditions
///
/// * `prefix` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_bip39_words_by_prefix(prefix: FfiStr) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let prefix = String::try_from_ffi(prefix).expect("prefix is invalid");
        let words = Language::English.words_by_prefix(&prefix);
        let joined_words = words.join(",");
        FfiOwnedStr::ffi_try_from(joined_words)
            .expect("joined_words could not be converted to a C string")
    })
}
