// Copyright 2018-2021 The MobileCoin Foundation

use crate::common::*;
use bip39::{Language, Mnemonic};
use mc_util_ffi::*;

/// # Preconditions
///
/// * `entropy` - length must be a multiple of 4 and between 16 and 32,
///   inclusive, in bytes.
#[no_mangle]
pub extern "C" fn mc_bip39_mnemonic_from_entropy(entropy: FfiRefPtr<McBuffer>) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
            .expect("entropy could not be converted to a mnemonic");
        FfiOwnedStr::ffi_try_from(mnemonic.to_string())
            .expect("mnemonic could not be converted to a C string")
    })
}

/// # Preconditions
///
/// * `prefix` - must be a nul-terminated C string containing valid UTF-8.
#[no_mangle]
pub extern "C" fn mc_bip39_words_by_prefix(prefix: FfiStr) -> FfiOptOwnedStr {
    ffi_boundary(|| {
        let prefix = String::try_from_ffi(prefix).expect("prefix is invalid");
        let words = Language::English.wordlist().get_words_by_prefix(&prefix);
        let joined_words = words.join(",");
        FfiOwnedStr::ffi_try_from(joined_words)
            .expect("joined_words could not be converted to a C string")
    })
}
