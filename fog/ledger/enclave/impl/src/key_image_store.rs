// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object representing trusted storage for key image records.
//! Mediates between the bytes used in ORAM and the protobuf format,
//! the various ORAM vs. fog api error codes, etc.

// These are the requirements on the storage, this is imposed by the choice of
// oram algorithm
#![allow(unused)]
use aligned_cmov::{
    typenum::{U32, U16, U4096, U64, U1024},
};


use alloc::boxed::Box;
use mc_crypto_rand::McRng;
use mc_oblivious_map::CuckooHashTableCreator;
use mc_oblivious_ram::PathORAM4096Z4Creator;

// internal constants
// KeySize and ValueSize reflect the needs of key_image_store
// We must choose an oblivious map algorithm that can support that

type KeySize = U32;
type ValueSize = U16;
// BlockSize is a tuning parameter for OMap which must become the ValueSize of
// the selected ORAM
type BlockSize = U1024;

// This selects an oblivious ram algorithm which can support queries of size
// BlockSize The ORAMStorageCreator type is a generic parameter to KeyImageStore
type ObliviousRAMAlgo<OSC> = PathORAM4096Z4Creator<McRng, OSC>;

pub type StorageDataSize = U4096;
pub type StorageMetaSize = U64;

use mc_oblivious_traits::{
    OMapCreator,ORAMStorageCreator
};

// This selects the oblivious map algorithm
type ObliviousMapCreator<OSC> = CuckooHashTableCreator<BlockSize, McRng, ObliviousRAMAlgo<OSC>>;

/// Object which holds ORAM and services KeyImageRecord requests
///
/// This object handles translations between protobuf types, and the aligned
/// chunks of bytes Key and Value used in the oblivious map interface.
///
/// - The size in the OMAP is ValueSize which must be divisible by 8,
/// - The user actually gives us a serialized protobuf
/// - We use a wire format in the omap where value[0] = ValueSize - 1 -
///   ciphertext.len(), ValueSize must be within 255 bytes of ciphertext.len().
/// - When the lookup misses, we try to obliviously return a buffer of the
///   normal size. We do this by remembering the ciphertext size byte of the
///   last stored ciphertext.

pub struct KeyImageStore<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> {

    
    omap: Box<<ObliviousMapCreator<OSC> as OMapCreator<KeySize, ValueSize, McRng>>::Output>,
  
    
}

impl<OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>> KeyImageStore<OSC> {


}














   

