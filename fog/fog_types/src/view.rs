// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::common::BlockRange;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use displaydoc::Display;
use mc_crypto_keys::{CompressedRistrettoPublic, KeyError};
use mc_transaction_core::{
    encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
    tx::TxOut,
    Amount, CompressedCommitment,
};
use prost::Message;
use serde::{Deserialize, Serialize};

pub use fog_kex_rng::KexRngPubkey;

// User <-> enclave proto schema types
// These are synced with types in fog_api view.proto, and tests enforce that they round trip
// These are NOT expected to be synced with Db schema types

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryRequestAAD {
    #[prost(int64, tag = "1")]
    pub start_from_user_event_id: i64,

    /// The first block index to search TXOs in.
    // TODO this is currently unused
    #[prost(uint64, tag = "2")]
    pub start_from_block_index: u64,
}

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryRequest {
    #[prost(bytes, repeated, tag = "1")]
    pub get_txos: Vec<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryResponse {
    #[prost(uint64, tag = "1")]
    pub highest_processed_block_count: u64,

    #[prost(uint64, tag = "2")]
    pub highest_processed_block_signature_timestamp: u64,

    #[prost(int64, tag = "3")]
    pub next_start_from_user_event_id: i64,

    #[prost(message, repeated, tag = "4")]
    pub missed_block_ranges: Vec<BlockRange>,

    #[prost(message, repeated, tag = "5")]
    pub rng_records: Vec<RngRecord>,

    #[prost(message, repeated, tag = "6")]
    pub decommissioned_ingest_invocations: Vec<DecommissionedIngestInvocation>,

    #[prost(message, repeated, tag = "7")]
    pub tx_out_search_results: Vec<TxOutSearchResult>,

    #[prost(uint64, tag = "8")]
    pub last_known_block_count: u64,

    #[prost(uint64, tag = "9")]
    pub last_known_block_cumulative_txo_count: u64,
}

/// A record that can be used by the user to produce an Rng shared with fog ingest
#[derive(Clone, Eq, PartialEq, Hash, Message, Serialize, Deserialize)]
pub struct RngRecord {
    /// The ingest invocation id that produced this record.
    #[prost(int64, tag = "1")]
    pub ingest_invocation_id: i64,

    /// A key-exchange message to be used by the client to create a VersionedKexRng
    #[prost(message, required, tag = "2")]
    pub pubkey: KexRngPubkey,

    /// The start block (when fog started using this rng)
    #[prost(uint64, tag = "3")]
    pub start_block: u64,
}

/// Information about a decommissioned ingest invocation.
#[derive(Clone, Eq, PartialEq, Hash, Message, Serialize, Deserialize)]
pub struct DecommissionedIngestInvocation {
    #[prost(int64, tag = "1")]
    pub ingest_invocation_id: i64,

    #[prost(uint64, tag = "2")]
    pub last_ingested_block: u64,
}

/// An enum representing the possible outcomes of a TxOut search
/// 0 is not an option here because we want this to go in the protobuf as fixed32,
/// but in proto3, the default value for fixed32 is 0 and cannot be changed.
/// Default values are omitted in the on-the-wire representation,
/// which would make the ciphertext length
/// reveal something about the result code, which we don't want.
/// Particularly, the Found and NotFound scenarios must be indistinguishable.
///
/// If any values are added they must be synced with the enum in view.proto
#[derive(PartialEq, Eq, Debug, Display)]
#[repr(u32)]
pub enum TxOutSearchResultCode {
    /// The tx was found and the ciphertext is valid
    Found = 1,
    /// The tx was not found and the ciphertext is just padding
    NotFound,
    /// The search key was bad (wrong size)
    BadSearchKey,
    /// The server had an internal error that prevented this lookup
    InternalError,
    /// The server decided not to service this query to satisfy a rate limit
    RateLimited,
}

impl TryFrom<u32> for TxOutSearchResultCode {
    type Error = ();
    fn try_from(src: u32) -> Result<Self, ()> {
        if src == Self::Found as u32 {
            Ok(Self::Found)
        } else if src == Self::NotFound as u32 {
            Ok(Self::NotFound)
        } else if src == Self::BadSearchKey as u32 {
            Ok(Self::BadSearchKey)
        } else if src == Self::InternalError as u32 {
            Ok(Self::InternalError)
        } else if src == Self::RateLimited as u32 {
            Ok(Self::RateLimited)
        } else {
            Err(())
        }
    }
}

/// A struct representing the result of a fog view Txo query
#[derive(Clone, Eq, Hash, PartialEq, Message, Serialize, Deserialize)]
pub struct TxOutSearchResult {
    /// The search key that yielded this result
    #[prost(bytes, tag = "1")]
    pub search_key: Vec<u8>,
    /// This is a TxOutSearchResultCode
    #[prost(fixed32, tag = "2")]
    pub result_code: u32,
    /// The ciphertext payload
    #[prost(bytes, tag = "3")]
    pub ciphertext: Vec<u8>,
}

// TxOutRecord is what information the fog service preserves for a user about their TxOut.
// These are created by the ingest server and then encrypted. The encrypted blobs
// are eventually returned to the user, who must deserialize them.
//
// Note: There are conformance tests in fog_api that check that this matches proto
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct TxOutRecord {
    /// The (compressed ristretto) bytes of commitment associated to amount field in the TxOut that was recovered
    #[prost(bytes, required, tag = "1")]
    pub tx_out_amount_commitment_data: Vec<u8>,
    /// The masked value associated to amount field in the TxOut that was recovered
    #[prost(fixed64, required, tag = "2")]
    pub tx_out_amount_masked_value: u64,
    /// The (compressed ristretto) bytes of the target key associated to the TxOut that was recovered
    #[prost(bytes, required, tag = "3")]
    pub tx_out_target_key_data: Vec<u8>,
    /// The (compressed ristretto) bytes of the public key associated to the TxOut that was recovered
    #[prost(bytes, required, tag = "4")]
    pub tx_out_public_key_data: Vec<u8>,
    /// Global index within the set of all TxOuts
    #[prost(fixed64, required, tag = "5")]
    pub tx_out_global_index: u64,

    /// Index of block at which this TxOut appeared
    #[prost(fixed64, required, tag = "6")]
    pub block_index: u64,

    /// Timestamp of block at which this TxOut appeared
    /// Note: The timestamps are based on untrusted reporting of time from the consensus validators.
    /// Represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    #[prost(fixed64, tag = "7")]
    pub timestamp: u64,
}

impl TxOutRecord {
    /// Helper to extract a FogTxOut object from the (flattened) TxOutRecord object
    pub fn get_fog_tx_out(&self) -> Result<FogTxOut, KeyError> {
        // CompressedCommitment does not implement TryFrom, so we have to do the logic here
        if self.tx_out_amount_commitment_data.len() != 32 {
            return Err(KeyError::LengthMismatch(
                32,
                self.tx_out_amount_commitment_data.len(),
            ));
        }
        let commitment_bytes: &[u8; 32] =
            &self.tx_out_amount_commitment_data[..].try_into().unwrap();
        Ok(FogTxOut {
            amount: Amount {
                commitment: CompressedCommitment::from(commitment_bytes),
                masked_value: self.tx_out_amount_masked_value,
            },
            target_key: CompressedRistrettoPublic::try_from(&self.tx_out_target_key_data[..])?,
            public_key: CompressedRistrettoPublic::try_from(&self.tx_out_public_key_data[..])?,
        })
    }
}

// FogTxOut is a redacted version of the TxOut, removing the fog hint.
// The hint is only used during ingest, so we don't need to persist it.
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct FogTxOut {
    /// The amount being sent.
    #[prost(message, required, tag = "1")]
    pub amount: Amount,

    /// The one-time public address of this output.
    #[prost(message, required, tag = "2")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[prost(message, required, tag = "3")]
    pub public_key: CompressedRistrettoPublic,
}

impl core::convert::From<&TxOut> for FogTxOut {
    #[inline]
    fn from(src: &TxOut) -> Self {
        Self {
            amount: src.amount.clone(),
            target_key: src.target_key,
            public_key: src.public_key,
        }
    }
}

impl core::convert::From<&FogTxOut> for TxOut {
    #[inline]
    fn from(src: &FogTxOut) -> Self {
        Self {
            amount: src.amount.clone(),
            target_key: src.target_key,
            public_key: src.public_key,
            e_fog_hint: EncryptedFogHint::from(&[0u8; ENCRYPTED_FOG_HINT_LEN]),
        }
    }
}
