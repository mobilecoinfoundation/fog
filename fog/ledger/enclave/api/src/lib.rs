// Copyright (c) 2018-2021 The MobileCoin Foundation

//! APIs for MobileCoin Ledger Service Enclave

#![no_std]

extern crate alloc;

mod error;
pub mod messages;
use crate::messages::KeyImageData;
pub use crate::{
    error::{AddRecordsError, Error},
    messages::EnclaveCall,
};
use alloc::vec::Vec;
use core::result::Result as StdResult;
pub use fog_types::ledger::{
    CheckKeyImagesResponse, GetOutputsResponse, KeyImageResult, KeyImageResultCode, OutputResult,
};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::ResponderId;
use mc_crypto_keys::X25519Public;
use mc_sgx_report_cache_api::ReportableEnclave;
use serde::{Deserialize, Serialize};

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An intermediate struct for holding data required to get outputs for the
/// client. This is returned by `client_get_outputs` and allows untrusted to
/// gather data that will be encrypted for the client in `outputs_for_client`.
///
/// Eventually we will do the key image check in ORAM, but for now untrusted
/// will do the check directly.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OutputContext {
    pub indexes: Vec<u64>,
    pub merkle_root_block: u64,
}

/// We will do the key image check in ORAM, but for now untrusted
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UntrustedKeyImageQueryResponse {
    /// The number of blocks at the time that the request was evaluated.
    pub highest_processed_block_count: u64,

    /// The timestamp of the highest processed block at the time that the
    /// request was evaluated.
    pub highest_processed_block_signature_timestamp: u64,

    /// The index of the last known block, which can be obtained by calculating
    /// last_known_block_count - 1. We don't store the index but instead store a
    /// count so that we have a way of representing no known block (0).
    pub last_known_block_count: u64,

    /// The cumulative txo count of the last known block.
    pub last_known_block_cumulative_count: u64,
}

/// The API for interacting with a ledger node's enclave.
pub trait LedgerEnclave: ReportableEnclave {
    // UTILITY METHODS
    /// Perform one-time initialization upon enclave startup.
    fn enclave_init(&self, self_id: &ResponderId, desired_capacity: u64) -> Result<()>;

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    // CLIENT-FACING METHODS

    /// Accept an inbound authentication request
    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)>;

    /// Destroy a peer association
    fn client_close(&self, channel_id: ClientSession) -> Result<()>;

    /// Extract context data to be handed back to untrusted so that it could
    /// collect the information required.
    fn get_outputs(&self, msg: EnclaveMessage<ClientSession>) -> Result<OutputContext>;

    /// Encrypt outputs and proofs for the given client session, using the given
    /// authenticated data for the client.
    fn get_outputs_data(
        &self,
        response: GetOutputsResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>>;

    /// Extract context data to be handed back to untrusted so that it could
    /// collect the information required.
    fn check_key_images(
        &self,
        msg: EnclaveMessage<ClientSession>,
        untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>>;

    // Add a key image data to the oram Using thrm -rf targete key image
    fn add_key_image_data(&self, records: Vec<KeyImageData>) -> Result<()>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait LedgerEnclaveProxy: LedgerEnclave + Clone + Send + Sync + 'static {}

impl<T> LedgerEnclaveProxy for T where T: LedgerEnclave + Clone + Send + Sync + 'static {}
