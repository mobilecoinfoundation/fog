// Copyright (c) 2018-2021 The MobileCoin Foundation

//! APIs for MobileCoin Ledger Service Enclaves

#![no_std]
#![feature(allocator_api)]

extern crate alloc;

mod error;
pub mod messages;

pub use crate::{
    error::{AddRecordsError, Error},
    messages::EnclaveCall,
};

use alloc::vec::Vec;
use core::{hash::Hash, result::Result as StdResult};
pub use fog_types::ledger::{
    CheckKeyImagesResponse, GetOutputsResponse, KeyImageResult, KeyImageResultCode, OutputResult,
};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::ResponderId;
use mc_crypto_keys::X25519Public;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_transaction_core::ring_signature::KeyImage;
use messages::KeyImageData;
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

/// An intermediate struct for holding data required to check key images for the
/// client. This is returned by `client_check_key_images` and allows untrusted
/// to gather data that will be encrypted for the client in
/// `outputs_for_client`.
///
/// Eventually we will do the key image check in ORAM, but for now untrusted
/// will do the check directly.
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyImageContext {
    pub key_images: Vec<KeyImage>,
    pub key_images_data: Vec<KeyImageData>,
}

/// The API for interacting with a ledger node's enclave.
pub trait LedgerEnclave: ReportableEnclave {
    // UTILITY METHODS

    /// Perform one-time initialization upon enclave startup.
    fn enclave_init(&self, self_id: &ResponderId) -> Result<()>;

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
    fn check_key_images(&self, msg: EnclaveMessage<ClientSession>) -> Result<KeyImageContext>;

    /// Encrypt key image check results for the given client session, using the
    /// given authenticated data for the client.
    fn encrypt_key_images_data(
        &self,
        response: CheckKeyImagesResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>>;

    // Add a key image data to the oram sing the key image
    fn add_key_image_data(&self, key_image: &KeyImage, data: KeyImageData) -> Result<()>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait LedgerEnclaveProxy: LedgerEnclave + Clone + Send + Sync + 'static {}

impl<T> LedgerEnclaveProxy for T where T: LedgerEnclave + Clone + Send + Sync + 'static {}
