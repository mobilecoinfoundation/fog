// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger Service Internal Enclave Implementation
//!
//! This crate implements the inside-the-enclave version of the LedgerEnclave
//! trait, which would traditionally be inside the ledger_enclave crate. This,
//! combined with a form of dependency injection, would provide the machines
//! with all the unit testing they would ever need. Fate, it seems, has a sense
//! of irony...

#![allow(unused)]
#![no_std]
extern crate alloc;

mod key_image_store;
use alloc::vec::Vec;
use fog_ledger_enclave_api::{
    messages::KeyImageData, AddRecordsError, Error, LedgerEnclave, OutputContext, Result,
    UntrustedKeyImageQueryResponse,
};
use fog_types::ledger::{
    CheckKeyImagesRequest, CheckKeyImagesResponse, GetOutputsRequest, GetOutputsResponse,
};
use key_image_store::{KeyImageStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::{
    logger::{create_root_logger, log, Logger},
    ResponderId,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_transaction_core::ring_signature::KeyImage;

/// In-enclave state associated to the ledger enclaves
pub struct SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// The encrypted storage
    keyimagestore: Mutex<Option<KeyImageStore<OSC>>>,

    ake: AkeEnclaveState<NullIdentity>,

    /// Logger object
    logger: Logger,
}

impl<OSC> ReportableEnclave for SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        Ok(self.ake.new_ereport(qe_info)?)
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        Ok(self.ake.verify_quote(quote, qe_report)?)
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        self.ake.verify_ias_report(ias_report)?;
        Ok(())
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        Ok(self.ake.get_ias_report()?)
    }
}

impl<OSC> LedgerEnclave for SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn new(&self, logger: Logger) -> Self {
        Self {
            keyimagestore: Mutex::new(None),
            ake: Default::default(),
            logger,
        }
    }

    fn enclave_init(&self, self_id: &ResponderId) -> Result<()> {
        self.ake.init(Default::default(), self_id.clone())?;
        Ok(())
    }

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        Ok(self.ake.client_accept(req)?)
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        Ok(self.ake.client_close(channel_id)?)
    }

    fn get_outputs(&self, msg: EnclaveMessage<ClientSession>) -> Result<OutputContext> {
        let request_bytes = self.ake.client_decrypt(msg)?;

        // Try and deserialize.
        let enclave_request: GetOutputsRequest = mc_util_serial::decode(&request_bytes)?;

        let output_context = OutputContext {
            indexes: enclave_request.indices,
            merkle_root_block: enclave_request.merkle_root_block,
        };

        Ok(output_context)
    }

    fn get_outputs_data(
        &self,
        response: GetOutputsResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>> {
        // Serialize this for the client.
        let response_bytes = mc_util_serial::encode(&response);

        // Encrypt for the client.
        Ok(self.ake.client_encrypt(&client, &[], &response_bytes)?)
    }

    fn check_key_images(
        &self,
        msg: EnclaveMessage<ClientSession>,
        untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>> {
        let channel_id = msg.channel_id.clone();
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let req: fog_types::ledger::QueryRequest = mc_util_serial::decode(&user_plaintext)
            .map_err(|e| {
                log::error!(self.logger, "Could not decode user request: {}", e);
                Error::ProstDecode
            })?;

        let mut resp = fog_types::ledger::QueryResponse {
            highest_processed_block_count: untrusted_keyimagequery_response
                .highest_processed_block_count,
            highest_processed_block_signature_timestamp: untrusted_keyimagequery_response
                .highest_processed_block_signature_timestamp,
            keyimage_search_results: Default::default(),
            last_known_block_count: untrusted_keyimagequery_response.last_known_block_count,
            last_known_block_cumulative_count: untrusted_keyimagequery_response
                .last_known_block_cumulative_count,
        };

        // Do the scope lock of keyimagetore
        {
            let mut lk = self.keyimagestore.lock()?;
            let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;

            resp.keyimage_search_results = req
                .get_keyimages
                .iter() // Attempt and deserialize the untrusted portion of this request.
                .map(|key| store.find_record(&key[..]))
                .collect();
        }

        let response_plaintext_bytes = mc_util_serial::encode(&resp);

        let response = self
            .ake
            .client_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response.data)
    }

    // Add a key image data to the oram sing the key image
    fn add_key_image_data(&self, records: Vec<KeyImageData>) -> Result<()> {
        let mut lk = self.keyimagestore.lock()?;
        let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        // add test KeyImageData record to ledger oram
        for rec in records {
            store.add_record(&rec.key_image, &rec.block_index, &rec.timestamp)?;
        }

        Ok(())
    }
}
