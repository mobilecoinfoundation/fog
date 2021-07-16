// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger Service Internal Enclave Implementation
//!
//! This crate implements the inside-the-enclave version of the LedgerEnclave
//! trait, which would traditionally be inside the ledger_enclave crate. This,
//! combined with a form of dependency injection, would provide the machines
//! with all the unit testing they would ever need. Fate, it seems, has a sense
//! of irony...
#![no_std]
#![deny(missing_docs)]
extern crate alloc;

mod key_image_store;
use alloc::vec::Vec;
use fog_ledger_enclave_api::{
    messages::KeyImageData, Error, LedgerEnclave, OutputContext, Result,
    UntrustedKeyImageQueryResponse,
};
use fog_types::ledger::{GetOutputsRequest, GetOutputsResponse};
use key_image_store::{KeyImageStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_oblivious_traits::{HeapORAMStorageCreator, ORAMStorageCreator};
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};

/// In-enclave state associated to the ledger enclaves
pub struct SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// The encrypted storage
    keyimagestore: Mutex<Option<KeyImageStore<OSC>>>,

    /// The enclave state
    ake: AkeEnclaveState<NullIdentity>,

    /// Logger object
    logger: Logger,
}

/// Implementation of the sgx ledger enclave
impl<OSC> SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// Constructor function for the ledger enclave
    pub fn new(logger: Logger) -> Self {
        Self {
            keyimagestore: Mutex::new(None),
            ake: Default::default(),
            logger,
        }
    }
}

/// Implementation of the reportable enclave for sgxledger enclave
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

/// Implemenation for ledger encave for sgx ledger enclave
impl<OSC> LedgerEnclave for SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn enclave_init(&self, self_id: &ResponderId, desired_capacity: u64) -> Result<()> {
        self.ake.init(Default::default(), self_id.clone())?;
        let mut lk = self.keyimagestore.lock()?;

        SgxLedgerEnclave::<HeapORAMStorageCreator>::new(self.logger.clone());
        *lk = Some(KeyImageStore::new(desired_capacity, self.logger.clone()));
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

        let req: fog_types::ledger::CheckKeyImagesRequest = mc_util_serial::decode(&user_plaintext)
            .map_err(|e| {
                log::error!(self.logger, "Could not decode user request: {}", e);
                Error::ProstDecode
            })?;

        let mut resp = fog_types::ledger::CheckKeyImagesResponse {
            num_blocks: untrusted_keyimagequery_response.highest_processed_block_count,
            results: Default::default(),
            global_txo_count: untrusted_keyimagequery_response.last_known_block_cumulative_count, /* ledger.numtxtout */
        };

        // Do the scope lock of keyimagetore
        {
            let mut lk = self.keyimagestore.lock()?;
            let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;

            resp.results = req
                .queries
                .iter() // Attempt and deserialize the untrusted portion of this request.
                .map(|key| store.find_record(&key.key_image))
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
            store.add_record(&rec.key_image, rec.block_index, rec.timestamp)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fog_ledger_enclave_api::{messages::KeyImageData, AddRecordsError};
    use mc_common::logger::create_root_logger;
    use mc_transaction_core::ring_signature::KeyImage;
    // Test that we were able to add key image record to the oram
    #[test]
    fn test_add_record() {
        let desired_capacity: u64 = 1024 * 1024;
        let logger = create_root_logger();
        // create a new keyimagestore
        let mut keyimagestore = key_image_store::KeyImageStore::<
            mc_oblivious_traits::HeapORAMStorageCreator,
        >::new(desired_capacity, logger);

        //we should get back "invalid key" error
        let rec3 = KeyImageData {
            key_image: KeyImage::from(0),
            block_index: 14978249314436157236,
            timestamp: 14613610561491525175,
        };

        let v_result: core::result::Result<_, AddRecordsError> =
            key_image_store::KeyImageStore::add_record(
                &mut keyimagestore,
                rec3.key_image,
                rec3.block_index,
                rec3.timestamp,
            );

        assert!(v_result.is_err() && !v_result.is_ok());
    }
}
