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
use fog_ledger_enclave_api::{Error, KeyImageContext, LedgerEnclave, OutputContext, Result};
use fog_types::ledger::{
    CheckKeyImagesRequest, CheckKeyImagesResponse, GetOutputsRequest, GetOutputsResponse,
};
use key_image_store::{KeyImageStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::ResponderId;
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};

/// In-enclave state associated to the ledger enclave
#[derive(Default)]
pub struct SgxLedgerEnclave {
    ake: AkeEnclaveState<NullIdentity>,
}

impl ReportableEnclave for SgxLedgerEnclave {
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

impl LedgerEnclave for SgxLedgerEnclave {
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

    fn check_key_images(&self, msg: EnclaveMessage<ClientSession>) -> Result<KeyImageContext> {
        let request_bytes = self.ake.client_decrypt(msg)?;

        // Try and deserialize.
        let enclave_request: CheckKeyImagesRequest = mc_util_serial::decode(&request_bytes)?;
        let mut key_images = Vec::new();
        for query in enclave_request.queries {
            key_images.push(query.key_image);
        }

        let context = KeyImageContext { key_images };

        Ok(context)
    }

    fn check_key_images_data(
        &self,
        response: CheckKeyImagesResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>> {
        // Serialize this for the client.
        let response_bytes = mc_util_serial::encode(&response);

        // Encrypt for the client.
        Ok(self.ake.client_encrypt(&client, &[], &response_bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::create_root_logger;
    use mc_transaction_core::ring_signature::KeyImage;
    // Test that we were able to add key image record to the oram
    #[test]
    fn test_add_record() {
        let mut desired_capacity: u64 = 1024 * 1024;
        let logger = create_root_logger();
        // create a new keyimagestore
        let mut keyimagestore = key_image_store::KeyImageStore::<
            mc_oblivious_traits::HeapORAMStorageCreator,
        >::new(desired_capacity, logger);

        // create test KeyImageData records to store sample block_index and timestamp
        let mut rec = key_image_store::KeyImageData {
            block_index: 0u64,
            timestamp: 0u64,
        };

        let mut rec2 = key_image_store::KeyImageData {
            block_index: 0u64,
            timestamp: 0u64,
        };

        let mut rec3 = key_image_store::KeyImageData {
            block_index: 0u64,
            timestamp: 0u64,
        };

        // create test record that will not be added to test if it will fail
        let mut not_found_rec = key_image_store::KeyImageData {
            block_index: 0u64,
            timestamp: 0u64,
        };

        let mut not_found_rec2 = key_image_store::KeyImageData {
            block_index: 0u64,
            timestamp: 0u64,
        };

        // records to be added to oram
        rec = key_image_store::KeyImageData {
            block_index: 15968249514437158236,
            timestamp: 14715610560481527175,
        };

        rec2 = key_image_store::KeyImageData {
            block_index: 15867249514237159136,
            timestamp: 14315610570481526166,
        };

        rec3 = key_image_store::KeyImageData {
            block_index: 14978249314436157236,
            timestamp: 14613610561491525175,
        };

        // record not added to oram
        not_found_rec = key_image_store::KeyImageData {
            block_index: 16967239515437158243,
            timestamp: 13714610510481517185,
        };

        let key_image = &KeyImage::from(2); // create key image

        // add test KeyImageData record to ledger oram
        key_image_store::KeyImageStore::add_record(&mut keyimagestore, key_image, rec);

        //create temp variables to store KeyImageData which we will use as key to query
        // ledger oram with find_record
        let v: (
            key_image_store::KeyImageData,
            fog_types::ledger::KeyImageResultCode,
        );

        let v2: (
            key_image_store::KeyImageData,
            fog_types::ledger::KeyImageResultCode,
        );

        let v3: (
            key_image_store::KeyImageData,
            fog_types::ledger::KeyImageResultCode,
        );

        let v4: (
            key_image_store::KeyImageData,
            fog_types::ledger::KeyImageResultCode,
        );

        //query the ledger oram for the record using the key_image
        v = key_image_store::KeyImageStore::find_record(&mut keyimagestore, key_image);

        let (var_keyimagedata, var_keyimageresultcode) = v; // save the result of query into the var_keyimagedata

        // this test should pass since we added this rec into the oram
        assert_eq!(rec.block_index, var_keyimagedata.block_index);
        assert_eq!(rec.timestamp, var_keyimagedata.timestamp);
        assert_eq!(var_keyimageresultcode,fog_types::ledger::KeyImageResultCode::NotSpent);

        // this test should pass since we did not add this rec into the oram
        assert_ne!(not_found_rec.block_index, var_keyimagedata.block_index);
        assert_ne!(not_found_rec.timestamp, var_keyimagedata.timestamp);

        let key_image2 = &KeyImage::from(2); // create key image

         // add test KeyImageData record to ledger oram
         key_image_store::KeyImageStore::add_record(&mut keyimagestore, key_image2, rec2);

         let key_image3 = &KeyImage::from(2); // create key image
         // add test KeyImageData record to ledger oram
        key_image_store::KeyImageStore::add_record(&mut keyimagestore, key_image3, rec3);

           //query the ledger oram for the record using the key_image
        v2 = key_image_store::KeyImageStore::find_record(&mut keyimagestore, key_image2);

        let (var_keyimagedata2, var_keyimageresultcode2) = v2; // save the result of query into the var_keyimagedata

             //query the ledger oram for the record using the key_image
        v3 = key_image_store::KeyImageStore::find_record(&mut keyimagestore, key_image3);

        let (var_keyimagedata3, var_keyimageresultcode3) = v3; // save the result of query into the var_keyimagedata

           // this test should pass since we added this rec into the oram
        assert_eq!(rec2.block_index, var_keyimagedata2.block_index);
        assert_eq!(rec2.timestamp, var_keyimagedata2.timestamp);
        assert_eq!(var_keyimageresultcode2,fog_types::ledger::KeyImageResultCode::NotSpent);

        // this test should pass since we did not add this rec into the oram
        assert_ne!(not_found_rec.block_index, var_keyimagedata2.block_index);
        assert_ne!(not_found_rec.timestamp, var_keyimagedata2.timestamp);

           // this test should pass since we added this rec into the oram
        assert_eq!(rec3.block_index, var_keyimagedata3.block_index);
        assert_eq!(rec3.timestamp, var_keyimagedata3.timestamp);
        assert_eq!(var_keyimageresultcode3,fog_types::ledger::KeyImageResultCode::NotSpent);

        // this test should pass since we did not add this rec into the oram
        assert_ne!(not_found_rec.block_index, var_keyimagedata3.block_index);
        assert_ne!(not_found_rec.timestamp, var_keyimagedata3.timestamp);

        let key_image4 = &KeyImage::from(2); // create key image that is not added to oram

            //query the ledger oram for the record using the key_image not added to oram
        v4 = key_image_store::KeyImageStore::find_record(&mut keyimagestore, key_image4);

        let (var_keyimagedata4, var_keyimageresultcode4) = v4; // save the result of query into the var_keyimagedata

        assert_eq!(var_keyimageresultcode4,fog_types::ledger::KeyImageResultCode::KeyImageError);
    }
}
