// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Ledger Service Internal Enclave Implementation
//!
//! This crate implements the inside-the-enclave version of the LedgerEnclave trait,
//! which would traditionally be inside the ledger_enclave crate. This, combined
//! with a form of dependency injection, would provide the machines with
//! all the unit testing they would ever need. Fate, it seems, has a sense
//! of irony...

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use fog_ledger_enclave_api::{KeyImageContext, LedgerEnclave, OutputContext, Result};
use fog_types::ledger::{
    CheckKeyImagesRequest, CheckKeyImagesResponse, GetOutputsRequest, GetOutputsResponse,
};
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
