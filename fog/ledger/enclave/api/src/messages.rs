// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The message types used by the ledger_enclave_api.

use fog_types::ledger::{CheckKeyImagesResponse, GetOutputsResponse};
use mc_attest_core::{Quote, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientSession, EnclaveMessage};
use mc_common::ResponderId;
use serde::{Deserialize, Serialize};

/// An enumeration of API calls and their arguments for use across serialization boundaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EnclaveCall {
    /// The [LedgerEnclave::enclave_init()] method.
    EnclaveInit(ResponderId),

    /// The [LedgerEnclave::client_accept()] method.
    ///
    /// Process a new inbound client connection.
    ClientAccept(ClientAuthRequest),

    /// The [LedgerEnclave::client_close()] method.
    ///
    /// Tears down any in-enclave state about a client association.
    ClientClose(ClientSession),

    /// The [LedgerEnclave::get_identity()] method.
    ///
    /// Retrieves the public identity (X25519 public key) of an enclave.
    GetIdentity,

    /// The [LedgerEnclave::new_ereport()] method.
    ///
    /// Creates a new report for the enclave with the provided target info.
    NewEreport(TargetInfo),

    /// The [LedgerEnclave::verify_quote()] method.
    ///
    /// * Verifies that the Quoting Enclave is sane,
    /// * Verifies that the Quote matches the previously generated report.
    /// * Caches the quote.
    VerifyQuote(Quote, Report),

    /// The [LedgerEnclave::verify_ias_report()] method.
    ///
    /// * Verifies the signed report from IAS matches the previously received quote,
    /// * Caches the signed report. This cached report may be overwritten by later calls.
    VerifyReport(VerificationReport),

    /// The [LedgerEnclave::get_ias_report()] method.
    ///
    /// Retrieves a previously cached report, if any.
    GetReport,

    /// The [LedgerEnclave::get_outputs()] method.
    ///
    /// Start a new request for outputs and membership proofs from a client.
    GetOutputs(EnclaveMessage<ClientSession>),

    /// The [LedgerEnclave::get_outputs_data()] method.
    ///
    /// Re-encrypt the given outputs and proofs for transmission to a client.
    GetOutputsData(GetOutputsResponse, ClientSession),

    /// The [LedgerEnclave::client_check_key_images()] method.
    ///
    /// Start a new key image check from a client.
    CheckKeyImages(EnclaveMessage<ClientSession>),

    /// The [LedgerEnclave::key_image_checks_for_client()] method.
    ///
    /// Encrypt the key image check results for transmission to a client.
    CheckKeyImagesData(CheckKeyImagesResponse, ClientSession),
}
