// Copyright (c) 2018-2021 The MobileCoin Foundation

use aes_gcm::Aes256Gcm;
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_attest_ake::{AuthResponseInput, ClientInitiate, Ready, Start, Transition};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_core::{VerificationReport, Verifier};
use mc_common::{
    logger::{log, Logger},
    trace_time,
};
use mc_connection::{AttestedConnection, Connection};
use mc_crypto_keys::X25519;
use mc_crypto_rand::McRng;
use mc_util_grpc::BasicCredentials;
use mc_util_uri::ConnectionUri;
use sha2::Sha512;

mod error;
pub use error::Error;

/// Abstracts the auth and enclave_request aspects of a grpc channel
/// Note that this need not be a simple grpc channel, it could be a mock,
/// or it could be something like a bidirectional streaming channel.
pub trait EnclaveGrpcChannel: Send + Sync {
    fn auth(
        &mut self,
        msg: &AuthMessage,
        creds: &BasicCredentials,
    ) -> Result<AuthMessage, grpcio::Error>;
    fn enclave_request(
        &mut self,
        ciphertext: &Message,
        creds: &BasicCredentials,
    ) -> Result<Message, grpcio::Error>;
}

/// A generic object representing an attested connection to a remote enclave
pub struct EnclaveConnection<U: ConnectionUri, G: EnclaveGrpcChannel> {
    /// The URI we are connecting to, and which provides the ResponderId
    uri: U,
    /// Abstraction of one or more grpc connections
    grpc: G,
    /// The AKE state machine object, if one is available.
    attest_cipher: Option<Ready<Aes256Gcm>>,
    /// An object which can verify a fog node's provided IAS report
    verifier: Verifier,
    /// Credentials to use for all GRPC calls (this allows authentication
    /// username/password to go through, if provided).
    creds: BasicCredentials,
    /// Logger
    logger: Logger,
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Connection for EnclaveConnection<U, G> {
    type Uri = U;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> AttestedConnection for EnclaveConnection<U, G> {
    type Error = Error;

    fn is_attested(&self) -> bool {
        self.attest_cipher.is_some()
    }

    fn attest(&mut self) -> Result<VerificationReport, Self::Error> {
        trace_time!(self.logger, "FogClient::attest");
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        let auth_response_msg = self.grpc.auth(&auth_request_output.into(), &self.creds)?;

        let auth_response_event =
            AuthResponseInput::new(auth_response_msg.into(), self.verifier.clone());
        let (initiator, verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.attest_cipher = Some(initiator);

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(self.logger, "Tearing down existing attested connection.");
            self.attest_cipher = None;
        }
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> EnclaveConnection<U, G> {
    pub fn new(uri: U, grpc: G, verifier: Verifier, logger: Logger) -> Self {
        let creds = BasicCredentials::new(&uri.username(), &uri.password());

        Self {
            uri,
            grpc,
            attest_cipher: None,
            verifier,
            creds,
            logger,
        }
    }

    pub fn encrypted_enclave_request<
        RequestMessage: mc_util_serial::Message,
        ResponseMessage: mc_util_serial::Message + Default,
    >(
        &mut self,
        plaintext_request: &RequestMessage,
        aad: &[u8],
    ) -> Result<ResponseMessage, Error> {
        if !self.is_attested() {
            let _verification_report = self.attest()?;
        }

        // Build encrypted request, scope attest_cipher borrow
        let msg = {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let mut msg = Message::new();
            msg.set_channel_id(Vec::from(attest_cipher.binding()));
            msg.set_aad(aad.to_vec());

            let plaintext_bytes = mc_util_serial::encode(plaintext_request);

            let request_ciphertext = attest_cipher.encrypt(aad, &plaintext_bytes)?;
            msg.set_data(request_ciphertext);
            msg
        };

        let resp = self.attested_call(|this| this.grpc.enclave_request(&msg, &this.creds))?;

        // Decrypt request, scope attest_cipher borrow
        {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes = attest_cipher.decrypt(&resp.get_aad(), resp.get_data())?;
            let plaintext_response: ResponseMessage = mc_util_serial::decode(&plaintext_bytes)?;
            Ok(plaintext_response)
        }
    }
}

// boilerplate

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Display for EnclaveConnection<U, G> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Eq for EnclaveConnection<U, G> {}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Hash for EnclaveConnection<U, G> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> PartialEq for EnclaveConnection<U, G> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> Ord for EnclaveConnection<U, G> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<U: ConnectionUri, G: EnclaveGrpcChannel> PartialOrd for EnclaveConnection<U, G> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}
