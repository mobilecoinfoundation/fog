// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A CLI tool that resolves FogPubkey requests
//!
//! This is used so that python can get the fog pubkey bytes as a hex string,
//! and then use them in the fog conformance test to create fog TxOuts.
//!
//! At time of writing, it takes the public address of a user (.pub keyfile),
//! since the FogPubkeyResolver API fully validates the fog report and the user's
//! signature over the cert chain.
//! In the future if needed we could make this take only the fog report url
//! and report id, and not fully validate the pubkey, but that would require
//! code changes in the GrpcFogPubkeyResolver object. It might make this a more
//! useful diagnostic tool.

use binascii::bin2hex;
use grpcio::EnvBuilder;
use mc_account_keys::PublicAddress;
use mc_attest_core::{Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_root_logger, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_report_connection::{Error, GrpcFogReportConnection};
use mc_fog_report_validation::{
    FogPubkeyResolver, FogReportResponses, FogResolver, FullyValidatedFogPubkey,
};
use mc_util_uri::FogUri;
use std::{
    path::PathBuf,
    process::exit,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;

/// The command-line arguments
#[derive(Debug, StructOpt)]
struct Config {
    /// Path to mobilecoin public address
    #[structopt(long = "public-address", short = "p")]
    pub public_address: PathBuf,

    /// How long to retry if NoReports, this is useful for tests
    #[structopt(long = "retry-seconds", short = "r", default_value = "10")]
    pub retry_seconds: u64,
}

/// Get fog response with retries, retrying if NoReports error occurs
fn get_fog_response_with_retries(
    fog_uri: FogUri,
    retry_duration: Duration,
    logger: Logger,
) -> FogReportResponses {
    // Create the grpc object and report verifier
    let grpc_env = Arc::new(EnvBuilder::new().name_prefix("cli").build());

    let conn = GrpcFogReportConnection::new(grpc_env, logger);

    let deadline = Instant::now() + retry_duration;
    loop {
        match conn.fetch_fog_reports(core::slice::from_ref(&fog_uri).iter().cloned()) {
            Ok(result) => {
                return result;
            }
            Err(Error::NoReports(_)) => {
                std::thread::sleep(Duration::from_millis(500));
                if Instant::now() > deadline {
                    eprintln!("No reports after {:?} time retrying", retry_duration);
                    exit(1)
                }
            }
            Err(err) => {
                eprintln!("Could not get fog response ({}): {}", fog_uri, err);
                exit(1);
            }
        }
    }
}

/// Try to resolve a public address to a fog public key
fn get_pubkey(responses: FogReportResponses, pub_addr: PublicAddress) -> FullyValidatedFogPubkey {
    let report_verifier = {
        let mr_signer_verifier = fog_ingest_enclave_measurement::get_mr_signer_verifier(None);

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    };

    let resolver = FogResolver::new(responses, &report_verifier);
    resolver
        .get_fog_pubkey(&pub_addr)
        .expect("Could not validate fog pubkey")
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::from_args();
    let logger = create_root_logger();

    // Read user public keys from disk
    let pub_addr = mc_util_keyfile::read_pubfile(config.public_address)
        .expect("Could not read public address file");

    // Get fog url
    let fog_uri = FogUri::from_str(
        pub_addr
            .fog_report_url()
            .expect("public address had no fog url"),
    )
    .expect("Could not parse fog report url as a valid fog url");

    // Try to make request
    let responses =
        get_fog_response_with_retries(fog_uri, Duration::from_secs(config.retry_seconds), logger);

    // Try to validate response
    let result = get_pubkey(responses, pub_addr);

    let mut hex_buf = [0u8; 64];
    bin2hex(
        CompressedRistrettoPublic::from(&result.pubkey).as_ref(),
        &mut hex_buf[..],
    )
    .expect("Failed converting to hex");
    print!("{}", std::str::from_utf8(&hex_buf).unwrap());
}
