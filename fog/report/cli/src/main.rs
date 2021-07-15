// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A CLI tool that resolves FogPubkey requests
//!
//! This is used so that python can get the fog pubkey bytes as a hex string,
//! and then use them in the fog conformance test to create fog TxOuts.
//!
//! At time of writing, it takes the public address of a user (.pub keyfile),
//! since the FogPubkeyResolver API fully validates the fog report and the
//! user's signature over the cert chain.
//! In the future if needed we could make this take only the fog report url
//! and report id, and not fully validate the pubkey, but that would require
//! code changes in the GrpcFogPubkeyResolver object. It might make this a more
//! useful diagnostic tool.

use binascii::bin2hex;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_core::{VerificationReportData, Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_report_connection::{Error, GrpcFogReportConnection};
use mc_fog_report_validation::{
    FogPubkeyResolver, FogReportResponses, FogResolver, FullyValidatedFogPubkey,
};
use mc_sgx_types::sgx_report_data_t;
use mc_util_uri::FogUri;
use std::{
    convert::TryFrom,
    path::PathBuf,
    process::exit,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;

/// A command line utility to reach out to the fog report server and fetch the
/// ingest report, and optionally validate it.
///
/// This command prints the bytes of the ingress pubkey in hex, with no newline,
/// so that it can be easily captured by automation.
/// Optionally, it also shows the pubkey-expiry value, in this case the output
/// is json formatted.
///
/// The action can be specified in a few ways:
/// - Supply a path to a public address file. This will perform full validation,
///   as if we were sending to this fog user.
/// - Supply a fog-url and a fog-spki. This will perform full validation, that
///   would be performed for a fog user with these values in their address.
/// - Supply only a fog-url. This will perform NO validation, not checking IAS,
///   measurements, or any cert chains.
#[derive(Debug, StructOpt)]
struct Config {
    /// Path to mobilecoin public address. Fog url and spki will be extracted,
    /// and fog signature will be checked.
    #[structopt(long = "public-address", short = "p")]
    pub public_address: Option<PathBuf>,

    /// The fog url to hit.
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-url", short = "u")]
    pub fog_url: Option<String>,

    /// The fog report id to find.
    /// This is optional and almost always defaulted to "".
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-report-id", short = "i")]
    pub fog_report_id: Option<String>,

    /// The fog authority spki, in base 64
    /// If omitted, then NO verification of any kind (IAS, MRSIGNER, cert
    /// chains) will be performed.
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-spki", short = "s")]
    pub fog_spki: Option<String>,

    /// How long to retry if NoReports, this is useful for tests
    #[structopt(long = "retry-seconds", short = "r", default_value = "10")]
    pub retry_seconds: u64,

    /// Indicates to output json encoding of hex bytes of fog ingress pubkey,
    /// and the pubkey expiry value of this key.
    #[structopt(long = "show-expiry", short = "v")]
    pub show_expiry: bool,
}

/// Get fog response with retries, retrying if NoReports error occurs
fn get_fog_response_with_retries(
    fog_uri: FogUri,
    retry_duration: Duration,
    logger: &Logger,
) -> FogReportResponses {
    // Create the grpc object and report verifier
    let grpc_env = Arc::new(EnvBuilder::new().name_prefix("cli").build());

    let conn = GrpcFogReportConnection::new(grpc_env, logger.clone());

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
fn get_validated_pubkey(
    responses: FogReportResponses,
    pub_addr: PublicAddress,
    logger: &Logger,
) -> FullyValidatedFogPubkey {
    let mut verifier = Verifier::default();

    {
        let mr_signer_verifier = fog_ingest_enclave_measurement::get_mr_signer_verifier(None);
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
    }

    log::debug!(logger, "IAS verifier: {:?}", &verifier);

    let resolver = FogResolver::new(responses, &verifier);
    resolver
        .expect("Could not get FogPubkey resolved")
        .get_fog_pubkey(&pub_addr)
        .expect("Could not validate fog pubkey")
}

/// Try to grab pubkey and expiry out of the response without validating
fn get_unvalidated_pubkey(
    responses: FogReportResponses,
    fog_uri: FogUri,
    fog_report_id: String,
    _logger: &Logger,
) -> (RistrettoPublic, u64) {
    let resp = responses
        .get(&fog_uri.to_string())
        .expect("Didn't find response from this URI");
    let rep = resp
        .reports
        .iter()
        .find(|rep| rep.fog_report_id == fog_report_id)
        .expect("Didn't find report with the right report id");
    let pubkey_expiry = rep.pubkey_expiry;
    // This parses the b64 json from intel
    let verification_report_data = VerificationReportData::try_from(&rep.report)
        .expect("Could not parse verification report data");
    // This extracts the user-data attached to the report, which is a thin wrapper
    // around [u8; 64]
    let report_data = verification_report_data
        .quote
        .report_body()
        .expect("bad report body")
        .report_data();
    // Unwrap the wrapper
    let report_data = sgx_report_data_t::from(report_data);
    // The second half of this is the data we care about (and which should be
    // Ristretto)
    let pubkey = RistrettoPublic::try_from(&report_data.d[32..64])
        .expect("report didn't contain a valid key");
    (pubkey, pubkey_expiry)
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::from_args();
    let logger = create_root_logger();

    // Get public address either from a file, or synthesize from BOTH fog-url and
    // spki. If we only have fog-url, we can't make a public address and we
    // won't do any validation.
    let pub_addr: Option<PublicAddress> = if let Some(path) = config.public_address {
        let pub_addr =
            mc_util_keyfile::read_pubfile(path).expect("Could not read public address file");
        if config.fog_url.is_some() {
            panic!("Can't specify public address file and fog url");
        }
        if config.fog_report_id.is_some() {
            panic!("Can't specify public address file and fog report id");
        }
        if config.fog_spki.is_some() {
            panic!("Can't specify public address file and fog spki");
        }
        Some(pub_addr)
    } else if let Some(spki) = config.fog_spki {
        log::debug!(logger, "Creating synthetic public address");
        let fog_report_url =
            FogUri::from_str(&config.fog_url.clone().expect("no fog url was specified"))
                .expect("Could not parse fog report url as a valid fog url");

        let report_id = config.fog_report_id.unwrap_or_default();

        let spki = base64::decode(spki).expect("Couldn't decode spki as base 64");

        let account_key = AccountKey::new_with_fog(
            &Default::default(),
            &Default::default(),
            fog_report_url,
            report_id,
            spki,
        );
        Some(account_key.default_subaddress())
    } else {
        None
    };

    // If we got a public address, use the validated code path
    let (pubkey, pubkey_expiry): (RistrettoPublic, u64) = if let Some(pub_addr) = pub_addr {
        // Get fog url
        let fog_uri = FogUri::from_str(
            pub_addr
                .fog_report_url()
                .expect("public address had no fog url"),
        )
        .expect("Could not parse fog report url as a valid fog url");

        // Try to make request
        let responses = get_fog_response_with_retries(
            fog_uri,
            Duration::from_secs(config.retry_seconds),
            &logger,
        );

        // Try to validate response
        let result = get_validated_pubkey(responses, pub_addr, &logger);
        (result.pubkey, result.pubkey_expiry)
    } else {
        // In this case, there's no spki and no validation,
        // we're going to just hit a Fog report server and
        // parse the pubkey and expiry out of response.
        let fog_uri = FogUri::from_str(&config.fog_url.expect("no fog url was specified"))
            .expect("Could not parse fog report url as a valid fog url");

        // Try to make request
        let responses = get_fog_response_with_retries(
            fog_uri.clone(),
            Duration::from_secs(config.retry_seconds),
            &logger,
        );

        get_unvalidated_pubkey(responses, fog_uri, "".to_string(), &logger)
    };

    let mut hex_buf = [0u8; 64];
    bin2hex(
        CompressedRistrettoPublic::from(&pubkey).as_ref(),
        &mut hex_buf[..],
    )
    .expect("Failed converting to hex");
    let hex_str = std::str::from_utf8(&hex_buf).unwrap();

    // if show-expiry is selected, we show key and expiry, formatted as json
    // else just print the hex bytes of key
    if config.show_expiry {
        print!(
            "{{ \"pubkey\": \"{}\", \"pubkey_expiry\": {} }}",
            hex_str, pubkey_expiry
        );
    } else {
        print!("{}", hex_str);
    }
}
