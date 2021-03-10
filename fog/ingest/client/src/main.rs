// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Fog Ingest client

use fog_ingest_client::{
    config::{IngestConfig, IngestConfigCommand},
    ClientResult, FogIngestGrpcClient,
};
use fog_uri::FogIngestUri;
use mc_common::logger::{create_root_logger, log, Logger};
use std::{str::FromStr, sync::Arc};
use structopt::StructOpt;

fn main() -> ClientResult<()> {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let logger = create_root_logger();

    let config = IngestConfig::from_args();

    let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());

    let uri = FogIngestUri::from_str(&config.uri).expect("failed to parse uri");

    let ingest_client =
        FogIngestGrpcClient::new(uri, config.retry_seconds, grpcio_env, logger.clone());

    match config.cmd {
        IngestConfigCommand::GetStatus => get_status(&logger, &ingest_client),

        IngestConfigCommand::NewKeys => new_keys(&logger, &ingest_client),

        IngestConfigCommand::SetPubkeyExpiryWindow {
            pubkey_expiry_window,
        } => set_pubkey_expiry_window(&logger, &ingest_client, pubkey_expiry_window),

        IngestConfigCommand::SetPeers { peer_uris } => {
            set_peers(&logger, &ingest_client, &peer_uris)
        }
        IngestConfigCommand::Activate => activate(&logger, &ingest_client),
        IngestConfigCommand::Retire => retire(&logger, &ingest_client),

        IngestConfigCommand::ReportMissedBlockRange { start, end } => {
            report_missed_block_range(&logger, &ingest_client, start, end)
        }

        IngestConfigCommand::GetMissedBlockRanges => {
            get_missed_block_ranges(&logger, &ingest_client)
        }
    }
}

fn get_status(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.get_status().expect("rpc failed");
    log::info!(logger, "Status: {:?}", status);
    Ok(())
}

fn new_keys(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.new_keys().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    Ok(())
}

fn set_pubkey_expiry_window(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    pubkey_expiry_window: u64,
) -> ClientResult<()> {
    let status = ingest_client
        .set_pubkey_expiry_window(pubkey_expiry_window)
        .expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    Ok(())
}

fn set_peers(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    peer_uris: &[String],
) -> ClientResult<()> {
    let status = ingest_client.set_peers(peer_uris).expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    Ok(())
}

fn activate(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.activate().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    Ok(())
}

fn retire(logger: &Logger, ingest_client: &FogIngestGrpcClient) -> ClientResult<()> {
    let status = ingest_client.retire().expect("rpc failed");
    log::info!(logger, "Done, status: {:?}", status);
    Ok(())
}

fn report_missed_block_range(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
    start: u64,
    end: u64,
) -> ClientResult<()> {
    ingest_client
        .report_missed_block_range(start, end)
        .expect("Failed reporting missed block range");
    log::info!(
        logger,
        "Missed block range [{}-{}) reported successfully!",
        start,
        end
    );
    Ok(())
}

fn get_missed_block_ranges(
    logger: &Logger,
    ingest_client: &FogIngestGrpcClient,
) -> ClientResult<()> {
    let missed_block_ranges = ingest_client
        .get_missed_block_ranges()
        .expect("Failed getting missed block ranges");

    for range in missed_block_ranges.iter() {
        log::info!(logger, "[{}-{})", range.start_block, range.end_block);
    }
    Ok(())
}
