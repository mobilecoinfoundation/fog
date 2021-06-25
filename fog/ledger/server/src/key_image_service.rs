// Copyright (c) 2018-2021 The MobileCoin Foundation

use fog_api::ledger_grpc::FogKeyImageApi;
use fog_ledger_enclave::{
    CheckKeyImagesResponse, KeyImageContext, KeyImageResult, KeyImageResultCode, LedgerEnclaveProxy,
};
use fog_ledger_enclave_api::Error as EnclaveError;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_enclave_api::ClientSession;
use mc_common::logger::{log, Logger};
use mc_ledger_db::{self, Ledger};
use mc_util_grpc::{
    rpc_database_err, rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error,
    send_result, Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::sync::Arc;

// Maximum number of Key Image that may be checked in a single request.
pub const MAX_REQUEST_SIZE: usize = 2000;

/// UntrustedKeyImageQueryResponse object that contains any data that is needed that isn't in the ORAM. This might be like "num_blocks"
#[derive(Serialize, Deserialize)]
pub struct UntrustedKeyImageQueryResponse {
     /// User events.
     pub user_events: Vec<FogUserEvent>,

     /// The next value the user should use for start_from_user_event_id.
     pub next_start_from_user_event_id: i64,
    /// The number of blocks at the time that the request was evaluated.
    pub highest_processed_block_count: u64,

    /// The timestamp of the highest processed block at the time that the
    /// request was evaluated.
    pub highest_processed_block_signature_timestamp: u64,

    /// The index of the last known block, which can be obtained by calculating
    /// last_known_block_count - 1. We don't store the index but instead store a
    /// count so that we have a way of representing no known block (0).
    pub last_known_block_count: u64,

    /// The cumulative count of the last known block.
    pub last_known_block_cumulative_count: u64,
}

#[derive(Clone)]
pub struct KeyImageService<L: Ledger + Clone, E: LedgerEnclaveProxy> {
    ledger: L,
    watcher: WatcherDB,
    enclave: E,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> KeyImageService<L, E> {
    pub fn new(
        ledger: L,
        watcher: WatcherDB,
        enclave: E,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            ledger,
            watcher,
            enclave,
            authenticator,
            logger,
        }
    }

    fn check_key_images_auth(&mut self, request: Message,  untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse) -> Result<Message, RpcStatus> {
       // self.enclave.check_key_images should take both an AttestMessage and an Untruste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dKeyImageQueryResponse object that contains any data that is
       //needed that isn't in the ORAM. This might be like "num_blocks" and similar stuff.
       //self.enclave.check_key_images should return an AttestMessage that we send back to the user.
        let mut resp = self.enclave.check_key_images(request.clone().into(), untrusted_keyimagequery_response);
            Ok(resp)
        }

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> FogKeyImageApi for KeyImageService<L, E> {
    fn check_key_images(&mut self, ctx: RpcContext, request: Message, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.check_key_images_auth(request), &logger)
        })
    }

    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.into()) {
                Ok((response, _session_id)) => {
                    send_result(ctx, sink, Ok(response.into()), &logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::info!(
                        logger,
                        "LedgerEnclave::client_accept failed: {}",
                        client_error
                    );
                    // TODO: increment failed inbound peering counter.
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "client_auth",
                            "Permission denied",
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }
}
