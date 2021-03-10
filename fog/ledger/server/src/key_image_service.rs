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
use std::{convert::From, sync::Arc};

// Maximum number of Key Images that may be checked in a single request.
pub const MAX_REQUEST_SIZE: usize = 2000;

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

    fn check_key_images_auth(&mut self, request: Message) -> Result<Message, RpcStatus> {
        let key_image_context = match self.enclave.check_key_images(request.clone().into()) {
            Ok(context) => context,
            Err(EnclaveError::Attest(attest_error)) => {
                return Err(rpc_permissions_error(
                    "check_key_images",
                    EnclaveError::Attest(attest_error),
                    &self.logger,
                ))
            }
            Err(EnclaveError::Serialization) => {
                return Err(rpc_invalid_arg_error(
                    "check_key_images",
                    EnclaveError::Serialization,
                    &self.logger,
                ))
            }
            Err(e) => return Err(rpc_internal_error("check_key_images", e, &self.logger)),
        };

        let response = self.check_key_images_impl(key_image_context)?;

        let result = match self
            .enclave
            .check_key_images_data(response, ClientSession::from(request.channel_id))
        {
            Ok(message) => message,
            Err(EnclaveError::Attest(attest_error)) => {
                return Err(rpc_permissions_error(
                    "check_key_images_data",
                    EnclaveError::Attest(attest_error),
                    &self.logger,
                ))
            }
            Err(EnclaveError::Serialization) => {
                return Err(rpc_invalid_arg_error(
                    "check_key_images_data",
                    EnclaveError::Serialization,
                    &self.logger,
                ))
            }
            Err(e) => return Err(rpc_internal_error("check_key_images_data", e, &self.logger)),
        };

        Ok(result.into())
    }

    fn check_key_images_impl(
        &mut self,
        key_image_context: KeyImageContext,
    ) -> Result<CheckKeyImagesResponse, RpcStatus> {
        if key_image_context.key_images.len() > MAX_REQUEST_SIZE {
            return Err(rpc_invalid_arg_error(
                "check_key_images",
                "Request size exceeds limit",
                &self.logger,
            ));
        }

        Ok(CheckKeyImagesResponse {
            num_blocks: self
                .ledger
                .num_blocks()
                .map_err(|err| rpc_database_err(err, &self.logger))?,
            global_txo_count: self
                .ledger
                .num_txos()
                .map_err(|err| rpc_database_err(err, &self.logger))?,
            results: key_image_context
                .key_images
                .iter()
                .map(|key_image| {
                    // Get the block where this KeyImage landed
                    let (spent_at, ki_result) = match self.ledger.check_key_image(&key_image) {
                        Ok(maybe_index) => match maybe_index {
                            Some(spent_at) => (spent_at, KeyImageResultCode::Spent),
                            None => (u64::MAX, KeyImageResultCode::NotSpent),
                        },
                        Err(err) => {
                            log::error!(
                                self.logger,
                                "Database error for key image {:?}: {}",
                                key_image,
                                err
                            );
                            (u64::MAX, KeyImageResultCode::KeyImageError)
                        }
                    };
                    // Get the timestamp of the spent_at block
                    let (timestamp, ts_result): (u64, TimestampResultCode) =
                        match self.watcher.get_block_timestamp(spent_at) {
                            Ok((ts, res)) => (ts, res),
                            Err(err) => {
                                log::error!(
                                    self.logger,
                                    "Could not obtain timestamp for block {} due to error {:?}",
                                    spent_at,
                                    err
                                );
                                (u64::MAX, TimestampResultCode::WatcherDatabaseError)
                            }
                        };

                    KeyImageResult {
                        key_image: *key_image,
                        spent_at,
                        timestamp,
                        timestamp_result_code: ts_result as u32,
                        key_image_result_code: ki_result as u32,
                    }
                })
                .collect(),
        })
    }
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
