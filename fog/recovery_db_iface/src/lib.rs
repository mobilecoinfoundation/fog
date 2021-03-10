// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Abstract interface to the fog recovery database

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod types;

use alloc::{string::String, vec::Vec};
use core::fmt::{Debug, Display};
use fog_kex_rng::KexRngPubkey;
use fog_types::view::TxOutSearchResult;
use mc_crypto_keys::CompressedRistrettoPublic;

pub use fog_types::{common::BlockRange, ETxOutRecord};
pub use mc_transaction_core::Block;
pub use types::{FogUserEvent, IngestInvocationId, IngestableRange, ReportData};

/// A generic error type for recovery db operations
pub trait RecoveryDbError: Debug + Display + Send + Sync {}
impl<T> RecoveryDbError for T where T: Debug + Display + Send + Sync {}

/// Status in the database connected to this ingress public key
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IngressPublicKeyStatus {
    /// The first block that fog promises to scan with this key after publishing it.
    /// This should be the latest block that existed before we published it (or, a block close to but before that)
    pub start_block: u64,
    /// The largest pubkey expiry value that we have ever published for this key.
    /// If less than start_block, it means we have never published this key.
    pub pubkey_expiry: u64,
    /// Whether this key is retiring / retired.
    /// When a key is retired, we stop publishing reports about it.
    pub retired: bool,
}

/// Information returned after attempting to add block data to the database.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AddBlockDataStatus {
    /// Indicates that the block we tried to add has already been scanned using this ingress key,
    /// and didn't need to be scanned again.
    ///
    /// If this value is true, then no data was added to the database.
    pub block_already_scanned_with_this_key: bool,
}

/// The recovery database interface.
pub trait RecoveryDb {
    /// The error type returned by the various calls in this trait.
    type Error: RecoveryDbError;

    /// Get the status of an ingress public key
    fn get_ingress_key_status(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<IngressPublicKeyStatus>, Self::Error>;

    /// Add a new ingress public key, which does not currently exist in the DB.
    ///
    /// Arguments:
    /// * key: the public key
    /// * start_block: the first block we promise to scan with this key
    ///
    /// Returns
    /// * true if the insert was successful, false if this key already exists in the database
    fn new_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        start_block: u64,
    ) -> Result<bool, Self::Error>;

    /// Mark an ingress public key for retiring.
    ///
    /// Passing set_retired = true will make all servers using it stop publishing reports,
    /// continue scanning to pubkey expiry value, and then stop.
    /// set_retired = false will cause it to not be marked for retiring anymore, if it was marked for retiring by mistake.
    fn retire_ingress_key(
        &self,
        key: &CompressedRistrettoPublic,
        set_retired: bool,
    ) -> Result<(), Self::Error>;

    /// Get the index of the last block scanned using this ingress key, if any.
    ///
    /// Arguments:
    /// * key: the ingress key
    ///
    /// Returns:
    /// * Some(BlockIndex) if blocks have already been scanned using this key,
    ///   None if no blocks have been scanned using this key.
    fn get_last_scanned_block_index(
        &self,
        key: &CompressedRistrettoPublic,
    ) -> Result<Option<u64>, Self::Error>;

    /// Adds a new ingest invocation to the database, optionally decommissioning an older one.
    ///
    /// This should be done when the ingest enclave is processing block data,
    /// and the ORAM overflows and the KexRngPubkey is rotated by the enclave.
    /// And, when the ingest enclave starts up and creates a KexRngPubkey, just
    /// before it starts consuming transactions.
    ///
    /// This decommissions the old ingest invocation id and creates a new one,
    /// associated to the new public keys.
    /// Arguments:
    /// * prev_ingest_invocation_id: The previous unique ingest invocation id to retire
    /// * ingress_public_key: The ingest server ingress public key, as reported to the report server.
    /// * egress_public_key: The kex rng pubkey emitted by the ingest enclave
    /// * start_block: The first block index this ingest invocation will start ingesting from.
    fn new_ingest_invocation(
        &self,
        prev_ingest_invocation_id: Option<IngestInvocationId>,
        ingress_public_key: &CompressedRistrettoPublic,
        egress_public_key: &KexRngPubkey,
        start_block: u64,
    ) -> Result<IngestInvocationId, Self::Error>;

    /// Get the list of blocks that the fog deployment is able to ingest.
    // TODO: Allow filtering so that we don't always get the entire list.
    fn get_ingestable_ranges(&self) -> Result<Vec<IngestableRange>, Self::Error>;

    /// Decommission a given ingest invocation.
    ///
    /// This should be done when a given ingest enclave goes down or is retired.
    ///
    /// Arguments:
    /// * ingest_invocation_id: The unique ingest invocation id that has been retired
    fn decommission_ingest_invocation(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error>;

    /// Add records corresponding to a FULLY PROCESSED BLOCK to the database
    ///
    /// Arguments:
    /// * ingest_invocation_id: The unique ingest invocation id this block was processed by.
    /// * block: The block that was processed.
    /// * block_signature_timestamp: Seconds since the unix epoch when the block was signed
    /// * tx_rows: TxRows that the ingest enclave emitted when processing this block
    fn add_block_data(
        &self,
        ingest_invocation_id: &IngestInvocationId,
        block: &Block,
        block_signature_timestamp: u64,
        txs: &[ETxOutRecord],
    ) -> Result<AddBlockDataStatus, Self::Error>;

    /// Report that a half-open range of blocks has been missed irrecoverably.
    ///
    /// Clients that hit the view node will learn about the range. Then they have to download
    /// missed blocks from the fog ledger server, and then view-key scan them to recover
    /// their transactions.
    ///
    /// If blocks are missed but this call is never made, then clients will never be able
    /// to compute an accurate balance after `start`. highest_processed_block_count will always be computed
    /// as less than any missed block (gap in the data), until a range covering that gap is reported
    /// permanently missed.
    /// This means that the database does the right thing to fulfill the client contract automatically
    /// in the face of missed blocks, but actively reporting missed block range is required to allow
    /// progress by the client.
    ///
    /// Arguments:
    /// * block_range: The missing block range.
    fn report_missed_block_range(&self, block_range: &BlockRange) -> Result<(), Self::Error>;

    /// Gets all the known missed block ranges.
    ///
    /// Returns:
    /// * A vector of missing block ranges.
    fn get_missed_block_ranges(&self) -> Result<Vec<BlockRange>, Self::Error>;

    /// Get any events which are new after `start_after_event_id`.
    ///
    /// Arguments:
    /// * start_after_event_id: The last event id the user has received.
    ///
    /// Returns:
    /// * List of found events, and higehst event id in the database (to be used as
    /// start_after_event_id in the next query).
    fn search_user_events(
        &self,
        start_from_user_event_id: i64,
    ) -> Result<(Vec<FogUserEvent>, i64), Self::Error>;

    /// Get any TxOutSearchResults corresponding to given search keys.
    /// Nonzero start_block can be provided as an optimization opportunity.
    ///
    /// Arguments:
    /// * start_block: A lower bound on where we will search. This can often be provided by the user
    ///                in order to limit the scope of the search and reduce load on the servers.
    /// * search_keys: A list of fog tx_out search keys to search for.
    ///
    /// Returns:
    /// * Exactly one TxOutSearchResult object for every search key, or an internal database error description.
    fn get_tx_outs(
        &self,
        start_block: u64,
        search_keys: &[Vec<u8>],
    ) -> Result<Vec<TxOutSearchResult>, Self::Error>;

    /// Mark a given ingest invocation as still being alive.
    fn update_last_active_at(
        &self,
        ingest_invocation_id: &IngestInvocationId,
    ) -> Result<(), Self::Error>;

    /// Get any ETxOutRecords produced by a given IngestInvocationId for a given block index.
    ///
    /// Arguments:
    /// * ingest_invocation_id: The ingest invocation we need ETxOutRecords from
    /// * block_index: The block we need ETxOutRecords from
    ///
    /// Returns:
    /// * The ETxOutRecord's from when this block was added, or, an error
    fn get_tx_outs_by_block(
        &self,
        ingest_invocation_id: &IngestInvocationId,
        block_index: u64,
    ) -> Result<Vec<ETxOutRecord>, Self::Error>;

    /// Get the cumulative txo count for a given block number.
    ///
    /// Arguments:
    /// * block_index: The block we need cumulative_txo_count for.
    ///
    /// Returns:
    /// * Some(cumulative_txo_count) if the block was found in the database, None if it wasn't, or
    /// an error if the query failed.
    fn get_cumulative_txo_count_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error>;

    /// Get the block signature timestamp for a given block number.
    /// This is a number of seconds since the unix epoch.
    ///
    /// Arguments:
    /// * block_index: The block we need cumulative_txo_count for.
    ///
    /// Returns:
    /// * Some(timestamp) if the block was found in the database, None if it wasn't, or
    /// an error if the query failed.
    ///
    /// Note: It is unspecified which invocation id we use when giving the timestamp
    fn get_block_signature_timestamp_for_block(
        &self,
        block_index: u64,
    ) -> Result<Option<u64>, Self::Error>;

    /// Get the highest block index for which we have any data at all.
    fn get_highest_known_block_index(&self) -> Result<Option<u64>, Self::Error>;
}

/// The report database interface.
pub trait ReportDb {
    /// The error type returned by the various calls in this trait.
    type Error: RecoveryDbError;

    /// Get all available report data
    /// Note: We always give the user all the report data, because it is a privacy
    /// issue if the user divulges which report they care about.
    /// There are not expected to be very many reports.
    /// If there are many reports, then this should be redesigned to use an oblivious
    /// lookup strategy inside of an sgx enclave.
    ///
    /// Returns:
    /// * Pairs of the form report-id, report-data
    fn get_all_reports(&self) -> Result<Vec<(String, ReportData)>, Self::Error>;

    /// Set report data associated with a given report id, unless the public key is retired.
    ///
    /// Arguments:
    /// * ingress_public_key - the public key signed by this report
    /// * report_id - the report_id associated to the report. this should almost always be the empty string.
    /// * data - The IAS verification report and cert chain.
    ///
    /// Returns:
    /// * The status of this ingress public key in the database.
    ///   If the status is retired, then this set operation DID NOT HAPPEN,
    ///   and no changes were made to the database.
    fn set_report(
        &self,
        ingress_public_key: &CompressedRistrettoPublic,
        report_id: &str,
        data: &ReportData,
    ) -> Result<IngressPublicKeyStatus, Self::Error>;

    /// Remove report data associated with a given report id.
    fn remove_report(&self, report_id: &str) -> Result<(), Self::Error>;
}
