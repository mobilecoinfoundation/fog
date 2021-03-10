// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Database API types
//! These are not user-facing, the user facing versions are in fog-types crate.

use core::{fmt, ops::Deref};
use mc_attest_core::VerificationReport;
use serde::{Deserialize, Serialize};

/// Possible user events to be returned to end users.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum FogUserEvent {
    /// A new RNG record the user should begin searching for.
    NewRngRecord(fog_types::view::RngRecord),

    /// Ingest invocation decommissioned event
    DecommissionIngestInvocation(fog_types::view::DecommissionedIngestInvocation),

    /// A missed block range
    MissingBlocks(fog_types::common::BlockRange),
}

/// An ingest invocation begins consuming the blockchain at some particular block index, and eventually stops.
/// The IngestableRange tracks the start block, what the last scanned block is,
/// and whether it has stopped.
/// Clients use this information, for example, to avoid making unnecessary fog-view queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestableRange {
    /// The ingest invocation id this range is tied to.
    pub id: IngestInvocationId,

    /// The first block index that will be ingested by this invocation.
    pub start_block: u64,

    /// Whether this ingest invocation has been decommissioned or is still active.
    pub decommissioned: bool,

    /// The last block ingested by this invocation, if any.
    pub last_ingested_block: Option<u64>,
}

impl IngestableRange {
    /// Is, or will this IngestableRange be able to provide data for a given block index.
    pub fn can_provide_block(&self, block: u64) -> bool {
        // If this ingestable range starts after the desired block, it is not going to provide it.
        if block < self.start_block {
            false
        } else {
            // If this ingestable range is decomissioned, it will only provide blocks up until the
            // last ingested block
            if self.decommissioned {
                if let Some(last_ingested_block) = self.last_ingested_block {
                    last_ingested_block >= block
                } else {
                    false
                }
            } else {
                // Ingest invocation is still active so it is expected to provide this block
                true
            }
        }
    }
}

/// A globally unique identifier for ingest invocations. This ID should be unique for each instance
/// of an ingest enclave, and allows identifying that enclave during its lifetime.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct IngestInvocationId(i64);
impl fmt::Display for IngestInvocationId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl AsRef<i64> for IngestInvocationId {
    fn as_ref(&self) -> &i64 {
        &self.0
    }
}
impl Deref for IngestInvocationId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<i64> for IngestInvocationId {
    fn from(id: i64) -> Self {
        Self(id)
    }
}
impl From<IngestInvocationId> for i64 {
    fn from(src: IngestInvocationId) -> i64 {
        src.0
    }
}

/// Fog report data (the data associated with each report).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportData {
    /// The ingest invocation id that wrote this report.
    pub ingest_invocation_id: Option<IngestInvocationId>,

    /// The Intel Attestation Service report, which include the pubkey
    pub report: VerificationReport,

    /// The pubkey_expiry (a block height)
    pub pubkey_expiry: u64,
}
