// Copyright (c) 2018-2021 The MobileCoin Foundation
#![allow(unused)]
use fog_api::fog_common::BlockRange;
use mc_common::logger::{log, Logger};
use mc_ledger_db::{self, Error as DbError, Ledger};
use std::collections::HashMap;

/// A utility object that keeps track of which block number was processed
/// . This provides utilities such as:
/// - Finding out what is the next block that needs processing .
/// - Finding out what is the highest block index we have encountered so far.
/// - Finding out for which block index have we processed data, while taking
///   into account missed blocks.
pub struct BlockTracker {
    last_highest_processed_block_count: u64,
    logger: Logger,
}

impl BlockTracker {
    pub fn new(logger: Logger) -> Self {
        Self {
            last_highest_processed_block_count: 0,
            logger,
        }
    }
}
