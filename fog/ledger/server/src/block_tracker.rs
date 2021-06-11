// Copyright (c) 2018-2021 The MobileCoin Foundation
#![allow(unused)]
use mc_ledger_db::{self, Error as DbError, Ledger};
use fog_api::fog_common::BlockRange;
use mc_common::logger::{log, Logger};
use std::collections::HashMap;

/// A utility object that keeps track of which block number was processed 
/// . This provides utilities such as:
/// - Finding out what is the next block that needs processing .
/// - Finding out what is the highest block index we have encountered so far.
/// - Finding out for which block index have we processed data, while
///   taking into account missed blocks.
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

    /// Given a list of ingestable ranges, missing blocks and current state, calculate the highest
    /// processed block count number. The highest processed block count number is the block count
    /// for which we know we have loaded all available data.
    pub fn highest_fully_processed_block_count(
        &mut self,
        missing_block_ranges: &[BlockRange],
    ) -> u64 {
        let initial_last_highest_processed_block_count = self.last_highest_processed_block_count;

       
            let next_block_index = self.last_highest_processed_block_count;
            let next_block_count = self.last_highest_processed_block_count + 1;

            log::trace!(
                self.logger,
                "checking if highest_processed_block_count can be advanced to {}",
                next_block_count,
            );

            // Go over all known ingestable ranges and ensure we have processed next_block_index
            // in all the ranges that are able to provide that block index.
            let mut block_can_be_provided = false;

            // If we got here it means:
            // 1) next_block_index is not reported as missing.
            // 2) At least one ingestable range could provide the block.
            // 3) All ingestable ranges that could process the block have processed it.
            self.last_highest_processed_block_count = next_block_count;
        

        if self.last_highest_processed_block_count != initial_last_highest_processed_block_count {
            log::info!(
                self.logger,
                "advancing last_highest_processed_block_count from {} to {}",
                initial_last_highest_processed_block_count,
                self.last_highest_processed_block_count,
            );
        }

        self.last_highest_processed_block_count
    }

    // Given a list of block ranges and the current state, calculate which block
   // index needs to be processed next.
    pub fn next_blocks(
            &mut self
        ) -> HashMap<IngestInvocationId, u64> {
            let mut next_blocks = HashMap::default();
             // to do figure how next block
            next_blocks
        }
    }
        