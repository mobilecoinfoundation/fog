// Copyright (c) 2018-2021 The MobileCoin Foundation

use fog_recovery_db_iface::{IngestInvocationId, IngestableRange};
use fog_types::common::BlockRange;
use mc_common::logger::{log, Logger};
use std::collections::HashMap;

/// A utility object that keeps track of which block number was processed for
/// every known ingest invocation. This provides utilities such as:
/// - Finding out what is the next block that needs processing for any of the
///   ingest invocations.
/// - Finding out what is the highest block index we have encountered so far.
/// - Finding out for which block index have we processed data for all ingest
///   invocations, while taking into account missed blocks.
pub struct BlockTracker {
    processed_block_per_invocation: HashMap<IngestInvocationId, u64>,
    last_highest_processed_block_count: u64,
    logger: Logger,
}

impl BlockTracker {
    pub fn new(logger: Logger) -> Self {
        Self {
            processed_block_per_invocation: HashMap::default(),
            last_highest_processed_block_count: 0,
            logger,
        }
    }

    // Given a list of ingestable ranges and the current state, calculate which
    // block index needs to be processed next for each ingest invocation.
    pub fn next_blocks(
        &self,
        ingestable_ranges: &[IngestableRange],
    ) -> HashMap<IngestInvocationId, u64> {
        let mut next_blocks = HashMap::default();

        for ingestable_range in ingestable_ranges {
            if let Some(last_processed_block) = self
                .processed_block_per_invocation
                .get(&ingestable_range.id)
            {
                // A block has previously been processed for this ingest invocation. See if the
                // next one can be provided by it, and if so add it to the list of next blocks
                // we would like to process.
                let next_block = last_processed_block + 1;
                if ingestable_range.can_provide_block(next_block) {
                    next_blocks.insert(ingestable_range.id, next_block);
                }
            } else {
                // No block has been processed for this invocation id, so the next block is the
                // first one, assuming it can actually be provided by the ingest invocation.
                // (It will not be able to provide the start block if it got decommissioned
                // immediately after starting before scanning any blocks)
                if ingestable_range.can_provide_block(ingestable_range.start_block) {
                    next_blocks.insert(ingestable_range.id, ingestable_range.start_block);
                }
            }
        }

        next_blocks
    }

    pub fn block_processed(&mut self, ingest_invocation_id: IngestInvocationId, block_index: u64) {
        if let Some(previous_block_index) = self
            .processed_block_per_invocation
            .insert(ingest_invocation_id, block_index)
        {
            // Sanity check that we are only moving forward and not skipping any blocks.
            assert!(block_index == previous_block_index + 1);
        }
    }

    /// Given a list of ingestable ranges, missing blocks and current state,
    /// calculate the highest processed block count number. The highest
    /// processed block count number is the block count for which we know we
    /// have loaded all available data.
    pub fn highest_fully_processed_block_count(
        &mut self,
        ingestable_ranges: &[IngestableRange],
        missing_block_ranges: &[BlockRange],
    ) -> u64 {
        let initial_last_highest_processed_block_count = self.last_highest_processed_block_count;

        'outer: loop {
            let next_block_index = self.last_highest_processed_block_count;
            let next_block_count = self.last_highest_processed_block_count + 1;

            log::trace!(
                self.logger,
                "checking if highest_processed_block_count can be advanced to {}",
                next_block_count,
            );

            // If the block has been reported as missing, we can advance since we don't need
            // to do any processing for it.
            if Self::is_missing_block(missing_block_ranges, next_block_index) {
                log::trace!(
                    self.logger,
                    "block {} reported missing, advancing block count to {}",
                    next_block_index,
                    next_block_count
                );
                self.last_highest_processed_block_count = next_block_count;
                continue;
            }

            // Go over all known ingestable ranges and ensure we have processed
            // next_block_index in all the ranges that are able to provide that
            // block index.
            let mut block_can_be_provided = false;

            for ingestable_range in ingestable_ranges.iter() {
                if !ingestable_range.can_provide_block(next_block_index) {
                    continue;
                }

                block_can_be_provided = true;

                if let Some(last_processed_block) = self
                    .processed_block_per_invocation
                    .get(&ingestable_range.id)
                {
                    if next_block_index > *last_processed_block {
                        // The ingestable range can provide next_block_index but hasn't yet so
                        // thats is as far as we can go.
                        log::trace!(self.logger, "cannot advance highest_processed_block_count to {} - ingest invocation {} only processed block {}", next_block_count, ingestable_range.id, last_processed_block);
                        break 'outer;
                    }
                } else {
                    // No blocks have been processed yet by this ingest invocation.
                    log::trace!(self.logger, "cannot advance highest_processed_block_count to {} - ingest invocation {} hasn't processed anything yet", next_block_count, ingestable_range.id);
                    break 'outer;
                }
            }

            if !block_can_be_provided {
                if !ingestable_ranges.is_empty() {
                    // next_block_index is neither missing nor can it be provided by any ingest
                    // invocation. This is fishy so stop here.
                    log::warn!(self.logger, "block index {} is not reported missing but cannot be fulfiled by any of the ingest invocation ranges {:?}", next_block_index, ingestable_ranges);
                }

                break;
            }

            // If we got here it means:
            // 1) next_block_index is not reported as missing.
            // 2) At least one ingestable range could provide the block.
            // 3) All ingestable ranges that could process the block have processed it.
            self.last_highest_processed_block_count = next_block_count;
        }

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

    /// Get the highest block count we have encountered.
    pub fn highest_known_block_count(&self) -> u64 {
        self.processed_block_per_invocation
            .iter()
            .map(|(_ingest_invocation_id, block_index)| *block_index + 1)
            .max()
            .unwrap_or(0)
    }

    /// Check if a block has been reported as missing.
    // TODO this can be much more efficient
    pub fn is_missing_block(missing_block_ranges: &[BlockRange], block: u64) -> bool {
        for range in missing_block_ranges.iter() {
            if range.contains(block) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::test_with_logger;
    use std::{cmp::min, iter::FromIterator};

    #[test_with_logger]
    fn next_blocks_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger.clone());
        assert_eq!(block_tracker.next_blocks(&[]).len(), 0);
    }

    // Single ingestable range (commissioned, hasn't scanned any blocks yet)
    #[test_with_logger]
    fn next_blocks_single_range_commissioned_hasnt_scanned(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);
        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 123,
            decommissioned: false,
            last_ingested_block: None,
        };

        let expected_state =
            HashMap::from_iter(vec![(ingestable_range.id, ingestable_range.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Repeated call should result in the same expected result.
        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            let expected_state = HashMap::from_iter(vec![(
                ingestable_range.id,
                ingestable_range.start_block + i + 1,
            )]);

            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );

            // Repeated call should result in the same expected result.
            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );
        }
    }

    // Single ingestable range (commissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_commissioned_scanned_some(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);
        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 123,
            decommissioned: false,
            last_ingested_block: Some(126),
        };

        let expected_state =
            HashMap::from_iter(vec![(ingestable_range.id, ingestable_range.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Repeated call should result in the same expected result.
        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            let expected_state = HashMap::from_iter(vec![(
                ingestable_range.id,
                ingestable_range.start_block + i + 1,
            )]);

            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );

            // Repeated call should result in the same expected result.
            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );
        }
    }

    // Single ingestable range (decommissioned, hasn't scanned anything)
    #[test_with_logger]
    fn next_blocks_single_range_decommissioned_hasnt_scanned(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);
        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 123,
            decommissioned: true,
            last_ingested_block: None,
        };

        let expected_state = HashMap::from_iter(vec![]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Repeated call should result in the same expected result.
        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Advancing to the next block should return the same result.
        for i in 0..10 {
            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );

            // Repeated call should result in the same expected result.
            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );
        }
    }

    // Single ingestable range (decommissioned, scanned some blocks)
    #[test_with_logger]
    fn next_blocks_single_range_decommissioned_scanned_some(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);
        let last_ingested_block = 126;
        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 123,
            decommissioned: true,
            last_ingested_block: Some(last_ingested_block.clone()),
        };

        let expected_state =
            HashMap::from_iter(vec![(ingestable_range.id, ingestable_range.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Repeated call should result in the same expected result.
        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range.clone()]),
            expected_state
        );

        // Advancing to the next block should advance the expected result.
        for i in 0..10 {
            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            // Capped at the last block that was scanned.
            let expected_state = if ingestable_range.start_block + i + 1 <= last_ingested_block {
                HashMap::from_iter(vec![(
                    ingestable_range.id,
                    ingestable_range.start_block + i + 1,
                )])
            } else {
                HashMap::default()
            };

            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );

            // Repeated call should result in the same expected result.
            assert_eq!(
                block_tracker.next_blocks(&[ingestable_range.clone()]),
                expected_state
            );
        }
    }

    // Two ingestable ranges should advance independently of eachother
    #[test_with_logger]
    fn next_blocks_multiple_ranges(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);
        let ingestable_range1 = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 123,
            decommissioned: false,
            last_ingested_block: None,
        };

        let ingestable_range2 = IngestableRange {
            id: IngestInvocationId::from(2),
            start_block: 3000,
            decommissioned: false,
            last_ingested_block: None,
        };

        let expected_state =
            HashMap::from_iter(vec![(ingestable_range1.id, ingestable_range1.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range1.clone()]),
            expected_state
        );

        // Repeated call should result in the same expected result.
        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range1.clone()]),
            expected_state
        );

        // Try again with the second ingestable range.
        let expected_state =
            HashMap::from_iter(vec![(ingestable_range2.id, ingestable_range2.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range2.clone()]),
            expected_state
        );

        // Advancing the first one should not affect the second.
        block_tracker.block_processed(ingestable_range1.id, ingestable_range1.start_block);

        let expected_state = HashMap::from_iter(vec![(
            ingestable_range1.id,
            ingestable_range1.start_block + 1,
        )]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range1.clone()]),
            expected_state
        );

        let expected_state =
            HashMap::from_iter(vec![(ingestable_range2.id, ingestable_range2.start_block)]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range2.clone()]),
            expected_state
        );

        // Try with both.
        let expected_state = HashMap::from_iter(vec![
            (ingestable_range1.id, ingestable_range1.start_block + 1),
            (ingestable_range2.id, ingestable_range2.start_block),
        ]);

        assert_eq!(
            block_tracker.next_blocks(&[ingestable_range1.clone(), ingestable_range2.clone()]),
            expected_state
        );
    }

    // highest_fully_processed_block_count behaves as expected
    #[test_with_logger]
    fn highest_fully_processed_block_count_all_empty(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[], &[]),
            0
        );
    }

    // A missing range that doesn't start at block 0 should not affect the count.
    #[test_with_logger]
    fn highest_fully_processed_block_count_some_missing_blocks(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[], &[BlockRange::new(1, 10)]),
            0
        );
    }

    // A missing range that does start at block 0 should advance the count to the
    // end of the range.
    #[test_with_logger]
    fn highest_fully_processed_block_count_starts_with_missing_blocks(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[], &[BlockRange::new(0, 10)]),
            10
        );
    }

    // Multiple missing ranges are handled appropriately
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_missing1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                &[],
                &[BlockRange::new(0, 10), BlockRange::new(20, 30)]
            ),
            10
        );
    }

    // Multiple missing ranges are handled appropriately
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_missing2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                &[],
                &[
                    BlockRange::new(0, 10),
                    BlockRange::new(20, 30),
                    BlockRange::new(10, 20)
                ]
            ),
            30
        );
    }

    // Check with an ingestable range that hasn't yet processed anything.
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_nothing_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 0,
            decommissioned: false,
            last_ingested_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(&[ingestable_range], &[]),
            0
        );
    }

    // Check with an ingestable range that hasn't yet processed anything but has
    // missing blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_missing_blocks_consecutivie_nothing_processed2(
        logger: Logger,
    ) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 0,
            decommissioned: false,
            last_ingested_block: None,
        };

        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                &[ingestable_range],
                &[BlockRange::new(0, 10)]
            ),
            10
        );
    }

    // A block tracker with a single ingestable range tracks it properly as blocks
    // are processed when the start block is 0.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed1(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 0,
            decommissioned: false,
            last_ingested_block: None,
        };

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[ingestable_range.clone()], &[]),
                ingestable_range.start_block + i,
            );

            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[ingestable_range.clone()], &[]),
                ingestable_range.start_block + i + 1,
            );
        }
    }

    // A block tracker with a single ingestable range ignores it if the start block
    // is higher than 0.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_block_processed2(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 10,
            decommissioned: false,
            last_ingested_block: None,
        };

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[ingestable_range.clone()], &[]),
                0
            );

            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(&[ingestable_range.clone()], &[]),
                0,
            );
        }
    }

    // A block tracker with a single ingestable range respects missing ranges before
    // the processed blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_with_missing_blocks_before(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 10,
            decommissioned: false,
            last_ingested_block: None,
        };

        let missing_ranges = vec![BlockRange::new(0, ingestable_range.start_block)];

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range.clone()],
                    &missing_ranges
                ),
                ingestable_range.start_block + i,
            );

            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range.clone()],
                    &missing_ranges
                ),
                ingestable_range.start_block + i + 1,
            );
        }
    }

    // A block tracker with a single ingestable range respects missing ranges after
    // the processed blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_with_missing_blocks_after(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 0,
            decommissioned: false,
            last_ingested_block: None,
        };

        let missing_ranges = vec![
            BlockRange::new(10, 20),
            BlockRange::new(20, 30),
            BlockRange::new(32, 40), /* This range skips blocks 31 and 32 so we will not advance
                                      * automatically to them. */
        ];

        for i in 0..10 {
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range.clone()],
                    &missing_ranges
                ),
                ingestable_range.start_block + i,
            );

            block_tracker.block_processed(ingestable_range.id, ingestable_range.start_block + i);

            // The last iteration moves ahead due to the missed block ranges.
            if i == 9 {
                assert_eq!(
                    block_tracker.highest_fully_processed_block_count(
                        &[ingestable_range.clone()],
                        &missing_ranges
                    ),
                    30
                );
            } else {
                assert_eq!(
                    block_tracker.highest_fully_processed_block_count(
                        &[ingestable_range.clone()],
                        &missing_ranges
                    ),
                    ingestable_range.start_block + i + 1,
                );
            }
        }

        // Proccess blocks 10-29, this should not change anything since they were
        // reported as missing.
        for i in 10..30 {
            block_tracker.block_processed(ingestable_range.id, i);
            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range.clone()],
                    &missing_ranges
                ),
                30
            );
        }

        // Process block #30, this should get us to #31
        block_tracker.block_processed(ingestable_range.id, 30);
        assert_eq!(
            block_tracker
                .highest_fully_processed_block_count(&[ingestable_range.clone()], &missing_ranges),
            31
        );

        // Process block 31, this should get us to 40 (due to missed range)
        block_tracker.block_processed(ingestable_range.id, 31);
        assert_eq!(
            block_tracker
                .highest_fully_processed_block_count(&[ingestable_range.clone()], &missing_ranges),
            40
        );
    }

    // A block tracker with a multiple ingestable ranges waits for both of them.
    // blocks.
    #[test_with_logger]
    fn highest_fully_processed_block_tracks_multiple_ingestable_ranges(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger.clone());

        let ingestable_range1 = IngestableRange {
            id: IngestInvocationId::from(1),
            start_block: 0,
            decommissioned: false,
            last_ingested_block: None,
        };

        let ingestable_range2 = IngestableRange {
            id: IngestInvocationId::from(2),
            start_block: 10,
            decommissioned: false,
            last_ingested_block: None,
        };

        // Initially, we're at 0.
        assert_eq!(
            block_tracker.highest_fully_processed_block_count(
                &[ingestable_range1.clone(), ingestable_range2.clone()],
                &[]
            ),
            0
        );

        // Advancing the first ingestable range would only get us up to 10 since at that
        // point we also need the 2nd range to advance.
        for i in 0..20 {
            block_tracker.block_processed(ingestable_range1.id, i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range1.clone(), ingestable_range2.clone()],
                    &[]
                ),
                min(ingestable_range2.start_block, i + 1),
            );
        }

        // Advancing the second range would get us all the way to the first one and stop
        // there.
        for i in 0..40 {
            block_tracker.block_processed(ingestable_range2.id, ingestable_range2.start_block + i);

            assert_eq!(
                block_tracker.highest_fully_processed_block_count(
                    &[ingestable_range1.clone(), ingestable_range2.clone()],
                    &[]
                ),
                min(
                    ingestable_range1.start_block + 20, /* We advanced the first range 20 times
                                                         * in the previous loop */
                    ingestable_range2.start_block + i + 1
                ),
            );
        }
    }

    // Higehst known block count is 0 when there are no inputs.
    #[test_with_logger]
    fn highest_known_block_count_when_empty(logger: Logger) {
        let block_tracker = BlockTracker::new(logger);

        assert_eq!(block_tracker.highest_known_block_count(), 0);
    }

    // Highest known block count is set to the highest block count that was
    // processed.
    #[test_with_logger]
    fn highest_known_block_count_tracks_processed(logger: Logger) {
        let mut block_tracker = BlockTracker::new(logger);

        block_tracker.block_processed(IngestInvocationId::from(1), 100);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(IngestInvocationId::from(2), 80);
        assert_eq!(block_tracker.highest_known_block_count(), 101);

        block_tracker.block_processed(IngestInvocationId::from(3), 101);
        assert_eq!(block_tracker.highest_known_block_count(), 102);
    }
}
