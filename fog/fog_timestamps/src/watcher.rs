// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::{log, Logger};
use mc_transaction_core::BlockIndex;
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::time::{Duration, Instant};

/// Poll for new data every 10 ms
const POLLING_FREQUENCY: Duration = Duration::from_millis(10);
/// If a database invariant is violated, e.g. we get block but not block
/// contents, it typically will not be fixed and so we won't be able to
/// proceed. But bringing the server down is costly from ops POV because
/// we will lose all the user rng's.
///
/// So instead, if this happens, we log an error, and retry in 1s.
/// This avoids logging at > 1hz when there is this error, which would be
/// very spammy. But the retries are unlikely to eventually lead to
/// progress. Another strategy might be for the server to enter a
/// "paused" state and signal for intervention.
const ERROR_RETRY_FREQUENCY: Duration = Duration::from_millis(1000);

// Get the timestamp from the watcher, or an error code,
// using retries if the watcher fell behind
pub fn get_watcher_timestamp(
    block_index: BlockIndex,
    watcher: &WatcherDB,
    watcher_timeout: Duration,
    logger: &Logger,
) -> u64 {
    // Timer that tracks how long we have had WatcherBehind error for,
    // if this exceeds watcher_timeout, we log a warning.
    let mut watcher_behind_timer = Instant::now();
    loop {
        match watcher.get_block_timestamp(block_index) {
            Ok((ts, res)) => match res {
                TimestampResultCode::WatcherBehind => {
                    if watcher_behind_timer.elapsed() > watcher_timeout {
                        log::warn!(logger, "watcher is still behind on block index = {} after waiting {} seconds, ingest will be blocked", block_index, watcher_timeout.as_secs());
                        watcher_behind_timer = Instant::now();
                    }
                    std::thread::sleep(POLLING_FREQUENCY);
                }
                TimestampResultCode::BlockIndexOutOfBounds => {
                    log::warn!(logger, "block index {} was out of bounds, we should not be scanning it, we will have junk timestamps for it", block_index);
                    return u64::MAX;
                }
                TimestampResultCode::Unavailable => {
                    log::crit!(logger, "watcher configuration is wrong and timestamps will not be available with this configuration. Ingest is blocked at block index {}", block_index);
                    std::thread::sleep(ERROR_RETRY_FREQUENCY);
                }
                TimestampResultCode::WatcherDatabaseError => {
                    log::crit!(logger, "The watcher database has an error which prevents us from getting timestamps. Ingest is blocked at block index {}", block_index);
                    std::thread::sleep(ERROR_RETRY_FREQUENCY);
                }
                TimestampResultCode::TimestampFound => {
                    return ts;
                }
            },
            Err(err) => {
                log::error!(
                        logger,
                        "Could not obtain timestamp for block {} due to error {}, this may mean the watcher is not correctly configured. will retry",
                        block_index,
                        err
                    );
                std::thread::sleep(ERROR_RETRY_FREQUENCY);
            }
        };
    }
}
