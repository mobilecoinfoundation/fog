// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A background thread, in the server side, that continuously checks the LedgerDB for new blocks, then gets all the key images associated to those blocks and adds them to the enclave.
#![allow(unused)]
use crate::{block_tracker::BlockTracker, counters};
use mc_ledger_db::{self, Error as DbError, Ledger};
use fog_api::fog_common::BlockRange;
use fog_api::ledger::KeyImageQuery;
use mc_common::logger::{log, Logger};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

/// Time to wait between database fetch attempts.
pub const DB_POLL_INTERNAL: Duration = Duration::from_millis(100);

/// Approximate maximum number of KeyImages we will collect inside
/// fetched_records before blocking and waiting for the enclave thread to pick
/// them up. Since DB fetching is significantlly faster than enclave insertion
/// we need a mechanism that prevents fetched_records from growing indefinitely.
/// This essentially caps the memory usage of the fetched_records array.
/// Assuming each KeyImage is <256 bytes, this gives a worst case scenario
/// of 128MB.
pub const MAX_QUEUED_RECORDS: usize = (128 * 1024 * 1024) / 256; // may not need queued record

/// A single block of fetched KeyImages, together with information
/// identifying where it came from.
pub struct FetchedRecords {
    /// The block index the KeyImages belong to.
    pub block_index: u64,

    /// The records got from the ledger db.
    pub records: Vec<mc_transaction_core::ring_signature::KeyImage>,
}

/// Container for data that is shared between the worker thread and the holder
/// of the DbFetcher object.
#[derive(Default)]
struct DbFetcherSharedState {
    /// Missing block ranges we are aware of.
    missing_block_ranges: Vec<BlockRange>,

    /// A queue of KeyImages we have fetched from the database.
    /// This is periodically polled by an external thread which grabs this data
    /// and feeds it into the enclave.
    /// The queue is limited to approximately MAX_QUEUED_RECORDS KeyImages
    /// total.
    fetched_records: Vec<FetchedRecords>,
}

/// An object for managing background data fetches from the ledger database.
pub struct DbFetcher {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,

    /// State shared with the worker thread.
    shared_state: Arc<Mutex<DbFetcherSharedState>>,

    /// A tuple containing a mutex that holds the number of KeyImages we
    /// have queued inside fetched_records so far, and a condition variable
    /// to signal when the count resets to zero.
    num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
}

impl DbFetcher {
    pub fn new<DB: Ledger + Clone + Send + Sync + 'static>(db: DB, logger: Logger) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));

        let shared_state = Arc::new(Mutex::new(DbFetcherSharedState::default()));

        // Clippy suggests to use AtomicUSize but we need a mutex for the conditional
        // variable.
        #[allow(clippy::mutex_atomic)]
        let num_queued_records_limiter = Arc::new((Mutex::new(0), Condvar::new()));

        let thread_stop_requested = stop_requested.clone();
        let thread_shared_state = shared_state.clone();
        let thread_num_queued_records_limiter = num_queued_records_limiter.clone();
        let join_handle = Some(
            ThreadBuilder::new()
                .name("ViewDbFetcher".to_owned())
                .spawn(move || {
                    DbFetcherThread::start(
                        db,
                        thread_stop_requested,
                        thread_shared_state,
                        thread_num_queued_records_limiter,
                        logger,
                    )
                })
                .expect("Could not spawn thread"),
        );

        Self {
            join_handle,
            stop_requested,
            shared_state,
            num_queued_records_limiter,
        }
    }

    /// Stop and join the db poll thread
    pub fn stop(&mut self) -> Result<(), ()> {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_requested.store(true, Ordering::SeqCst);
            join_handle.join().map_err(|_| ())?;
        }

        Ok(())
    }

   
   /// Get a copy of the currently known missing block ranges.
   /// This updates over time by the background worker thread.
   pub fn known_missing_block_ranges(&self) -> Vec<BlockRange> {
            self.shared_state().missing_block_ranges.clone()
      }

    /// Get the list of FetchedRecords that were obtained by the worker thread.
    /// This also clears the queue so that more records could be fetched by
    /// the worker thread. This updates over time by the background worker
    /// thread.
    pub fn get_pending_fetched_records(&self) -> Vec<FetchedRecords> {
        // First grab all the records queued so far.
        let records = self.shared_state().fetched_records.split_off(0);

        // Now, signal the condition variable that the queue has been drained.
        let (lock, condvar) = &*self.num_queued_records_limiter;
        let mut num_queued_records = lock.lock().expect("mutex poisoned");
        *num_queued_records = 0;

        counters::DB_FETCHER_NUM_QUEUED_RECORDS.set(0);

        condvar.notify_one();

        // Return the records
        records
    }

    /// Get a locked reference to the shared state.
    fn shared_state(&self) -> MutexGuard<DbFetcherSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}

impl Drop for DbFetcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DbFetcherThread<DB: Ledger + Clone + Send + Sync + 'static> {
    db: DB,
    stop_requested: Arc<AtomicBool>,
    shared_state: Arc<Mutex<DbFetcherSharedState>>,
    block_tracker: BlockTracker,
    num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
    logger: Logger,
}

/// Background worker thread implementation that takes care of periodically
/// polling data out of the database.
impl<DB: Ledger + Clone + Send + Sync + 'static> DbFetcherThread<DB> {
    pub fn start(
        db: DB,
        stop_requested: Arc<AtomicBool>,
        shared_state: Arc<Mutex<DbFetcherSharedState>>,
        num_queued_records_limiter: Arc<(Mutex<usize>, Condvar)>,
        logger: Logger,
    ) {
        let thread = Self {
            db,
            stop_requested,
            shared_state,
            block_tracker: BlockTracker::new(logger.clone()),
            num_queued_records_limiter,
            logger,
        };
        thread.run();
    }

    fn run(mut self) {
        log::info!(self.logger, "Db fetcher thread started.");
        loop {
            if self.stop_requested.load(Ordering::SeqCst) {
                log::info!(self.logger, "Db fetcher thread stop requested.");
                break;
            }

            // Each call to load_block_data attempts to load one block for each known
            // invocation. We want to keep loading blocks as long as we have data to load,
            // but that could take some time which is why the loop is also gated
            // on the stop trigger in case a stop is requested during loading.
            while self.load_block_data() && !self.stop_requested.load(Ordering::SeqCst) {}

            sleep(DB_POLL_INTERNAL);
        }
    }

    /// Attempt to load the next block for each of the ledger db invocations we are
    /// aware of and tracking.
    /// Returns true if we might have more block data to load.
    fn load_block_data(&mut self) -> bool {
        let mut has_more_work = false;

        // See whats the next block number we need to load for each invocation we are aware of.
        let missing_block_ranges = {
              let shared_state = self.shared_state();
               (
                  shared_state.missing_block_ranges.clone(),
              )
          };

          let next_block_index_per_invocation_id = self.block_tracker.next_blocks(&missing_block_ranges);
          
                log::trace!(
                    self.logger,
                      "load_block_data next_blocks: {:?}",
                      next_block_index_per_invocation_id
                  );

                  for (ingest_invocation_id, block_index) in next_block_index_per_invocation_id.into_iter() {
                             
                                // This ensures we do not have holes in the blocks processed by the enclave thread.
                                self.shared_state().fetched_records.push(FetchedRecords {
                                    block_index,
                                    records: vec![],
                                });
                                  
                                // Attempt to load data for the next block.
                                let get_key_images_by_block_result = {
                                    let _metrics_timer = counters::GET_KEY_IMAGES_BY_BLOCK_TIME.start_timer();
                                    self.db
                                        .get_key_images_by_block(block_index)
                                };
                    
                                match get_key_images_by_block_result {
                                    Ok(keyimage_outs) => {
                                        let num_keyimage_outs = keyimage_outs.len();
                    
                                        // NOTE: This makes a very nuanced and important assumption, which is that
                                        // always produces data KeyImage Records for each block it has processed,
                                        // EVEN if it actually found NO matches.
                                        // Based on that assumption, keyimage_outs will be empty only when it has not yet
                                        // createdd the block (and wrote the results into the database).
                                        if !keyimage_outs.is_empty() {
                                            // Log
                                            log::info!(
                                                self.logger,
                                                "invocation id {} fetched {} keyimage outs for block {}",
                                                ingest_invocation_id,
                                                num_keyimage_outs,
                                                block_index,
                                            );
                    
                                            // Ingest has produced data for this block, we'd like to keep trying the
                                            // next block on the next loop iteration.
                                            has_more_work = true;
                                   
                                            // Store the fetched records so that they could be consumed by the enclave
                                            // when its ready.
                                            self.shared_state().fetched_records.push(FetchedRecords {
                                                block_index,
                                                records: keyimage_outs,
                                            });
                    
                                            // Update metrics.
                                            counters::BLOCKS_FETCHED_COUNT.inc();
                                            counters::KEYIMAGES_FETCHED_COUNT.inc_by(num_keyimage_outs as i64);
                    
                                            // Block if we have queued up enough records for now.
                                            // (Until the enclave thread drains the queue).
                                            let (lock, condvar) = &*self.num_queued_records_limiter;
                                            let mut num_queued_records = condvar
                                                .wait_while(lock.lock().unwrap(), |num_queued_records| {
                                                    *num_queued_records > MAX_QUEUED_RECORDS
                                                })
                                                .expect("condvar wait failed");
                                            *num_queued_records += num_keyimage_outs;
                    
                                            counters::DB_FETCHER_NUM_QUEUED_RECORDS.set(*num_queued_records as i64);
                                        } else {
                                            log::trace!(
                                                self.logger,
                                                "invocation id {} fetched {} tx outs for block {}",
                                                ingest_invocation_id,
                                                num_keyimage_outs,
                                                block_index,
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        log::warn!(
                                            self.logger,
                                            "Failed querying keyimage outs for {}/{}: {}",
                                            ingest_invocation_id,
                                            block_index,
                                            err
                                        );
                                    }
                                }
                            }
                    
                            has_more_work
                        }
                    
                        fn shared_state(&self) -> MutexGuard<DbFetcherSharedState> {
                            self.shared_state.lock().expect("mutex poisoned")
                        }
}