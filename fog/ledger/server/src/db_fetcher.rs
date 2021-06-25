// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A background thread, in the server side, that continuously checks the
//! LedgerDB for new blocks, then gets all the key images associated to those
//! blocks and adds them to the enclave.
#![allow(unused)]
use crate::{block_tracker::BlockTracker, counters};
use fog_api::{fog_common::BlockRange, ledger::KeyImageQuery};
use mc_common::logger::{log, Logger};
use mc_ledger_db::{self, Error as DbError, Ledger};
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
                .name("LedgerDbFetcher".to_owned())
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
/// polling data out of the database. Add join handle
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

    /// Attempt to load the next block for each of the ledger db invocations we
    /// are aware of and tracking.
    /// Returns true if we might have more block data to load.
    fn load_block_data(&mut self) -> bool {
        let mut has_more_work = false;

          // Grab whatever fetched records have shown up since the last time we ran.
          let fetched_records_list = self.db_fetcher.get_pending_fetched_records();
          for fetched_records in fetched_records_list.into_iter() {
              // Early exit if stop as requested.
              if self.stop_requested.load(Ordering::SeqCst) {
                  mut has_more_work = true;
                  break;
              }

              // Insert the records into the enclave.
              self.add_records_to_enclave(
                  fetched_records.block_index,
                  fetched_records.records,
              );
          }

        has_more_work
    }

    fn add_records_to_enclave(
        &mut self,
        block_index: u64,
        records: Vec<KeyImageOutRecord>,
    ) {
        let num_records = records.len();

        let add_records_result = {
            trace_time!(
                self.logger,
                "Added {} records into the enclave",
                num_records
            );
            let _metrics_timer = counters::ENCLAVE_ADD_RECORDS_TIME.start_timer();
            self.enclave.add_key_image_data(records)
        };

        match add_records_result {
            Err(err) => {
                // Failing to add records to the enclave is unrecoverable,
                // When we encounter this failure mode we will begin logging a high-priority log
                // message every ten minutes indefinitely.
                loop {
                    log::crit!(
                        self.logger,
                        "Failed adding {} keyimage_outs for {} into enclave: {}",
                        num_records,
                        block_index,
                        err
                    );
                    sleep(Duration::from_secs(600));
                }
            }

            Ok(_) => {
                log::info!(
                    self.logger,
                    "Added {} keyimage outs for {} into the enclave",
                    num_records,
                    block_index
                );

                // Update metrics
                counters::BLOCKS_ADDED_COUNT.inc();
                counters::KEYIMAGES_FETCHED_COUNT.inc_by(num_records as i64);
            }
        }
    }

    fn shared_state(&self) -> MutexGuard<DbFetcherSharedState> {
        self.shared_state.lock().expect("mutex poisoned")
    }
}
