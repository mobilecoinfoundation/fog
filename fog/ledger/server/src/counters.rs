// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
          pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_ledger");

          // Ledger enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
          pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");

          // Number of blocks loaded since startup.
          pub static ref BLOCKS_LOADED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_loaded_count");
          // Number of blocks fetched (from the database) since startup.
          pub static ref BLOCKS_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_fetched_count");

          // Number of blocks added (to the enclave) since startup.
          pub static ref BLOCKS_ADDED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_added_count");

           // Time it takes to perform the enclave add_records call.
           pub static ref ENCLAVE_ADD_RECORDS_TIME: Histogram = OP_COUNTERS.histogram("enclave_add_records_time");

          // Number of records currently in the db fetcher fetched_records queue.
          pub static ref DB_FETCHER_NUM_QUEUED_RECORDS: IntGauge = OP_COUNTERS.gauge("db_fetcher_num_queued_records");

            // Time it takes to perform the load_missing_block_ranges call.
          pub static ref LOAD_MISSING_BLOCK_RANGES_TIME: Histogram = OP_COUNTERS.histogram("load_missing_block_ranges_time");

           // Time it take to perform the db get_key_images_by_block call.
           pub static ref GET_KEY_IMAGES_BY_BLOCK_TIME: Histogram = OP_COUNTERS.histogram("get_key_images_by_block_time");

               // Number of blocks fetched (from the database) since startup.
            pub static ref KEYIMAGES_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("keyimages_fetched_count");
}
