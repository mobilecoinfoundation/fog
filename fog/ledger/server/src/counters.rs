// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_metrics::{IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
          pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_ledger");
          // Ledger enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
          pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");
          // Number of blocks added (to the enclave) since startup.
          pub static ref BLOCKS_ADDED_COUNT: IntCounter = OP_COUNTERS.counter("blocks_added_count");
          // Number of keyimages fetched (from the database) since startup.
          pub static ref KEYIMAGES_FETCHED_COUNT: IntCounter = OP_COUNTERS.counter("keyimages_fetched_count");
}
