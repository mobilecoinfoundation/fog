// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_metrics::{IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_ledger");

    // Ledger enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");
}
