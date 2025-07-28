//! Utility module for serde of types.

pub mod generic_hashmap;

use serde::{Deserialize, Serialize};

/// Struct used to (de-)serialize BGPseer's `Analyzer` collected data for a single sample ran on
/// hardware
#[derive(Debug, Deserialize, Serialize)]
#[allow(unused)]
pub struct CiscoAnalyzerData {
    /// Human-readable formatted timestamp when the sample was taken (starting time)
    pub execution_timestamp: String,
    /// Overall duration of this sample, including setup and teardown (excluding the initial connection and setup time shared for multiple samples)
    pub execution_duration: f64,
    /// Timestamp when the violation was introduced (e.g. the respective BGP message was sent)
    pub event_start: f64,
    /// Filename of the saved prober_results
    pub prober_result_filename: String,
    /// Filename of the saved pcap
    pub pcap_filename: String,
    /// Rate in \[pps\] used for generating prober packets during the experiment
    #[serde(default = "_one_thousand_u64")]
    pub capture_frequency: u64,
    /// Filename of the saved `HardwareMapping`
    pub hardware_mapping_filename: String,
    #[serde(default)]
    pub packets_dropped: usize,
}

const fn _one_thousand_u64() -> u64 {
    1_000
}
