use crate::trace::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceUsage {
    pub user_cpu_ms: Option<u64>,
    pub system_cpu_ms: Option<u64>,
    pub max_rss_kb: Option<i64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: Uuid,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub trace_path: String,
    pub summary_path: PathBuf,
    pub resources: ResourceUsage,
    #[serde(default)]
    pub denials: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvReport {
    pub platform: String,
    pub supported: bool,
    pub details: BTreeMap<String, serde_json::Value>,
}
