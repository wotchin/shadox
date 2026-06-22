use crate::trace::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Success,
    Timeout,
    SeccompDenied,
    LandlockDenied,
    OomLike,
    Signal,
    ExitNonZero,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureClassification {
    pub kind: FailureKind,
    pub confidence: Confidence,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl FailureClassification {
    pub fn success() -> Self {
        Self {
            kind: FailureKind::Success,
            confidence: Confidence::High,
            reason: "process exited successfully".to_string(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputReport {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CgroupStats {
    pub path: Option<PathBuf>,
    pub cpu_usage_usec: Option<u64>,
    pub cpu_user_usec: Option<u64>,
    pub cpu_system_usec: Option<u64>,
    pub memory_current_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    #[serde(default)]
    pub memory_events: BTreeMap<String, u64>,
    #[serde(default)]
    pub memory_events_delta: BTreeMap<String, i64>,
    pub pids_current: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceUsage {
    pub user_cpu_ms: Option<u64>,
    pub system_cpu_ms: Option<u64>,
    pub max_rss_kb: Option<i64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub cgroup: Option<CgroupStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticHint {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub action: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub schema_version: u32,
    pub shadox_version: String,
    pub profile: String,
    pub profile_version: u32,
    pub run_id: Uuid,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub trace_path: String,
    pub summary_path: PathBuf,
    pub resources: ResourceUsage,
    pub output: OutputReport,
    pub failure: FailureClassification,
    #[serde(default)]
    pub denials: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub hints: Vec<DiagnosticHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvReport {
    pub platform: String,
    pub supported: bool,
    pub details: BTreeMap<String, serde_json::Value>,
}
