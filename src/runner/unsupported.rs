use crate::config::SandboxSpec;
use crate::report::{EnvReport, RunReport};
use serde_json::json;
use std::collections::BTreeMap;

pub fn run(_spec: SandboxSpec) -> anyhow::Result<RunReport> {
    Err(anyhow::anyhow!(
        "shadox run is Linux-only; use WSL2 or a Linux host for sandbox execution"
    ))
}

pub fn check_env() -> EnvReport {
    let mut details = BTreeMap::new();
    details.insert(
        "reason".to_string(),
        json!("sandbox primitives require Linux procfs, prctl, rlimit, Landlock, and seccomp"),
    );
    EnvReport {
        platform: std::env::consts::OS.to_string(),
        supported: false,
        details,
    }
}
