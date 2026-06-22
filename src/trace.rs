use crate::observer::Observer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub message: String,
    pub severity: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub schema_version: u32,
    pub shadox_version: String,
    pub profile: String,
    pub profile_version: u32,
    pub ts: u128,
    pub seq: u64,
    pub run_id: Uuid,
    pub kind: String,
    pub pid: Option<u32>,
    pub level: String,
    pub data: Value,
}

impl TraceEvent {
    pub fn new(
        seq: u64,
        run_id: Uuid,
        kind: impl Into<String>,
        pid: Option<u32>,
        level: impl Into<String>,
        data: Value,
    ) -> Self {
        Self::with_context(
            &TraceContext::default(),
            seq,
            run_id,
            kind,
            pid,
            level,
            data,
        )
    }

    pub fn with_context(
        context: &TraceContext,
        seq: u64,
        run_id: Uuid,
        kind: impl Into<String>,
        pid: Option<u32>,
        level: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            schema_version: context.schema_version,
            shadox_version: context.shadox_version.clone(),
            profile: context.profile.clone(),
            profile_version: context.profile_version,
            ts: epoch_millis(),
            seq,
            run_id,
            kind: kind.into(),
            pid,
            level: level.into(),
            data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceContext {
    pub schema_version: u32,
    pub shadox_version: String,
    pub profile: String,
    pub profile_version: u32,
}

impl TraceContext {
    pub fn new(profile: impl Into<String>, profile_version: u32) -> Self {
        Self {
            schema_version: crate::metadata::SCHEMA_VERSION,
            shadox_version: crate::metadata::SHADOX_VERSION.to_string(),
            profile: profile.into(),
            profile_version,
        }
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new("agent-default", crate::metadata::PROFILE_VERSION)
    }
}

pub struct TraceLogger {
    state: Mutex<TraceState>,
}

struct TraceState {
    context: TraceContext,
    run_id: Uuid,
    seq: u64,
    writer: Box<dyn Write + Send>,
    observer: Option<Observer>,
    findings: Vec<Finding>,
}

impl TraceLogger {
    pub fn new(run_id: Uuid, trace: &str, observer: Option<Observer>) -> anyhow::Result<Self> {
        Self::new_with_context(run_id, trace, observer, TraceContext::default())
    }

    pub fn new_with_context(
        run_id: Uuid,
        trace: &str,
        observer: Option<Observer>,
        context: TraceContext,
    ) -> anyhow::Result<Self> {
        let writer: Box<dyn Write + Send> = if trace == "-" {
            Box::new(BufWriter::new(io::stdout()))
        } else {
            let path = Path::new(trace);
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            Box::new(BufWriter::new(File::create(path)?))
        };

        Ok(Self {
            state: Mutex::new(TraceState {
                context,
                run_id,
                seq: 0,
                writer,
                observer,
                findings: Vec::new(),
            }),
        })
    }

    pub fn emit(
        &self,
        kind: impl Into<String>,
        pid: Option<u32>,
        level: impl Into<String>,
        data: Value,
    ) -> anyhow::Result<()> {
        self.emit_inner(kind.into(), pid, level.into(), data, true)
    }

    pub fn findings(&self) -> Vec<Finding> {
        self.state
            .lock()
            .expect("trace state poisoned")
            .findings
            .clone()
    }

    fn emit_inner(
        &self,
        kind: String,
        pid: Option<u32>,
        level: String,
        data: Value,
        run_observer: bool,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().expect("trace state poisoned");
        state.seq += 1;
        let event = TraceEvent::with_context(
            &state.context,
            state.seq,
            state.run_id,
            kind,
            pid,
            level,
            data,
        );
        serde_json::to_writer(&mut state.writer, &event)?;
        state.writer.write_all(b"\n")?;
        state.writer.flush()?;

        if run_observer && let Some(observer) = state.observer.as_mut() {
            let findings = observer.on_event(&event)?;
            for finding in findings {
                state.findings.push(finding.clone());
                state.seq += 1;
                let event = TraceEvent::with_context(
                    &state.context,
                    state.seq,
                    state.run_id,
                    "observer.finding",
                    pid,
                    finding.severity.clone(),
                    json!({
                        "message": finding.message,
                        "severity": finding.severity,
                        "tags": finding.tags,
                    }),
                );
                serde_json::to_writer(&mut state.writer, &event)?;
                state.writer.write_all(b"\n")?;
                state.writer.flush()?;
            }
        }

        Ok(())
    }
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
