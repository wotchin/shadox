#![cfg(target_os = "linux")]

use serde_json::Value;
use shadox::config::{
    LimitsSpec, ObserveSpec, ProcessSpec, SandboxProfile, SandboxSpec, SeccompProfile, SecuritySpec,
};
use shadox::runner::Runner;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

#[test]
fn trace_stdout_is_jsonl_only() {
    let dir = tempdir().unwrap();
    let summary = dir.path().join("summary.json");
    let output = Command::new(env!("CARGO_BIN_EXE_shadox"))
        .args([
            "run",
            "--profile",
            "permissive-observe",
            "--no-landlock",
            "--seccomp-profile",
            "off",
            "--trace",
            "-",
            "--summary",
            summary.to_str().unwrap(),
            "--",
            "/bin/echo",
            "hello",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.trim().is_empty());
    let mut saw_summary = false;
    for line in stdout.lines() {
        let value: Value = serde_json::from_str(line).expect("stdout line should be JSON");
        assert!(value["kind"].is_string(), "missing event kind in {value}");
        saw_summary |= value["kind"] == "run.summary";
    }
    assert!(saw_summary, "trace stream should include run.summary");
}

#[test]
fn timeout_kills_detached_descendant() {
    let dir = tempdir().unwrap();
    let pidfile = dir.path().join("detached.pid");
    let trace = dir.path().join("trace.jsonl");
    let summary = dir.path().join("summary.json");

    let spec = SandboxSpec {
        profile: SandboxProfile::PermissiveObserve,
        security: SecuritySpec {
            landlock: false,
            seccomp_profile: SeccompProfile::Off,
            ..SecuritySpec::default()
        },
        limits: LimitsSpec {
            timeout_ms: Some(500),
            ..LimitsSpec::default()
        },
        observe: ObserveSpec {
            trace: Some(trace.to_string_lossy().to_string()),
            summary: Some(summary),
            ..ObserveSpec::default()
        },
        process: ProcessSpec {
            cmd: Some("/bin/sh".into()),
            args: vec![
                "-c".to_string(),
                concat!(
                    "setsid sh -c 'echo $$ > \"$1\"; sleep 30' child \"$1\" & ",
                    "while [ ! -s \"$1\" ]; do sleep 0.01; done; ",
                    "sleep 30"
                )
                .to_string(),
                "outer".to_string(),
                pidfile.to_string_lossy().to_string(),
            ],
            ..ProcessSpec::default()
        },
        ..SandboxSpec::default()
    };

    let report = Runner::run(spec).unwrap();
    assert!(report.timed_out);

    let detached_pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_process_exits(detached_pid);
}

fn assert_process_exits(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !process_is_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("process {pid} was still alive after timeout cleanup");
}

fn process_is_alive(pid: u32) -> bool {
    let stat_path = format!("/proc/{pid}/stat");
    let Ok(stat) = std::fs::read_to_string(Path::new(&stat_path)) else {
        return false;
    };
    let Some(end) = stat.rfind(')') else {
        return true;
    };
    let state = stat[end + 1..].split_whitespace().next();
    state != Some("Z")
}
