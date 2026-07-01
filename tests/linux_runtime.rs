#![cfg(target_os = "linux")]

use serde_json::Value;
use shadox::WorkspaceStore;
use shadox::config::{
    LimitsSpec, ObserveSpec, ProcessSpec, SandboxProfile, SandboxSpec, SeccompProfile,
    SecuritySpec, VersionedWorkspaceSpec,
};
use shadox::report::FailureKind;
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

#[test]
fn versioned_workspace_commits_successful_run() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("a.txt"), "one").unwrap();

    let report = Runner::run(versioned_workspace_spec(
        &workspace,
        dir.path(),
        "printf two > \"$1/a.txt\"",
        true,
        false,
    ))
    .unwrap();

    let fs = report.fs.expect("versioned workspace report");
    assert_eq!(report.failure.kind, FailureKind::Success);
    assert_eq!(
        std::fs::read_to_string(workspace.join("a.txt")).unwrap(),
        "two"
    );
    assert!(fs.committed);
    assert!(!fs.rolled_back);
    assert_eq!(fs.changed_files, 1);
    assert!(fs.journal_path.is_file());

    let store = WorkspaceStore::open(&workspace).unwrap();
    assert_eq!(store.head().unwrap(), Some(fs.checkpoint_after));
}

#[test]
fn versioned_workspace_rolls_back_failed_run() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("a.txt"), "one").unwrap();

    let report = Runner::run(versioned_workspace_spec(
        &workspace,
        dir.path(),
        "printf bad > \"$1/a.txt\"; exit 7",
        false,
        true,
    ))
    .unwrap();

    let fs = report.fs.expect("versioned workspace report");
    assert_eq!(report.exit_code, Some(7));
    assert_eq!(report.failure.kind, FailureKind::ExitNonZero);
    assert_eq!(
        std::fs::read_to_string(workspace.join("a.txt")).unwrap(),
        "one"
    );
    assert!(!fs.committed);
    assert!(fs.rolled_back);
    assert!(fs.rollback.is_some());
    assert_eq!(fs.changed_files, 1);
    assert!(fs.journal_path.is_file());
}

fn versioned_workspace_spec(
    workspace: &Path,
    output_dir: &Path,
    shell_script: &str,
    commit_on_success: bool,
    rollback_on_failure: bool,
) -> SandboxSpec {
    SandboxSpec {
        profile: SandboxProfile::PermissiveObserve,
        security: SecuritySpec {
            landlock: false,
            seccomp_profile: SeccompProfile::Off,
            ..SecuritySpec::default()
        },
        observe: ObserveSpec {
            trace: Some(output_dir.join("trace.jsonl").to_string_lossy().to_string()),
            summary: Some(output_dir.join("summary.json")),
            ..ObserveSpec::default()
        },
        process: ProcessSpec {
            cmd: Some("/bin/sh".into()),
            args: vec![
                "-c".to_string(),
                shell_script.to_string(),
                "versioned-workspace-test".to_string(),
                workspace.to_string_lossy().to_string(),
            ],
            ..ProcessSpec::default()
        },
        versioned_workspace: VersionedWorkspaceSpec {
            workspace: Some(workspace.to_path_buf()),
            rollback_on_failure,
            commit_on_success,
        },
        ..SandboxSpec::default()
    }
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
