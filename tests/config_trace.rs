use serde_json::json;
use shadox::config::{SandboxProfile, SandboxSpec, SeccompProfile};
use shadox::observer::Observer;
use shadox::report::{
    Confidence, FailureClassification, FailureKind, OutputReport, ResourceUsage, RunReport,
};
use shadox::runner::Runner;
use shadox::trace::{TraceEvent, TraceLogger};
use std::path::PathBuf;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn parses_toml_config_with_defaults() {
    let config = r#"
        [process]
        cmd = "/bin/echo"
        args = ["hello"]

        [security]
        seccomp_profile = "basic"
    "#;

    let spec: SandboxSpec = toml::from_str(config).unwrap();
    assert_eq!(spec.process.cmd.unwrap().to_string_lossy(), "/bin/echo");
    assert_eq!(spec.process.args, vec!["hello"]);
    assert!(spec.security.no_new_privs);
    assert!(spec.security.landlock);
    assert_eq!(spec.security.seccomp_profile, SeccompProfile::Basic);
    assert!(spec.observe.capture_stdout);
    assert!(spec.observe.collect_cgroup);
    assert_eq!(spec.profile, SandboxProfile::AgentDefault);
}

#[test]
fn effective_profiles_are_agent_native_and_narrow() {
    let spec = SandboxSpec::default();
    let policy = spec.effective_policy();
    assert_eq!(policy.profile, SandboxProfile::AgentDefault);
    assert_eq!(policy.fs.write, vec![PathBuf::from(".")]);

    let mut read_only = SandboxSpec {
        profile: SandboxProfile::ReadOnly,
        ..SandboxSpec::default()
    };
    read_only.fs.read.push(PathBuf::from("/usr/bin"));
    let policy = read_only.effective_policy();
    assert!(policy.fs.write.is_empty());
    assert_eq!(policy.fs.read, vec![PathBuf::from("/usr/bin")]);

    let permissive = SandboxSpec {
        profile: SandboxProfile::PermissiveObserve,
        ..SandboxSpec::default()
    };
    assert!(!permissive.effective_policy().security.landlock);
}

#[test]
fn trace_logger_writes_jsonl_and_observer_finding() {
    let dir = tempdir().unwrap();
    let trace = dir.path().join("trace.jsonl");
    let observer = Observer::from_source(
        r#"
            fn on_event(event) {
                if event.kind == "stderr.chunk" {
                    return #{ message: "stderr seen", severity: "warn", tags: ["stderr"] };
                }
            }
        "#,
    )
    .unwrap();
    let logger = TraceLogger::new(
        Uuid::nil(),
        trace.to_string_lossy().as_ref(),
        Some(observer),
    )
    .unwrap();
    logger
        .emit("stderr.chunk", Some(7), "info", json!({ "text": "oops" }))
        .unwrap();

    let text = std::fs::read_to_string(trace).unwrap();
    assert!(text.contains("\"schema_version\":1"));
    assert!(text.contains("\"profile\":\"agent-default\""));
    assert!(text.contains("\"kind\":\"stderr.chunk\""));
    assert!(text.contains("\"kind\":\"observer.finding\""));
    assert_eq!(logger.findings()[0].message, "stderr seen");
}

#[test]
fn observer_accepts_string_findings() {
    let mut observer = Observer::from_source(r#"fn on_event(event) { return "hello"; }"#).unwrap();
    let event = TraceEvent::new(1, Uuid::nil(), "run.start", None, "info", json!({}));
    let findings = observer.on_event(&event).unwrap();
    assert_eq!(findings[0].message, "hello");
}

#[test]
fn explain_basic_profile_is_stable() {
    let value = Runner::explain(&SandboxSpec::default());
    let blocked = value["seccomp"]["blocked_syscalls"].as_array().unwrap();
    assert!(blocked.iter().any(|item| item == "ptrace"));
    assert_eq!(value["profile"], "agent-default");
    assert_eq!(value["seccomp"]["seccomp_profile"], "basic");
    assert_eq!(value["effective_policy"]["profile"], "agent-default");
}

#[test]
fn run_report_schema_contains_observability_plus_fields() {
    let report = RunReport {
        schema_version: 1,
        shadox_version: "0.1.0".to_string(),
        profile: "agent-default".to_string(),
        profile_version: 1,
        run_id: Uuid::nil(),
        command: vec!["echo".to_string(), "hello".to_string()],
        exit_code: Some(0),
        signal: None,
        timed_out: false,
        duration_ms: 7,
        trace_path: "-".to_string(),
        summary_path: PathBuf::from("summary.json"),
        resources: ResourceUsage::default(),
        output: OutputReport {
            stdout_bytes: 6,
            stdout_tail: "hello\n".to_string(),
            ..OutputReport::default()
        },
        failure: FailureClassification {
            kind: FailureKind::Success,
            confidence: Confidence::High,
            reason: "ok".to_string(),
            evidence: Vec::new(),
        },
        denials: Vec::new(),
        findings: Vec::new(),
        hints: Vec::new(),
    };

    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["profile"], "agent-default");
    assert_eq!(value["failure"]["kind"], "success");
    assert_eq!(value["output"]["stdout_bytes"], 6);
    assert!(value["resources"].get("cgroup").is_some());
    assert!(value["hints"].is_array());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn run_is_explicitly_unsupported_off_linux() {
    let mut spec = SandboxSpec::default();
    spec.process.cmd = Some("echo".into());
    let err = Runner::run(spec).unwrap_err().to_string();
    assert!(err.contains("Linux-only"));
}
