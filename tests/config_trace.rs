use serde_json::json;
use shadox::config::{SandboxSpec, SeccompProfile};
use shadox::observer::Observer;
use shadox::runner::Runner;
use shadox::trace::{TraceEvent, TraceLogger};
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
    let value = Runner::explain(SeccompProfile::Basic);
    let blocked = value["blocked_syscalls"].as_array().unwrap();
    assert!(blocked.iter().any(|item| item == "ptrace"));
    assert_eq!(value["seccomp_profile"], "basic");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn run_is_explicitly_unsupported_off_linux() {
    let mut spec = SandboxSpec::default();
    spec.process.cmd = Some("echo".into());
    let err = Runner::run(spec).unwrap_err().to_string();
    assert!(err.contains("Linux-only"));
}
