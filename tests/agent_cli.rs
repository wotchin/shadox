use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn agent_guide_prints_embedded_markdown_from_any_cwd() {
    let dir = tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_shadox"))
        .current_dir(dir.path())
        .args(["agent-guide"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("# Agent Contract"));
    assert!(stdout.contains("shadox agent-guide --format markdown"));
    assert!(stdout.contains("shadox run"));
}

#[test]
fn agent_guide_json_wraps_the_markdown_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadox"))
        .args(["agent-guide", "--format", "json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "shadox.agent_guide");
    assert_eq!(value["source"], "docs/agent-contract.md");
    assert!(
        value["content"]
            .as_str()
            .unwrap()
            .contains("# Agent Contract")
    );
}

#[test]
fn capabilities_prints_machine_readable_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadox"))
        .args(["capabilities", "--format", "json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "shadox.agent_capabilities");
    assert_eq!(value["runtime"]["role"], "agent runtime control plane");
    assert_eq!(value["runtime"]["security_boundary"], "not_hardened");
    assert_eq!(value["runtime"]["provider_specific_orchestration"], false);
    assert_eq!(
        value["isolation"]["model"],
        "caller_composed_external_boundary"
    );
    assert_eq!(value["isolation"]["built_in_layer"]["name"], "native-linux");
    assert_eq!(value["isolation"]["provider_adapters"], "not_required");
    assert!(
        value["isolation"]
            .get("future_provider_interface")
            .is_none()
    );
    assert_eq!(
        value["guide"]["command"],
        "shadox agent-guide --format markdown"
    );
    assert!(value["commands"].as_array().unwrap().iter().any(|command| {
        command["name"] == "run" && command["purpose"].as_str().unwrap().contains("workspace")
    }));
}

#[test]
fn run_help_does_not_advertise_provider_specific_isolation_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadox"))
        .args(["run", "--help"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("--isolation"));
}
