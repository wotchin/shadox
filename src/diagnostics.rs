use crate::config::{EffectivePolicy, SandboxProfile};
use crate::report::{DiagnosticHint, FailureClassification, FailureKind, OutputReport};

pub fn diagnostic_hints(
    failure: &FailureClassification,
    policy: &EffectivePolicy,
    output: &OutputReport,
) -> Vec<DiagnosticHint> {
    let mut hints = Vec::new();
    match failure.kind {
        FailureKind::Success => {}
        FailureKind::Timeout => hints.push(hint(
            "timeout_budget_exhausted",
            "warn",
            "The process exceeded the configured wall-clock timeout.",
            "Increase limits.timeout_ms for trusted workloads, or split the agent task into smaller steps.",
            &["timeout", "budget"],
        )),
        FailureKind::LandlockDenied => hints.push(hint(
            "landlock_fs_allowlist",
            "warn",
            "Filesystem access was likely denied by the effective Landlock allowlist.",
            "Add the required path to fs.read or fs.write, or pass --allow-read/--allow-write for this run.",
            &["landlock", "filesystem", "policy"],
        )),
        FailureKind::SeccompDenied => hints.push(hint(
            "seccomp_profile_blocked_syscall",
            "warn",
            "The basic seccomp profile likely blocked a syscall used by the command.",
            "Use seccomp_profile=\"off\" only for trusted diagnostics, then decide whether the workload needs a narrower custom profile.",
            &["seccomp", "syscall", "policy"],
        )),
        FailureKind::OomLike => hints.push(hint(
            "oom_like_termination",
            "warn",
            "The process was killed and memory telemetry suggests an OOM-like event.",
            "Reduce the workload memory footprint or run with a larger external memory budget.",
            &["memory", "budget"],
        )),
        FailureKind::Signal => hints.push(hint(
            "signal_termination",
            "info",
            "The process was terminated by a signal.",
            "Inspect failure.evidence and stderr_tail to distinguish isolation policy from application behavior.",
            &["signal", "diagnostics"],
        )),
        FailureKind::ExitNonZero => hints.push(hint(
            "non_zero_exit",
            "info",
            "The process exited with a non-zero status.",
            "Inspect output.stderr_tail and observer findings before changing isolation policy.",
            &["process", "diagnostics"],
        )),
    }

    if output.stdout_truncated || output.stderr_truncated {
        hints.push(hint(
            "output_tail_truncated",
            "info",
            "The summary retained only bounded output tails.",
            "Use trace.jsonl for full chunk-level output, or let the agent stream --trace - for live consumption.",
            &["output", "trace"],
        ));
    }

    if matches!(policy.profile, SandboxProfile::PermissiveObserve) {
        hints.push(hint(
            "permissive_observe_profile",
            "info",
            "The permissive-observe profile prioritizes telemetry over filesystem restriction.",
            "Use agent-default, read-only, or workspace-write when policy enforcement matters.",
            &["profile", "observe"],
        ));
    }

    hints
}

fn hint(code: &str, severity: &str, message: &str, action: &str, tags: &[&str]) -> DiagnosticHint {
    DiagnosticHint {
        code: code.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        action: action.to_string(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxSpec;
    use crate::report::{Confidence, FailureClassification};

    #[test]
    fn hints_explain_likely_landlock_denial() {
        let policy = SandboxSpec::default().effective_policy();
        let failure = FailureClassification {
            kind: FailureKind::LandlockDenied,
            confidence: Confidence::Medium,
            reason: "permission denied".to_string(),
            evidence: vec!["landlock=true".to_string()],
        };

        let hints = diagnostic_hints(&failure, &policy, &OutputReport::default());

        assert!(
            hints
                .iter()
                .any(|hint| hint.code == "landlock_fs_allowlist")
        );
    }

    #[test]
    fn hints_call_out_permissive_observe_profile() {
        let spec = SandboxSpec {
            profile: SandboxProfile::PermissiveObserve,
            ..SandboxSpec::default()
        };
        let policy = spec.effective_policy();

        let hints = diagnostic_hints(
            &FailureClassification::success(),
            &policy,
            &OutputReport::default(),
        );

        assert!(
            hints
                .iter()
                .any(|hint| hint.code == "permissive_observe_profile")
        );
    }
}
