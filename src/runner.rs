use crate::config::{SandboxSpec, SeccompProfile};
use crate::metadata::{SCHEMA_VERSION, SHADOX_VERSION};
use crate::report::{EnvReport, RunReport};

#[cfg(target_os = "linux")]
mod platform {
    pub use crate::runner::linux::*;
}

#[cfg(not(target_os = "linux"))]
mod platform {
    pub use crate::runner::unsupported::*;
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod unsupported;

pub struct Runner;

impl Runner {
    pub fn run(spec: SandboxSpec) -> anyhow::Result<RunReport> {
        platform::run(spec)
    }

    pub fn check_env() -> EnvReport {
        platform::check_env()
    }

    pub fn explain(spec: &SandboxSpec) -> serde_json::Value {
        let policy = spec.effective_policy();
        let seccomp = Self::explain_seccomp(policy.security.seccomp_profile);
        serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "shadox_version": SHADOX_VERSION,
            "profile": policy.profile.to_string(),
            "profile_version": policy.profile_version,
            "effective_policy": policy,
            "seccomp": seccomp,
            "diagnostics": {
                "summary_hints": true,
                "failure_kinds": [
                    "timeout",
                    "seccomp_denied",
                    "landlock_denied",
                    "oom_like",
                    "signal",
                    "exit_non_zero"
                ]
            },
            "agent_contract": {
                "trace": "JSONL event stream for live agent consumption",
                "summary": "final JSON report with failure classification and hints",
                "policy": "effective policy is explicit before run"
            }
        })
    }

    pub fn explain_seccomp(profile: SeccompProfile) -> serde_json::Value {
        match profile {
            SeccompProfile::Off => serde_json::json!({
                "seccomp_profile": "off",
                "description": "No seccomp filter is installed.",
                "blocked_syscalls": [],
            }),
            SeccompProfile::Basic => serde_json::json!({
                "seccomp_profile": "basic",
                "description": "Block obvious privileged or introspection syscalls while keeping ordinary CLI programs usable.",
                "blocked_syscalls": [
                    "ptrace",
                    "kexec_load",
                    "bpf",
                    "perf_event_open",
                    "mount",
                    "umount2",
                    "reboot",
                    "init_module",
                    "finit_module",
                    "delete_module"
                ],
            }),
        }
    }
}
