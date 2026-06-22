use crate::config::{SandboxSpec, SeccompProfile};
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

    pub fn explain(profile: SeccompProfile) -> serde_json::Value {
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
