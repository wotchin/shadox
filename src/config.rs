use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SandboxSpec {
    #[serde(default)]
    pub profile: SandboxProfile,
    #[serde(default)]
    pub process: ProcessSpec,
    #[serde(default)]
    pub limits: LimitsSpec,
    #[serde(default)]
    pub fs: FsSpec,
    #[serde(default)]
    pub security: SecuritySpec,
    #[serde(default)]
    pub observe: ObserveSpec,
    #[serde(default)]
    pub versioned_workspace: VersionedWorkspaceSpec,
}

impl SandboxSpec {
    pub fn from_toml_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let source = fs::read_to_string(path.as_ref())?;
        let spec = toml::from_str(&source)?;
        Ok(spec)
    }

    pub fn command_line(&self) -> anyhow::Result<(PathBuf, Vec<String>)> {
        let cmd = self.process.cmd.clone().ok_or_else(|| {
            anyhow::anyhow!("missing process command; pass a command after -- or set process.cmd")
        })?;
        Ok((cmd, self.process.args.clone()))
    }

    pub fn effective_policy(&self) -> EffectivePolicy {
        let mut policy = EffectivePolicy {
            profile: self.profile,
            profile_version: crate::metadata::PROFILE_VERSION,
            process: self.process.clone(),
            limits: self.limits.clone(),
            fs: self.fs.clone(),
            security: self.security.clone(),
            observe: self.observe.clone(),
            versioned_workspace: self.versioned_workspace.clone(),
            notes: Vec::new(),
        };

        match policy.profile {
            SandboxProfile::AgentDefault | SandboxProfile::WorkspaceWrite => {
                if policy.fs.write.is_empty() {
                    let workspace = policy
                        .process
                        .cwd
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("."));
                    policy.fs.write.push(workspace);
                    policy.notes.push(
                        "profile grants write access to the process working directory".to_string(),
                    );
                }
            }
            SandboxProfile::ReadOnly => {
                if !policy.fs.write.is_empty() {
                    policy.notes.push(
                        "read-only profile was broadened by explicit write allowlist".to_string(),
                    );
                }
            }
            SandboxProfile::PermissiveObserve => {
                if policy.security.landlock {
                    policy.notes.push(
                        "permissive-observe disables Landlock filesystem restrictions".to_string(),
                    );
                }
                policy.security.landlock = false;
            }
        }

        policy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub profile: SandboxProfile,
    pub profile_version: u32,
    pub process: ProcessSpec,
    pub limits: LimitsSpec,
    pub fs: FsSpec,
    pub security: SecuritySpec,
    pub observe: ObserveSpec,
    pub versioned_workspace: VersionedWorkspaceSpec,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl EffectivePolicy {
    pub fn command_line(&self) -> anyhow::Result<(PathBuf, Vec<String>)> {
        let cmd = self.process.cmd.clone().ok_or_else(|| {
            anyhow::anyhow!("missing process command; pass a command after -- or set process.cmd")
        })?;
        Ok((cmd, self.process.args.clone()))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxProfile {
    #[default]
    AgentDefault,
    ReadOnly,
    WorkspaceWrite,
    PermissiveObserve,
}

impl fmt::Display for SandboxProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AgentDefault => "agent-default",
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::PermissiveObserve => "permissive-observe",
        })
    }
}

impl FromStr for SandboxProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent-default" | "agent" | "default" => Ok(Self::AgentDefault),
            "read-only" | "readonly" => Ok(Self::ReadOnly),
            "workspace-write" | "workspace" => Ok(Self::WorkspaceWrite),
            "permissive-observe" | "observe" | "permissive" => Ok(Self::PermissiveObserve),
            other => Err(format!("unknown sandbox profile: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProcessSpec {
    pub cmd: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub clear_env: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LimitsSpec {
    pub timeout_ms: Option<u64>,
    pub cpu_time_secs: Option<u64>,
    pub address_space_bytes: Option<u64>,
    pub open_files: Option<u64>,
    pub file_size_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FsSpec {
    #[serde(default)]
    pub read: Vec<PathBuf>,
    #[serde(default)]
    pub write: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySpec {
    #[serde(default = "default_true")]
    pub no_new_privs: bool,
    #[serde(default = "default_true")]
    pub landlock: bool,
    #[serde(default)]
    pub seccomp_profile: SeccompProfile,
    #[serde(default)]
    pub allow_degraded: bool,
}

impl Default for SecuritySpec {
    fn default() -> Self {
        Self {
            no_new_privs: true,
            landlock: true,
            seccomp_profile: SeccompProfile::Basic,
            allow_degraded: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompProfile {
    Off,
    #[default]
    Basic,
}

impl FromStr for SeccompProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" | "none" => Ok(Self::Off),
            "basic" => Ok(Self::Basic),
            other => Err(format!("unknown seccomp profile: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObserveSpec {
    pub trace: Option<String>,
    pub summary: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub capture_stdout: bool,
    #[serde(default = "default_true")]
    pub capture_stderr: bool,
    #[serde(default = "default_true")]
    pub collect_cgroup: bool,
    #[serde(default = "default_proc_sample_interval_ms")]
    pub proc_sample_interval_ms: u64,
    #[serde(default)]
    pub trace_syscalls: bool,
    #[serde(default = "default_max_trace_output_bytes")]
    pub max_trace_output_bytes: Option<u64>,
    pub rhai_script: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct VersionedWorkspaceSpec {
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub rollback_on_failure: bool,
    #[serde(default)]
    pub commit_on_success: bool,
}

impl Default for ObserveSpec {
    fn default() -> Self {
        Self {
            trace: None,
            summary: None,
            capture_stdout: true,
            capture_stderr: true,
            collect_cgroup: true,
            proc_sample_interval_ms: default_proc_sample_interval_ms(),
            trace_syscalls: false,
            max_trace_output_bytes: default_max_trace_output_bytes(),
            rhai_script: None,
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_proc_sample_interval_ms() -> u64 {
    100
}

const fn default_max_trace_output_bytes() -> Option<u64> {
    Some(1024 * 1024)
}
