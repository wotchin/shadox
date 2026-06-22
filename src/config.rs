use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SandboxSpec {
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
    pub rhai_script: Option<PathBuf>,
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
