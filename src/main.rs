use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use shadox::{
    FsSpec, LimitsSpec, ObserveSpec, ProcessSpec, Runner, SandboxProfile, SandboxSpec,
    SeccompProfile,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "shadox")]
#[command(about = "Rootless, process-level, agent-observable sandbox runtime")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    CheckEnv(CheckEnvArgs),
    Run(RunArgs),
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
struct CheckEnvArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    #[command(flatten)]
    policy: PolicyArgs,
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    policy: PolicyArgs,
    #[arg(long)]
    trace: Option<String>,
    #[arg(long)]
    summary: Option<PathBuf>,
    #[arg(long)]
    observe_script: Option<PathBuf>,
    #[arg(long)]
    trace_syscalls: bool,
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    profile: Option<SandboxProfile>,
    #[arg(long)]
    timeout_ms: Option<u64>,
    #[arg(long = "allow-read")]
    allow_read: Vec<PathBuf>,
    #[arg(long = "allow-write")]
    allow_write: Vec<PathBuf>,
    #[arg(long)]
    allow_degraded: bool,
    #[arg(long)]
    no_landlock: bool,
    #[arg(long)]
    seccomp_profile: Option<SeccompProfile>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::CheckEnv(args) => {
            let report = Runner::check_env();
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("platform: {}", report.platform);
                println!("supported: {}", report.supported);
                for (key, value) in report.details {
                    println!("{key}: {value}");
                }
            }
        }
        Command::Run(args) => {
            let spec = build_spec(args)?;
            let report = Runner::run(spec)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Explain(args) => {
            let spec = build_explain_spec(args)?;
            println!("{}", serde_json::to_string_pretty(&Runner::explain(&spec))?);
        }
    }
    Ok(())
}

fn build_spec(args: RunArgs) -> anyhow::Result<SandboxSpec> {
    let mut spec = build_base_spec(&args.policy)?;
    apply_policy_overrides(&mut spec, args.policy);

    if !args.command.is_empty() {
        let mut command = args.command.into_iter();
        spec.process.cmd = command.next().map(PathBuf::from);
        spec.process.args = command.collect();
    }

    if let Some(trace) = args.trace {
        spec.observe.trace = Some(trace);
    }
    if let Some(summary) = args.summary {
        spec.observe.summary = Some(summary);
    }
    if args.trace_syscalls {
        spec.observe.trace_syscalls = true;
    }
    if let Some(script) = args.observe_script {
        spec.observe.rhai_script = Some(script);
    }

    spec.command_line()?;
    Ok(spec)
}

fn build_explain_spec(args: ExplainArgs) -> anyhow::Result<SandboxSpec> {
    let mut spec = build_base_spec(&args.policy)?;
    apply_policy_overrides(&mut spec, args.policy);

    if !args.command.is_empty() {
        let mut command = args.command.into_iter();
        spec.process.cmd = command.next().map(PathBuf::from);
        spec.process.args = command.collect();
    }
    Ok(spec)
}

fn build_base_spec(args: &PolicyArgs) -> anyhow::Result<SandboxSpec> {
    let spec = if let Some(path) = &args.config {
        SandboxSpec::from_toml_file(path)
            .with_context(|| format!("failed to read config {}", path.display()))?
    } else {
        SandboxSpec::default()
    };
    Ok(spec)
}

fn apply_policy_overrides(spec: &mut SandboxSpec, args: PolicyArgs) {
    if let Some(profile) = args.profile {
        spec.profile = profile;
    }
    if let Some(timeout_ms) = args.timeout_ms {
        spec.limits.timeout_ms = Some(timeout_ms);
    }
    if args.allow_degraded {
        spec.security.allow_degraded = true;
    }
    if args.no_landlock {
        spec.security.landlock = false;
    }
    if let Some(seccomp_profile) = args.seccomp_profile {
        spec.security.seccomp_profile = seccomp_profile;
    }
    spec.fs.read.extend(args.allow_read);
    spec.fs.write.extend(args.allow_write);
}

#[allow(dead_code)]
fn _keep_public_types(_: ProcessSpec, _: LimitsSpec, _: FsSpec, _: ObserveSpec) {}
