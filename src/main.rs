use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use shadox::{FsSpec, LimitsSpec, ObserveSpec, ProcessSpec, Runner, SandboxSpec, SeccompProfile};
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
    #[arg(long, default_value = "basic")]
    profile: SeccompProfile,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    trace: Option<String>,
    #[arg(long)]
    summary: Option<PathBuf>,
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
    #[arg(long, default_value = "basic")]
    seccomp_profile: SeccompProfile,
    #[arg(long)]
    observe_script: Option<PathBuf>,
    #[arg(long)]
    trace_syscalls: bool,
    #[arg(last = true, trailing_var_arg = true)]
    command: Vec<String>,
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
            println!(
                "{}",
                serde_json::to_string_pretty(&Runner::explain(args.profile))?
            );
        }
    }
    Ok(())
}

fn build_spec(args: RunArgs) -> anyhow::Result<SandboxSpec> {
    let mut spec = if let Some(path) = args.config {
        SandboxSpec::from_toml_file(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?
    } else {
        SandboxSpec::default()
    };

    if !args.command.is_empty() {
        let mut command = args.command.into_iter();
        spec.process.cmd = command.next().map(PathBuf::from);
        spec.process.args = command.collect();
    }

    if let Some(timeout_ms) = args.timeout_ms {
        spec.limits.timeout_ms = Some(timeout_ms);
    }
    if let Some(trace) = args.trace {
        spec.observe.trace = Some(trace);
    }
    if let Some(summary) = args.summary {
        spec.observe.summary = Some(summary);
    }
    if args.allow_degraded {
        spec.security.allow_degraded = true;
    }
    if args.no_landlock {
        spec.security.landlock = false;
    }
    spec.security.seccomp_profile = args.seccomp_profile;
    if args.trace_syscalls {
        spec.observe.trace_syscalls = true;
    }
    if let Some(script) = args.observe_script {
        spec.observe.rhai_script = Some(script);
    }
    spec.fs.read.extend(args.allow_read);
    spec.fs.write.extend(args.allow_write);

    spec.command_line()?;
    Ok(spec)
}

#[allow(dead_code)]
fn _keep_public_types(_: ProcessSpec, _: LimitsSpec, _: FsSpec, _: ObserveSpec) {}
