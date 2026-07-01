use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use shadox::{
    FsSpec, LimitsSpec, ObserveSpec, ProcessSpec, Runner, SandboxProfile, SandboxSpec,
    SeccompProfile, WorkspaceStore,
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
    Fs(FsArgs),
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
    #[arg(long)]
    max_trace_output_bytes: Option<u64>,
    #[arg(long)]
    versioned_workspace: Option<PathBuf>,
    #[arg(long)]
    rollback_on_failure: bool,
    #[arg(long)]
    commit_on_success: bool,
    #[arg(last = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct FsArgs {
    #[command(subcommand)]
    command: FsCommand,
}

#[derive(Debug, Subcommand)]
enum FsCommand {
    Init(FsWorkspaceArgs),
    Checkpoint(FsCheckpointArgs),
    Diff(FsDiffArgs),
    Rollback(FsRollbackArgs),
    Commit(FsCommitArgs),
    Log(FsWorkspaceArgs),
    Verify(FsWorkspaceArgs),
    Gc(FsWorkspaceArgs),
    Materialize(FsMaterializeArgs),
    Status(FsWorkspaceArgs),
    Replay(FsReplayArgs),
    Journal(FsJournalArgs),
    OpReplay(FsReplayArgs),
    OpJournal(FsJournalArgs),
    OpRestore(FsRestoreArgs),
    Mount(FsMountArgs),
}

#[derive(Debug, Args)]
struct FsWorkspaceArgs {
    #[arg(default_value = ".")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct FsCheckpointArgs {
    #[arg(default_value = ".")]
    workspace: PathBuf,
    #[arg(long)]
    message: Option<String>,
    #[arg(long)]
    source_run_id: Option<uuid::Uuid>,
}

#[derive(Debug, Args)]
struct FsDiffArgs {
    from: String,
    to: String,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct FsRollbackArgs {
    checkpoint: String,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct FsCommitArgs {
    checkpoint: String,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct FsMaterializeArgs {
    checkpoint: String,
    destination: PathBuf,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct FsReplayArgs {
    run_id: String,
    destination: PathBuf,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
    #[arg(long)]
    until_seq: Option<usize>,
    #[arg(long)]
    until_ts: Option<u128>,
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct FsJournalArgs {
    run_id: String,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

#[derive(Debug, Args)]
struct FsRestoreArgs {
    run_id: String,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
    #[arg(long)]
    until_seq: Option<usize>,
    #[arg(long)]
    until_ts: Option<u128>,
}

#[derive(Debug, Args)]
struct FsMountArgs {
    backing: PathBuf,
    mountpoint: PathBuf,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
    #[arg(long)]
    run_id: Option<uuid::Uuid>,
    #[arg(long)]
    commit_on_unmount: bool,
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
            if report.trace_path == "-" {
                eprintln!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        }
        Command::Explain(args) => {
            let spec = build_explain_spec(args)?;
            println!("{}", serde_json::to_string_pretty(&Runner::explain(&spec))?);
        }
        Command::Fs(args) => run_fs_command(args)?,
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
    if let Some(max_trace_output_bytes) = args.max_trace_output_bytes {
        spec.observe.max_trace_output_bytes = Some(max_trace_output_bytes);
    }
    if let Some(script) = args.observe_script {
        spec.observe.rhai_script = Some(script);
    }
    if let Some(workspace) = args.versioned_workspace {
        spec.versioned_workspace.workspace = Some(workspace);
    }
    if args.rollback_on_failure {
        spec.versioned_workspace.rollback_on_failure = true;
    }
    if args.commit_on_success {
        spec.versioned_workspace.commit_on_success = true;
    }

    spec.command_line()?;
    Ok(spec)
}

fn run_fs_command(args: FsArgs) -> anyhow::Result<()> {
    match args.command {
        FsCommand::Init(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let head = store.head()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "initialized": true,
                    "head": head,
                }))?
            );
        }
        FsCommand::Checkpoint(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let checkpoint = store.create_checkpoint(args.message, args.source_run_id, true)?;
            if let Some(run_id) = args.source_run_id {
                let mut compact = store.compact_run_journals(run_id)?;
                compact.checkpoint_id = checkpoint.checkpoint_id.clone();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "checkpoint": checkpoint.summary(),
                        "compact": compact,
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&checkpoint.summary())?);
            }
        }
        FsCommand::Diff(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let diff = store.diff_checkpoints(&args.from, &args.to)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        FsCommand::Rollback(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.rollback(&args.checkpoint)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Commit(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.commit_with_report(&args.checkpoint)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Log(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let checkpoints = store.list_checkpoints()?;
            println!("{}", serde_json::to_string_pretty(&checkpoints)?);
        }
        FsCommand::Verify(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.verify()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Gc(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.gc()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Materialize(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.materialize(&args.checkpoint, args.destination, args.force)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Status(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.status()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Replay(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.replay_journal(
                &args.run_id,
                args.until_seq,
                args.until_ts,
                args.destination,
                args.force,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Journal(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let events = store.list_journal(&args.run_id)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        FsCommand::OpReplay(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report = store.replay_operation_journal(
                &args.run_id,
                args.until_seq,
                args.until_ts,
                args.destination,
                args.force,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::OpJournal(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let events = store.list_operation_journal(&args.run_id)?;
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        FsCommand::OpRestore(args) => {
            let store = WorkspaceStore::open(args.workspace)?;
            let report =
                store.restore_operation_journal(&args.run_id, args.until_seq, args.until_ts)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        FsCommand::Mount(args) => run_fs_mount_command(args)?,
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "fuse"))]
fn run_fs_mount_command(args: FsMountArgs) -> anyhow::Result<()> {
    let run_id = args.run_id.unwrap_or_else(uuid::Uuid::new_v4);
    shadox::mount_recording_fuse(shadox::FuseMountSpec {
        backing: args.backing,
        mountpoint: args.mountpoint,
        workspace: args.workspace,
        run_id,
        commit_on_unmount: args.commit_on_unmount,
    })
}

#[cfg(not(all(target_os = "linux", feature = "fuse")))]
fn run_fs_mount_command(_args: FsMountArgs) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "fs mount requires Linux and the optional `fuse` feature"
    ))
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
