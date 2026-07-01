use crate::config::{EffectivePolicy, FsSpec, LimitsSpec, SandboxSpec, SeccompProfile};
use crate::diagnostics::diagnostic_hints;
use crate::metadata::{SCHEMA_VERSION, SHADOX_VERSION};
use crate::observer::Observer;
use crate::report::{
    CgroupStats, Confidence, EnvReport, FailureClassification, FailureKind, OutputReport,
    ResourceUsage, RunReport, VersionedFsReport,
};
use crate::trace::{TraceContext, TraceLogger};
use crate::versioned_fs::WorkspaceTransaction;
use anyhow::Context;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn run(spec: SandboxSpec) -> anyhow::Result<RunReport> {
    let effective = spec.effective_policy();
    let (cmd, args) = effective.command_line()?;
    let run_id = Uuid::new_v4();
    let run_dir = default_run_dir(run_id);
    let trace_path = effective
        .observe
        .trace
        .clone()
        .unwrap_or_else(|| run_dir.join("trace.jsonl").to_string_lossy().to_string());
    let summary_path = effective
        .observe
        .summary
        .clone()
        .unwrap_or_else(|| run_dir.join("summary.json"));

    if trace_path != "-"
        && let Some(parent) = Path::new(&trace_path).parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = summary_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let observer = match &effective.observe.rhai_script {
        Some(path) => Some(
            Observer::from_file(path)
                .with_context(|| format!("failed to load observer script {}", path.display()))?,
        ),
        None => None,
    };
    let trace_context = TraceContext::new(effective.profile.to_string(), effective.profile_version);
    let logger = Arc::new(TraceLogger::new_with_context(
        run_id,
        &trace_path,
        observer,
        trace_context,
    )?);
    logger.emit(
        "run.start",
        None,
        "info",
        json!({
            "schema_version": SCHEMA_VERSION,
            "shadox_version": SHADOX_VERSION,
            "profile": effective.profile,
            "profile_version": effective.profile_version,
            "command": cmd,
            "args": args,
            "trace_path": trace_path,
            "summary_path": summary_path,
            "observe": {
                "proc_sample_interval_ms": effective.observe.proc_sample_interval_ms,
                "collect_cgroup": effective.observe.collect_cgroup,
                "trace_syscalls": effective.observe.trace_syscalls,
                "max_trace_output_bytes": effective.observe.max_trace_output_bytes,
            }
        }),
    )?;

    let versioned_run = prepare_versioned_workspace(&effective, run_id, &logger)?;

    let mut denials = Vec::new();
    let mut prepared = PreparedSandbox::prepare(
        &effective.fs,
        effective.security.landlock,
        effective.security.allow_degraded,
    )?;
    for degradation in &prepared.degraded {
        logger.emit(
            "sandbox.degraded",
            None,
            "warn",
            json!({ "reason": degradation }),
        )?;
    }
    if effective.observe.trace_syscalls {
        logger.emit(
            "sandbox.degraded",
            None,
            "warn",
            json!({
                "reason": "trace_syscalls was requested, but lightweight v1 does not enable ptrace syscall timelines"
            }),
        )?;
    }
    logger.emit(
        "sandbox.policy",
        None,
        "info",
        json!({
            "profile": effective.profile,
            "profile_version": effective.profile_version,
            "profile_notes": effective.notes,
            "no_new_privs": effective.security.no_new_privs,
            "landlock": effective.security.landlock,
            "seccomp_profile": effective.security.seccomp_profile,
            "allow_degraded": effective.security.allow_degraded,
            "fs": effective.fs,
            "limits": effective.limits,
        }),
    )?;

    let landlock_fd = prepared.landlock_ruleset_fd;
    let limits = effective.limits.clone();
    let security = effective.security.clone();
    let cgroup_path = if effective.observe.collect_cgroup {
        discover_cgroup_path("self")
    } else {
        None
    };
    let cgroup_before = cgroup_path
        .as_ref()
        .and_then(|path| read_cgroup_stats(path, None));
    if let Some(path) = &cgroup_path {
        logger.emit("cgroup.detected", None, "debug", json!({ "path": path }))?;
    }

    let mut command = Command::new(&cmd);
    command.args(&args);
    if let Some(cwd) = &effective.process.cwd {
        command.current_dir(cwd);
    }
    if effective.process.clear_env {
        command.env_clear();
    }
    command.envs(effective.process.env.clone());
    if effective.observe.capture_stdout {
        command.stdout(Stdio::piped());
    }
    if effective.observe.capture_stderr {
        command.stderr(Stdio::piped());
    }

    unsafe {
        command.pre_exec(move || {
            child_pre_exec(&limits, &security, landlock_fd)
                .map_err(|err| std::io::Error::other(err.to_string()))
        });
    }

    let start = Instant::now();
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", cmd.display()))?;
    if let Some(fd) = landlock_fd {
        unsafe {
            libc::close(fd);
        }
        prepared.landlock_ruleset_fd = None;
    }
    let pid = child.id();
    logger.emit("process.spawn", Some(pid), "info", json!({ "pid": pid }))?;

    let stop_sampler = Arc::new(AtomicBool::new(false));
    let last_sample = Arc::new(Mutex::new(None));
    let sampler = spawn_proc_sampler(
        pid,
        effective.observe.proc_sample_interval_ms,
        logger.clone(),
        stop_sampler.clone(),
        last_sample.clone(),
        cgroup_path.clone(),
    );

    let output = Arc::new(Mutex::new(OutputAccumulator::default()));
    let stdout_thread = child.stdout.take().map(|stdout| {
        spawn_pipe_reader(
            stdout,
            "stdout.chunk",
            pid,
            logger.clone(),
            output.clone(),
            effective.observe.max_trace_output_bytes,
        )
    });
    let stderr_thread = child.stderr.take().map(|stderr| {
        spawn_pipe_reader(
            stderr,
            "stderr.chunk",
            pid,
            logger.clone(),
            output.clone(),
            effective.observe.max_trace_output_bytes,
        )
    });

    let wait = wait_for_child(pid, effective.limits.timeout_ms, logger.clone())?;
    if wait.timed_out {
        denials.push("timeout".to_string());
    }

    stop_sampler.store(true, Ordering::SeqCst);
    let _ = sampler.join();
    if let Some(handle) = stdout_thread {
        let _ = handle.join();
    }
    if let Some(handle) = stderr_thread {
        let _ = handle.join();
    }

    let last_sample = last_sample.lock().expect("proc sample poisoned").clone();
    let cgroup_final = cgroup_path
        .as_ref()
        .and_then(|path| read_cgroup_stats(path, cgroup_before.as_ref()));
    let resources = ResourceUsage {
        user_cpu_ms: wait.rusage.as_ref().map(user_cpu_ms),
        system_cpu_ms: wait.rusage.as_ref().map(system_cpu_ms),
        max_rss_kb: wait.rusage.as_ref().map(|usage| usage.ru_maxrss),
        read_bytes: last_sample.as_ref().map(|sample| sample.read_bytes),
        write_bytes: last_sample.as_ref().map(|sample| sample.write_bytes),
        cgroup: cgroup_final.clone(),
    };
    let output = output.lock().expect("output accumulator poisoned").report();
    let failure = classify_failure(&wait, &effective, &output, cgroup_final.as_ref());
    if matches!(
        failure.kind,
        FailureKind::Timeout
            | FailureKind::SeccompDenied
            | FailureKind::LandlockDenied
            | FailureKind::OomLike
    ) {
        logger.emit(
            "sandbox.denied",
            Some(pid),
            "error",
            json!({
                "kind": failure.kind,
                "confidence": failure.confidence,
                "reason": failure.reason,
                "evidence": failure.evidence,
            }),
        )?;
    }

    let command_vec = std::iter::once(cmd.to_string_lossy().to_string())
        .chain(args)
        .collect::<Vec<_>>();
    let hints = diagnostic_hints(&failure, &effective, &output);
    let fs_report = finish_versioned_workspace(
        versioned_run,
        matches!(failure.kind, FailureKind::Success),
        effective.versioned_workspace.rollback_on_failure,
        effective.versioned_workspace.commit_on_success,
        &logger,
    )?;
    let report = RunReport {
        schema_version: SCHEMA_VERSION,
        shadox_version: SHADOX_VERSION.to_string(),
        profile: effective.profile.to_string(),
        profile_version: effective.profile_version,
        run_id,
        command: command_vec,
        exit_code: wait.exit_code,
        signal: wait.signal,
        timed_out: wait.timed_out,
        duration_ms: start.elapsed().as_millis(),
        trace_path: trace_path.clone(),
        summary_path: summary_path.clone(),
        resources,
        output,
        failure,
        denials,
        findings: logger.findings(),
        hints,
        fs: fs_report,
    };

    logger.emit(
        "process.exit",
        Some(pid),
        "info",
        json!({
            "exit_code": report.exit_code,
            "signal": report.signal,
            "timed_out": report.timed_out,
            "failure": report.failure,
        }),
    )?;
    logger.emit(
        "run.summary",
        Some(pid),
        "info",
        serde_json::to_value(&report)?,
    )?;

    let mut summary = File::create(&summary_path)?;
    summary.write_all(serde_json::to_string_pretty(&report)?.as_bytes())?;
    summary.write_all(b"\n")?;
    Ok(report)
}

fn prepare_versioned_workspace(
    policy: &EffectivePolicy,
    run_id: Uuid,
    logger: &TraceLogger,
) -> anyhow::Result<Option<WorkspaceTransaction>> {
    let Some(workspace) = &policy.versioned_workspace.workspace else {
        return Ok(None);
    };
    let (transaction, checkpoint) = WorkspaceTransaction::begin(workspace, run_id)
        .with_context(|| format!("failed to checkpoint workspace {}", workspace.display()))?;
    logger.emit(
        "fs.checkpoint",
        None,
        "info",
        json!({
            "phase": "before",
            "workspace": transaction.workspace(),
            "checkpoint_id": checkpoint.checkpoint_id,
            "entry_count": checkpoint.entries.len(),
        }),
    )?;
    Ok(Some(transaction))
}

fn finish_versioned_workspace(
    versioned_run: Option<WorkspaceTransaction>,
    command_succeeded: bool,
    rollback_on_failure: bool,
    commit_on_success: bool,
    logger: &TraceLogger,
) -> anyhow::Result<Option<VersionedFsReport>> {
    let Some(transaction) = versioned_run else {
        return Ok(None);
    };
    let outcome = transaction.finish(command_succeeded, rollback_on_failure, commit_on_success)?;
    logger.emit(
        "fs.diff",
        None,
        "info",
        json!({
            "workspace": &outcome.workspace,
            "checkpoint_before": &outcome.checkpoint_before,
            "checkpoint_after": &outcome.checkpoint_after,
            "journal_path": &outcome.journal_path,
            "changed_files": outcome.changed_files,
            "changes": &outcome.changes,
        }),
    )?;
    if outcome.committed {
        logger.emit(
            "fs.commit",
            None,
            "info",
            json!({ "checkpoint_id": &outcome.checkpoint_after }),
        )?;
    }
    if outcome.rolled_back {
        logger.emit(
            "fs.rollback",
            None,
            "warn",
            json!({
                "checkpoint_id": &outcome.checkpoint_before,
                "rollback": &outcome.rollback,
            }),
        )?;
    }
    Ok(Some(VersionedFsReport {
        enabled: true,
        workspace: outcome.workspace,
        checkpoint_before: outcome.checkpoint_before,
        checkpoint_after: outcome.checkpoint_after,
        journal_path: outcome.journal_path,
        changed_files: outcome.changed_files,
        changes: outcome.changes,
        committed: outcome.committed,
        rolled_back: outcome.rolled_back,
        rollback: outcome.rollback,
    }))
}

pub fn check_env() -> EnvReport {
    let mut details = BTreeMap::new();
    let landlock_abi = landlock_abi().ok();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let default_run_supported = landlock_abi.is_some();
    let degraded_reasons = if default_run_supported {
        Vec::<String>::new()
    } else {
        vec![
            "Landlock is unavailable; default runs fail closed unless allow_degraded is set"
                .to_string(),
        ]
    };

    details.insert("kernel".to_string(), json!(kernel_release()));
    details.insert("seccomp".to_string(), json!(true));
    details.insert("landlock_abi".to_string(), json!(landlock_abi));
    details.insert(
        "default_run_supported".to_string(),
        json!(default_run_supported),
    );
    details.insert("degraded_reasons".to_string(), json!(degraded_reasons));
    details.insert(
        "max_user_namespaces".to_string(),
        json!(read_to_string_trimmed("/proc/sys/user/max_user_namespaces").ok()),
    );
    details.insert(
        "unprivileged_userns_clone".to_string(),
        json!(read_to_string_trimmed("/proc/sys/kernel/unprivileged_userns_clone").ok()),
    );
    details.insert("cgroup_v2".to_string(), json!(cgroup_v2));
    details.insert(
        "cgroup_path".to_string(),
        json!(discover_cgroup_path("self")),
    );
    EnvReport {
        platform: "linux".to_string(),
        supported: default_run_supported,
        details,
    }
}

fn child_pre_exec(
    limits: &LimitsSpec,
    security: &crate::config::SecuritySpec,
    landlock_fd: Option<RawFd>,
) -> anyhow::Result<()> {
    unsafe {
        if libc::setpgid(0, 0) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    apply_rlimits(limits)?;
    if security.no_new_privs {
        set_no_new_privs()?;
    }
    if let Some(fd) = landlock_fd {
        restrict_landlock(fd)?;
    }
    if security.seccomp_profile == SeccompProfile::Basic {
        install_basic_seccomp()?;
    }
    Ok(())
}

fn apply_rlimits(limits: &LimitsSpec) -> anyhow::Result<()> {
    if let Some(value) = limits.cpu_time_secs {
        set_rlimit(libc::RLIMIT_CPU, value)?;
    }
    if let Some(value) = limits.address_space_bytes {
        set_rlimit(libc::RLIMIT_AS, value)?;
    }
    if let Some(value) = limits.open_files {
        set_rlimit(libc::RLIMIT_NOFILE, value)?;
    }
    if let Some(value) = limits.file_size_bytes {
        set_rlimit(libc::RLIMIT_FSIZE, value)?;
    }
    if let Some(value) = limits.max_processes {
        set_rlimit(libc::RLIMIT_NPROC, value)?;
    }
    Ok(())
}

fn set_rlimit(resource: libc::__rlimit_resource_t, value: u64) -> anyhow::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    let result = unsafe { libc::setrlimit(resource, &limit) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_no_new_privs() -> anyhow::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

struct PreparedSandbox {
    landlock_ruleset_fd: Option<RawFd>,
    degraded: Vec<String>,
}

impl PreparedSandbox {
    fn prepare(fs: &FsSpec, enable_landlock: bool, allow_degraded: bool) -> anyhow::Result<Self> {
        if !enable_landlock {
            return Ok(Self {
                landlock_ruleset_fd: None,
                degraded: Vec::new(),
            });
        }

        match prepare_landlock(fs) {
            Ok(fd) => Ok(Self {
                landlock_ruleset_fd: Some(fd),
                degraded: Vec::new(),
            }),
            Err(err) if allow_degraded => Ok(Self {
                landlock_ruleset_fd: None,
                degraded: vec![format!("landlock disabled: {err}")],
            }),
            Err(err) => Err(err),
        }
    }
}

impl Drop for PreparedSandbox {
    fn drop(&mut self) {
        if let Some(fd) = self.landlock_ruleset_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

fn prepare_landlock(fs: &FsSpec) -> anyhow::Result<RawFd> {
    let abi = landlock_abi().context("Landlock is not available on this kernel")?;
    let handled = landlock_supported_mask(abi, fs);
    if handled == 0 {
        return Err(anyhow::anyhow!("Landlock handled access mask is empty"));
    }

    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset_attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        ) as RawFd
    };
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create Landlock ruleset");
    }

    let read_access =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    let write_access = write_access_mask(abi);
    let enforce_read = !fs.read.is_empty();
    for path in &fs.read {
        add_landlock_path_rule(ruleset_fd, path, read_access & handled)?;
    }
    for path in &fs.write {
        let mut access = write_access & handled;
        if enforce_read {
            access |= read_access & handled;
        }
        add_landlock_path_rule(ruleset_fd, path, access)?;
    }

    Ok(ruleset_fd)
}

fn landlock_abi() -> anyhow::Result<i32> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        ) as i32
    };
    if abi < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to query Landlock ABI");
    }
    Ok(abi)
}

fn landlock_supported_mask(abi: i32, fs: &FsSpec) -> u64 {
    let mut mask = write_access_mask(abi);
    if !fs.read.is_empty() {
        mask |=
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
    }
    mask
}

fn write_access_mask(abi: i32) -> u64 {
    let mut mask = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    mask
}

fn add_landlock_path_rule(
    ruleset_fd: RawFd,
    path: &Path,
    allowed_access: u64,
) -> anyhow::Result<()> {
    if allowed_access == 0 {
        return Ok(());
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let parent_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open Landlock path {}", path.display()));
    }
    let rule = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &rule,
            0,
        )
    };
    unsafe {
        libc::close(parent_fd);
    }
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to add Landlock rule for {}", path.display()));
    }
    Ok(())
}

fn restrict_landlock(ruleset_fd: RawFd) -> anyhow::Result<()> {
    let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to restrict process with Landlock");
    }
    Ok(())
}

fn install_basic_seccomp() -> anyhow::Result<()> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

    let native_arch = native_audit_arch()
        .ok_or_else(|| anyhow::anyhow!("basic seccomp is unsupported on this CPU architecture"))?;

    let blocked = [
        libc::SYS_ptrace,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
    ];

    let mut filters = vec![
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_ARCH_OFFSET,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: native_arch,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
    ];
    for syscall in blocked {
        filters.push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filters.push(libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            // Uncatchable SIGSYS gives the parent a strong classification signal.
            k: SECCOMP_RET_KILL_PROCESS,
        });
    }
    filters.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    let mut program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &mut program,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to install seccomp filter");
    }
    Ok(())
}

fn native_audit_arch() -> Option<u32> {
    #[cfg(target_arch = "x86_64")]
    {
        return Some(0xC000003E);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Some(0xC00000B7);
    }
    #[cfg(target_arch = "riscv64")]
    {
        return Some(0xC00000F3);
    }
    #[allow(unreachable_code)]
    None
}

struct WaitResult {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    rusage: Option<libc::rusage>,
}

fn classify_failure(
    wait: &WaitResult,
    policy: &EffectivePolicy,
    output: &OutputReport,
    cgroup: Option<&CgroupStats>,
) -> FailureClassification {
    // Order matters: prefer direct kernel evidence first, then labeled heuristics.
    if wait.timed_out {
        return FailureClassification {
            kind: FailureKind::Timeout,
            confidence: Confidence::High,
            reason: "process exceeded configured timeout and was killed".to_string(),
            evidence: vec!["timed_out=true".to_string()],
        };
    }

    if wait.exit_code == Some(0) && wait.signal.is_none() {
        return FailureClassification::success();
    }

    if wait.signal == Some(libc::SIGSYS) {
        return FailureClassification {
            kind: FailureKind::SeccompDenied,
            confidence: Confidence::High,
            reason: "process received SIGSYS, which usually indicates a seccomp trap".to_string(),
            evidence: vec!["signal=SIGSYS".to_string()],
        };
    }

    if looks_oom_like(wait, cgroup) {
        return FailureClassification {
            kind: FailureKind::OomLike,
            confidence: Confidence::Medium,
            reason: "process was killed and cgroup memory events suggest an OOM-like termination"
                .to_string(),
            evidence: oom_evidence(wait, cgroup),
        };
    }

    // Landlock denials surface to the sandboxed process as ordinary EACCES/EPERM.
    // Without ptrace or audit logs, v1 keeps this intentionally heuristic and
    // labels the confidence rather than pretending exact attribution.
    let stderr = output.stderr_tail.to_ascii_lowercase();
    if policy.security.landlock
        && (stderr.contains("permission denied") || stderr.contains("operation not permitted"))
    {
        return FailureClassification {
            kind: FailureKind::LandlockDenied,
            confidence: Confidence::Medium,
            reason: "stderr contains a permission denial while Landlock was enabled".to_string(),
            evidence: vec![
                "landlock=true".to_string(),
                "stderr_permission_denial=true".to_string(),
            ],
        };
    }

    if policy.security.seccomp_profile == SeccompProfile::Basic
        && stderr.contains("operation not permitted")
    {
        return FailureClassification {
            kind: FailureKind::SeccompDenied,
            confidence: Confidence::Low,
            reason: "stderr contains EPERM while the basic seccomp profile was enabled".to_string(),
            evidence: vec![
                "seccomp_profile=basic".to_string(),
                "stderr_eperm=true".to_string(),
            ],
        };
    }

    if let Some(signal) = wait.signal {
        return FailureClassification {
            kind: FailureKind::Signal,
            confidence: Confidence::High,
            reason: format!("process terminated by signal {signal}"),
            evidence: vec![format!("signal={signal}")],
        };
    }

    FailureClassification {
        kind: FailureKind::ExitNonZero,
        confidence: Confidence::High,
        reason: format!(
            "process exited with non-zero status {}",
            wait.exit_code.unwrap_or_default()
        ),
        evidence: vec![format!("exit_code={}", wait.exit_code.unwrap_or_default())],
    }
}

fn looks_oom_like(wait: &WaitResult, cgroup: Option<&CgroupStats>) -> bool {
    let killed = wait.signal == Some(libc::SIGKILL);
    let oom_delta = cgroup
        .and_then(|stats| stats.memory_events_delta.get("oom_kill").copied())
        .unwrap_or_default();
    killed && oom_delta > 0
}

fn oom_evidence(wait: &WaitResult, cgroup: Option<&CgroupStats>) -> Vec<String> {
    let mut evidence = Vec::new();
    if let Some(signal) = wait.signal {
        evidence.push(format!("signal={signal}"));
    }
    if let Some(stats) = cgroup {
        for (key, value) in &stats.memory_events_delta {
            if *value != 0 {
                evidence.push(format!("memory.events.delta.{key}={value}"));
            }
        }
    }
    evidence
}

fn kill_process_tree(root_pid: u32) -> Vec<u32> {
    let mut pids = collect_proc_tree_sample(root_pid)
        .map(|sample| sample.pids)
        .unwrap_or_else(|| vec![root_pid]);
    pids.push(root_pid);

    let mut seen = HashSet::new();
    pids.retain(|pid| seen.insert(*pid));

    unsafe {
        libc::kill(-(root_pid as libc::pid_t), libc::SIGKILL);
    }

    for pid in pids.iter().rev() {
        unsafe {
            libc::kill(*pid as libc::pid_t, libc::SIGKILL);
        }
    }

    pids
}

fn wait_for_child(
    pid: u32,
    timeout_ms: Option<u64>,
    logger: Arc<TraceLogger>,
) -> anyhow::Result<WaitResult> {
    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    let mut timed_out = false;
    loop {
        let mut status = 0;
        let mut rusage = unsafe { std::mem::zeroed::<libc::rusage>() };
        let result =
            unsafe { libc::wait4(pid as libc::pid_t, &mut status, libc::WNOHANG, &mut rusage) };
        if result == pid as libc::pid_t {
            let exit_code = if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status))
            } else {
                None
            };
            let signal = if libc::WIFSIGNALED(status) {
                Some(libc::WTERMSIG(status))
            } else {
                None
            };
            return Ok(WaitResult {
                exit_code,
                signal,
                timed_out,
                rusage: Some(rusage),
            });
        }
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("wait4 failed");
        }
        if let Some(deadline) = deadline
            && !timed_out
            && Instant::now() >= deadline
        {
            timed_out = true;
            let killed_pids = kill_process_tree(pid);
            logger.emit(
                "sandbox.denied",
                Some(pid),
                "error",
                json!({
                    "reason": "timeout",
                    "timeout_ms": timeout_ms,
                    "killed_pids": killed_pids,
                }),
            )?;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Debug, Clone, Default)]
struct ProcSample {
    pids: Vec<u32>,
    rss_kb: u64,
    read_bytes: u64,
    write_bytes: u64,
}

fn spawn_proc_sampler(
    root_pid: u32,
    interval_ms: u64,
    logger: Arc<TraceLogger>,
    stop: Arc<AtomicBool>,
    last_sample: Arc<Mutex<Option<ProcSample>>>,
    cgroup_path: Option<PathBuf>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let interval = Duration::from_millis(interval_ms.max(10));
        while !stop.load(Ordering::SeqCst) {
            if let Some(sample) = collect_proc_tree_sample(root_pid) {
                let mut data = json!({
                    "pids": sample.pids,
                    "process_count": sample.pids.len(),
                    "rss_kb": sample.rss_kb,
                    "read_bytes": sample.read_bytes,
                    "write_bytes": sample.write_bytes,
                });
                if let Some(path) = &cgroup_path
                    && let Some(stats) = read_cgroup_stats(path, None)
                    && let Some(object) = data.as_object_mut()
                {
                    object.insert(
                        "cgroup".to_string(),
                        serde_json::to_value(stats).unwrap_or(json!(null)),
                    );
                }
                *last_sample.lock().expect("proc sample poisoned") = Some(sample);
                let _ = logger.emit("proc.sample", Some(root_pid), "debug", data);
            }
            thread::sleep(interval);
        }
    })
}

fn collect_proc_tree_sample(root_pid: u32) -> Option<ProcSample> {
    let ppid_map = collect_ppid_map();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, ppid) in ppid_map {
        children.entry(ppid).or_default().push(pid);
    }
    let mut pids = Vec::new();
    let mut queue = VecDeque::from([root_pid]);
    while let Some(pid) = queue.pop_front() {
        pids.push(pid);
        if let Some(items) = children.get(&pid) {
            for child in items {
                queue.push_back(*child);
            }
        }
    }

    let mut sample = ProcSample {
        pids,
        ..Default::default()
    };
    for pid in &sample.pids {
        if let Some(rss) = read_status_rss_kb(*pid) {
            sample.rss_kb += rss;
        }
        if let Some((read_bytes, write_bytes)) = read_io_bytes(*pid) {
            sample.read_bytes += read_bytes;
            sample.write_bytes += write_bytes;
        }
    }
    Some(sample)
}

fn collect_ppid_map() -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(ppid) = read_ppid(pid) {
            map.insert(pid, ppid);
        }
    }
    map
}

fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let tail = stat.get(end + 1..)?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    fields.get(1)?.parse().ok()
}

fn read_status_rss_kb(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            return value.split_whitespace().next()?.parse().ok();
        }
    }
    Some(0)
}

fn read_io_bytes(pid: u32) -> Option<(u64, u64)> {
    let io = fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    let mut read_bytes = 0;
    let mut write_bytes = 0;
    for line in io.lines() {
        if let Some(value) = line.strip_prefix("read_bytes:") {
            read_bytes = value.trim().parse().ok()?;
        } else if let Some(value) = line.strip_prefix("write_bytes:") {
            write_bytes = value.trim().parse().ok()?;
        }
    }
    Some((read_bytes, write_bytes))
}

fn discover_cgroup_path(proc_name: &str) -> Option<PathBuf> {
    // v1 never creates or mutates cgroups. It only discovers the ambient cgroup
    // for observability, which keeps the sandbox rootless and delegation-free.
    let cgroup_file = format!("/proc/{proc_name}/cgroup");
    let content = fs::read_to_string(cgroup_file).ok()?;
    for line in content.lines() {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        if controllers.is_empty() {
            let relative = path.trim_start_matches('/');
            return Some(if relative.is_empty() {
                PathBuf::from("/sys/fs/cgroup")
            } else {
                PathBuf::from("/sys/fs/cgroup").join(relative)
            });
        }
    }
    None
}

fn read_cgroup_stats(path: &Path, before: Option<&CgroupStats>) -> Option<CgroupStats> {
    // cgroup v2 files are optional across kernels and environments, so every
    // field is best-effort and missing files simply become null in JSON.
    if !path.exists() {
        return None;
    }

    let memory_events = read_key_value_u64(path.join("memory.events")).unwrap_or_default();
    let memory_events_delta = before
        .map(|before| diff_u64_maps(&before.memory_events, &memory_events))
        .unwrap_or_default();
    let cpu = read_key_value_u64(path.join("cpu.stat")).unwrap_or_default();

    Some(CgroupStats {
        path: Some(path.to_path_buf()),
        cpu_usage_usec: cpu.get("usage_usec").copied(),
        cpu_user_usec: cpu.get("user_usec").copied(),
        cpu_system_usec: cpu.get("system_usec").copied(),
        memory_current_bytes: read_single_u64(path.join("memory.current")),
        memory_peak_bytes: read_single_u64(path.join("memory.peak")),
        memory_events,
        memory_events_delta,
        pids_current: read_single_u64(path.join("pids.current")),
    })
}

fn read_key_value_u64(path: PathBuf) -> Option<BTreeMap<String, u64>> {
    let content = fs::read_to_string(path).ok()?;
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if let Ok(value) = value.parse::<u64>() {
            values.insert(key.to_string(), value);
        }
    }
    Some(values)
}

fn read_single_u64(path: PathBuf) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn diff_u64_maps(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> BTreeMap<String, i64> {
    after
        .iter()
        .map(|(key, value)| {
            let before = before.get(key).copied().unwrap_or_default();
            (key.clone(), *value as i64 - before as i64)
        })
        .collect()
}

#[derive(Debug, Default)]
struct OutputAccumulator {
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_trace_bytes: u64,
    stderr_trace_bytes: u64,
    stdout_tail: String,
    stderr_tail: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

impl OutputAccumulator {
    const TAIL_LIMIT_CHARS: usize = 4096;

    fn push(&mut self, kind: &str, bytes: &[u8], trace_limit_bytes: Option<u64>) -> TraceChunk {
        // Keep byte counts exact, but only retain bounded tails for agent hints.
        let text = String::from_utf8_lossy(bytes);
        if kind == "stderr.chunk" {
            self.stderr_bytes += bytes.len() as u64;
            Self::append_tail(&mut self.stderr_tail, &mut self.stderr_truncated, &text);
            Self::trace_chunk(&mut self.stderr_trace_bytes, bytes, trace_limit_bytes)
        } else {
            self.stdout_bytes += bytes.len() as u64;
            Self::append_tail(&mut self.stdout_tail, &mut self.stdout_truncated, &text);
            Self::trace_chunk(&mut self.stdout_trace_bytes, bytes, trace_limit_bytes)
        }
    }

    fn report(&self) -> OutputReport {
        OutputReport {
            stdout_bytes: self.stdout_bytes,
            stderr_bytes: self.stderr_bytes,
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
            stdout_tail: self.stdout_tail.clone(),
            stderr_tail: self.stderr_tail.clone(),
        }
    }

    fn append_tail(target: &mut String, truncated: &mut bool, text: &str) {
        target.push_str(text);
        let char_count = target.chars().count();
        if char_count > Self::TAIL_LIMIT_CHARS {
            let keep_from = char_count - Self::TAIL_LIMIT_CHARS;
            *target = target.chars().skip(keep_from).collect();
            *truncated = true;
        }
    }

    fn trace_chunk(emitted: &mut u64, bytes: &[u8], limit: Option<u64>) -> TraceChunk {
        let allowed = limit
            .map(|limit| limit.saturating_sub(*emitted) as usize)
            .unwrap_or(bytes.len())
            .min(bytes.len());
        *emitted = (*emitted).saturating_add(allowed as u64);
        TraceChunk {
            text: String::from_utf8_lossy(&bytes[..allowed]).to_string(),
            truncated: allowed < bytes.len(),
            omitted_bytes: (bytes.len() - allowed) as u64,
        }
    }
}

struct TraceChunk {
    text: String,
    truncated: bool,
    omitted_bytes: u64,
}

fn spawn_pipe_reader<R: Read + Send + 'static>(
    mut reader: R,
    kind: &'static str,
    pid: u32,
    logger: Arc<TraceLogger>,
    output: Arc<Mutex<OutputAccumulator>>,
    trace_limit_bytes: Option<u64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let trace_chunk = output.lock().expect("output accumulator poisoned").push(
                        kind,
                        &buffer[..n],
                        trace_limit_bytes,
                    );
                    let data = json!({
                        "bytes": n,
                        "text": trace_chunk.text,
                        "truncated": trace_chunk.truncated,
                        "omitted_bytes": trace_chunk.omitted_bytes,
                    });
                    let _ = logger.emit(kind, Some(pid), "info", data);
                }
                Err(_) => break,
            }
        }
    })
}

fn user_cpu_ms(usage: &libc::rusage) -> u64 {
    timeval_ms(usage.ru_utime)
}

fn system_cpu_ms(usage: &libc::rusage) -> u64 {
    timeval_ms(usage.ru_stime)
}

fn timeval_ms(value: libc::timeval) -> u64 {
    (value.tv_sec as u64 * 1000) + (value.tv_usec as u64 / 1000)
}

fn default_run_dir(run_id: Uuid) -> PathBuf {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let short = run_id.to_string();
    PathBuf::from(".shadox")
        .join("runs")
        .join(format!("{seconds}-{}", &short[..8]))
}

fn read_to_string_trimmed(path: &str) -> anyhow::Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn kernel_release() -> String {
    let mut uts = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return "unknown".to_string();
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    release.to_string_lossy().to_string()
}
