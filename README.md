# shadox

`shadox` is a research-oriented, rootless-first, process-level sandbox runtime for Linux.

It is not a Docker competitor. The goal is to run ordinary commands with a small set of Linux restriction primitives and produce agent-friendly traces that explain what happened.

## What v1 Does

- Runs one process under a supervised sandbox.
- Applies `no_new_privs`, `rlimit`, Landlock filesystem restrictions, and a basic seccomp blocklist on Linux.
- Captures stdout/stderr as JSONL trace events.
- Bounds trace output text by default while preserving exact byte counts.
- Samples `/proc` for lightweight process-tree resource telemetry.
- Reads cgroup v2 stats when available, without creating or managing cgroups.
- Writes a `summary.json` report at the end of the run.
- Can checkpoint, diff, rollback, and commit a workspace around agent commands.
- Classifies failures as timeout, signal, non-zero exit, seccomp-denied, Landlock-like denial, or OOM-like.
- Emits diagnostic hints that tell an agent what to inspect or change next.
- Explains the effective policy before a run.
- Supports Rhai scripts as programmable observation rules.
- Builds on non-Linux hosts, but `shadox run` is Linux-only.

## Quick Start

```bash
cargo build

shadox check-env --json

shadox explain --profile agent-default -- /bin/echo "hello from shadox"

shadox run --config examples/shadox.toml

shadox run \
  --profile workspace-write \
  --allow-write . \
  --versioned-workspace . \
  --rollback-on-failure \
  --timeout-ms 5000 \
  --observe-script examples/observe.rhai \
  -- /bin/echo "hello from shadox"
```

By default, traces are written to:

```text
.shadox/runs/<timestamp>-<run_id>/trace.jsonl
.shadox/runs/<timestamp>-<run_id>/summary.json
```

Pass `--trace -` to stream JSONL events to stdout.

When `--trace -` is used, the CLI writes the final pretty summary to stderr so stdout remains a pure JSONL event stream. The same summary is also emitted as the `run.summary` trace event and written to `summary.json`.

## Agent-Native Profiles

Profiles are intentionally small policy presets, not container modes:

- `agent-default`: rootless restrictions, observability on, and write access to the process working directory when no explicit write allowlist is provided.
- `read-only`: deny filesystem writes by default while keeping ordinary reads and execution usable.
- `workspace-write`: explicitly expresses the common agent case of writing only inside the workspace.
- `permissive-observe`: disables Landlock filesystem restrictions and keeps telemetry on for trusted diagnostics.

CLI flags and TOML fields can still narrow or broaden the effective policy. Use `shadox explain --config shadox.toml` to inspect the final contract before running.

## Trace Event Shape

Each JSONL event uses a stable envelope:

```json
{
  "schema_version": 1,
  "shadox_version": "0.1.0",
  "profile": "agent-default",
  "profile_version": 1,
  "ts": 1790000000000,
  "seq": 1,
  "run_id": "00000000-0000-0000-0000-000000000000",
  "kind": "process.spawn",
  "pid": 1234,
  "level": "info",
  "data": {}
}
```

Current event kinds include:

- `run.start`
- `sandbox.policy`
- `sandbox.degraded`
- `cgroup.detected`
- `process.spawn`
- `proc.sample`
- `stdout.chunk`
- `stderr.chunk`
- `sandbox.denied`
- `observer.finding`
- `process.exit`
- `run.summary`

`syscall.enter` and `syscall.exit` are reserved for a future ptrace-backed syscall trace mode. In lightweight v1, `--trace-syscalls` records a `sandbox.degraded` event instead of silently pretending syscall tracing is active.

## Summary Report

`summary.json` is meant to be consumed directly by an agent. It includes:

- process result: `exit_code`, `signal`, `timed_out`
- failure classification: `failure.kind`, `failure.confidence`, `failure.evidence`
- resource summary: CPU time, max RSS, IO bytes, and optional cgroup v2 stats
- output summary: stdout/stderr byte counts and 4 KiB tails
- observer findings emitted by Rhai rules
- diagnostic hints with `code`, `severity`, `message`, `action`, and `tags`

Landlock denials usually appear to the child as ordinary `EACCES` or `EPERM`, so v1 classifies them with medium confidence based on stderr signatures. Seccomp denials in the basic profile use `SIGSYS`, which gives the parent a high-confidence classification signal.

The top-level summary also includes `schema_version`, `shadox_version`, `profile`, and `profile_version` so agents can consume reports with explicit compatibility checks.

## Versioned Workspace

`shadox` can act as a transaction layer for agent command execution. In v1 this is command-boundary versioning: shadox records a full workspace checkpoint before the command, records another checkpoint after it, writes a JSONL change journal, and can roll the workspace back when the command fails.

```bash
shadox fs init .
shadox fs checkpoint . --message "known good"
shadox fs checkpoint . --source-run-id <run_id> --message "merge run"

shadox run \
  --profile workspace-write \
  --allow-write . \
  --versioned-workspace . \
  --rollback-on-failure \
  --commit-on-success \
  -- cargo test
```

Useful workspace commands:

```bash
shadox fs log .
shadox fs diff <checkpoint_a> <checkpoint_b> --workspace .
shadox fs rollback <checkpoint_id> --workspace .
shadox fs commit <checkpoint_id> --workspace .
shadox fs status .
shadox fs materialize <checkpoint_id> ./historical-view --workspace .
shadox fs journal <run_id> --workspace .
shadox fs replay <run_id> ./replayed-view --workspace . --until-seq 3
shadox fs op-journal <run_id> --workspace .
shadox fs op-replay <run_id> ./operation-view --workspace . --until-seq 3
shadox fs op-replay <run_id> ./as-of-view --workspace . --until-ts 1790000000000
shadox fs op-restore <run_id> --workspace . --until-ts 1790000000000
shadox fs verify .
shadox fs gc .

cargo run --features fuse -- fs mount ./backing ./mnt --workspace ./backing
```

The run summary includes an `fs` block with `checkpoint_before`, `checkpoint_after`, `journal_path`, changed paths, and whether the run committed or rolled back. File renames are surfaced as `renamed` changes when the content fingerprint matches. The journal is a stable JSONL redo stream with operation names such as `create_file`, `write_file`, `delete_path`, and `rename_path`. This makes each agent command behave like an observable transaction: inspect the summary, keep good changes, recover bad ones, materialize a historical checkpoint, or replay the first N journal events into a separate directory without changing the live workspace.

Replay commands accept `--until-seq` and `--until-ts`, so agents can materialize a view at an event boundary or timestamp without mutating the live workspace. `op-restore` applies an operation replay back to the live workspace when the user wants an actual rollback to that event boundary or timestamp.

V1 stores checkpoint manifests and SHA-256 content objects under `.shadox/fs`. It intentionally skips `.shadox`, `.git`, `target`, and `node_modules`. Use `shadox fs verify` to check that all checkpoint objects are present and uncorrupted, and `shadox fs gc` to remove unreferenced objects.

Committing a checkpoint with a `source_run_id`, or creating a checkpoint with `--source-run-id`, compacts that run: active redo logs are moved under `journals/compacted/` or `operation-journals/compacted/`. `journal`, `replay`, `op-journal`, and `op-replay` still find compacted logs automatically.

The V2 operation-level redo path is available through the Rust API, `op-journal` / `op-replay`, and the optional Linux FUSE passthrough adapter. Build with `--features fuse`, then mount a backing directory into a mountpoint with `shadox fs mount <backing> <mountpoint> --workspace <backing>`. Writes through the mountpoint are applied to the backing directory and recorded as operation-level redo events.

See `docs/agent-contract.md` for the exact workflow an agent should follow when wrapping commands, reading summaries, and recovering changes.

## Programmable Observation

Rhai scripts can define an `on_event(event)` hook. The hook cannot mutate sandbox policy in v1; it only emits findings.

```rhai
fn on_event(event) {
    if event.kind == "stderr.chunk" {
        return #{
            message: "process wrote to stderr",
            severity: "warn",
            tags: ["stderr"]
        };
    }
}
```

The event passed to Rhai contains:

- `schema_version`
- `shadox_version`
- `profile`
- `profile_version`
- `ts`
- `seq`
- `run_id`
- `kind`
- `pid`
- `level`
- `data_json`

Large stdout/stderr streams are budgeted in trace events by `observe.max_trace_output_bytes`, defaulting to 1 MiB per stream. Chunk events keep the original `bytes` value and include `truncated` plus `omitted_bytes` when event text is capped.

## Security Model

`shadox` is a research sandbox and should not be treated as a hardened security boundary.

The default posture is fail-closed. If a requested security primitive is unavailable, the run fails unless `--allow-degraded` is set. Degraded runs are marked in the trace.

The v1 seccomp profile is a conservative blocklist for obviously privileged or introspection-oriented syscalls. Future versions may add strict allowlist profiles.

## Linux Notes

`shadox run` expects Linux with procfs. Landlock requires a recent Linux kernel. Rootless namespace work is intentionally left out of v1; the first milestone focuses on restriction and observability rather than container semantics.
