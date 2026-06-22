# shadox

`shadox` is a research-oriented, rootless-first, process-level sandbox runtime for Linux.

It is not a Docker competitor. The goal is to run ordinary commands with a small set of Linux restriction primitives and produce agent-friendly traces that explain what happened.

## What v1 Does

- Runs one process under a supervised sandbox.
- Applies `no_new_privs`, `rlimit`, Landlock filesystem restrictions, and a basic seccomp blocklist on Linux.
- Captures stdout/stderr as JSONL trace events.
- Samples `/proc` for lightweight process-tree resource telemetry.
- Reads cgroup v2 stats when available, without creating or managing cgroups.
- Writes a `summary.json` report at the end of the run.
- Classifies failures as timeout, signal, non-zero exit, seccomp-denied, Landlock-like denial, or OOM-like.
- Supports Rhai scripts as programmable observation rules.
- Builds on non-Linux hosts, but `shadox run` is Linux-only.

## Quick Start

```bash
cargo build

shadox check-env --json

shadox run --config examples/shadox.toml

shadox run \
  --allow-write . \
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

## Trace Event Shape

Each JSONL event uses a stable envelope:

```json
{
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

Landlock denials usually appear to the child as ordinary `EACCES` or `EPERM`, so v1 classifies them with medium confidence based on stderr signatures. Seccomp denials in the basic profile use `SIGSYS`, which gives the parent a high-confidence classification signal.

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

- `ts`
- `seq`
- `run_id`
- `kind`
- `pid`
- `level`
- `data_json`

## Security Model

`shadox` is a research sandbox and should not be treated as a hardened security boundary.

The default posture is fail-closed. If a requested security primitive is unavailable, the run fails unless `--allow-degraded` is set. Degraded runs are marked in the trace.

The v1 seccomp profile is a conservative blocklist for obviously privileged or introspection-oriented syscalls. Future versions may add strict allowlist profiles.

## Linux Notes

`shadox run` expects Linux with procfs. Landlock requires a recent Linux kernel. Rootless namespace work is intentionally left out of v1; the first milestone focuses on restriction and observability rather than container semantics.
