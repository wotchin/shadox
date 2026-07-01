# Versioned Workspace Design

`shadox` treats the agent as the planner and itself as the execution partner. The agent stays outside the command transaction, while each command can run as a recoverable transaction.

## Goals

- Create a checkpoint before an agent command.
- Record the filesystem changes caused by the command.
- Roll back failed or risky commands without asking the agent to infer the inverse patch.
- Commit accepted changes as the new workspace head.
- Expose recovery state through `trace.jsonl` and `summary.json`.

For the agent-facing command contract, see [Agent Contract](agent-contract.md).

## Non-Goals

- V1 is not a hardened security boundary. Landlock, seccomp, and rlimits are the built-in native enforcement layer; hardened isolation should be supplied by the caller's environment when required.
- V1 is not a full FUSE filesystem. It observes command boundaries rather than every `write(2)` offset.
- V1 does not snapshot ignored build or VCS directories such as `.git`, `.shadox`, `target`, and `node_modules`.

## V1 Model

V1 uses command-boundary versioning:

1. `shadox run --versioned-workspace <path>` creates a checkpoint before spawning the command.
2. After the command exits, shadox creates a second checkpoint.
3. shadox diffs the two checkpoint manifests.
4. shadox writes a JSONL journal for the run.
5. If the command failed and `--rollback-on-failure` is set, shadox materializes the pre-run checkpoint.
6. If the command succeeded and `--commit-on-success` is set, shadox updates the workspace `HEAD` ref to the post-run checkpoint.

The core property is recovery by reconstruction, not undo. Rollback materializes `checkpoint_before`; commit advances a ref to `checkpoint_after`.

## Storage Layout

```text
.shadox/fs/
  objects/
    <content-id>
  checkpoints/
    ckpt_<uuid>.json
  journals/
    <run_id>.jsonl
    compacted/
      <run_id>.jsonl
  operation-journals/
    <run_id>.jsonl
    compacted/
      <run_id>.jsonl
  refs/
    head
```

Checkpoint manifests store relative paths and file objects:

```json
{
  "checkpoint_id": "ckpt_...",
  "parent": "ckpt_...",
  "created_at": 1790000000000,
  "message": "before run ...",
  "source_run_id": "...",
  "entries": {
    "src/main.rs": {
      "type": "file",
      "size": 1234,
      "hash": "...",
      "object": "...",
      "readonly": false
    }
  }
}
```

The content identifier is the SHA-256 digest of the file bytes. This keeps object storage deterministic, enables lightweight integrity checks, and gives diffing a stable content fingerprint for rename detection.

When one path disappears and another file with the same size and SHA-256 appears, V1 reports a `renamed` change with `source_path` set to the old path and `path` set to the new path.

## Trace And Summary Integration

`shadox run` emits:

- `fs.checkpoint` before spawning the command.
- `fs.diff` after the command exits.
- `fs.commit` when the post-run checkpoint becomes the workspace head.
- `fs.rollback` when the pre-run checkpoint is materialized.

`summary.json` includes:

```json
{
  "fs": {
    "enabled": true,
    "workspace": "...",
    "checkpoint_before": "ckpt_...",
    "checkpoint_after": "ckpt_...",
    "journal_path": ".shadox/fs/journals/<run_id>.jsonl",
    "changed_files": 3,
    "changes": [],
    "committed": false,
    "rolled_back": true
  }
}
```

## CLI

```bash
shadox fs init .
shadox fs checkpoint . --message "known good"
shadox fs checkpoint . --source-run-id <run_id> --message "merge run"
shadox fs log .
shadox fs diff <from> <to> --workspace .
shadox fs rollback <checkpoint> --workspace .
shadox fs commit <checkpoint> --workspace .
shadox fs status .
shadox fs materialize <checkpoint> ./historical-view --workspace .
shadox fs journal <run_id> --workspace .
shadox fs replay <run_id> ./replayed-view --workspace . --until-seq 3
shadox fs op-journal <run_id> --workspace .
shadox fs op-replay <run_id> ./operation-view --workspace . --until-seq 3
shadox fs op-replay <run_id> ./as-of-view --workspace . --until-ts 1790000000000
shadox fs op-restore <run_id> --workspace . --until-ts 1790000000000
shadox fs verify .
shadox fs gc .

cargo run --features fuse -- fs mount ./backing ./mnt --workspace ./backing

shadox run \
  --profile workspace-write \
  --allow-write . \
  --versioned-workspace . \
  --rollback-on-failure \
  --commit-on-success \
  -- cargo test
```

`status` compares the live workspace with the current `HEAD` checkpoint. `materialize` writes a checkpoint into an independent directory, which gives agents a safe time-travel view without mutating the workspace. `journal` prints the JSONL redo events for a run as a structured JSON array. `replay` starts from the run journal's base checkpoint and applies change events up to `--until-seq` or `--until-ts`, giving a command-boundary approximation of `checkpoint + redo[0..seq]` or `checkpoint + redo[ts<=T]`. `op-journal` and `op-replay` expose the V2 operation-level redo stream used by lower-level adapters. `op-restore` applies operation replay back to the live workspace for an actual rollback to an event boundary or timestamp. `verify` checks that every checkpoint-referenced object exists and still hashes to its object id. `gc` removes content objects that are not referenced by any checkpoint.

When a checkpoint with a `source_run_id` is committed, or when `fs checkpoint --source-run-id <run_id>` is used, shadox treats the checkpoint as the compacted state for that run. Active redo logs are moved into `journals/compacted/` or `operation-journals/compacted/`. The read and replay commands automatically fall back to compacted journals, so audit and time-travel views still work while the live journal area only contains open increments.

Journal events are versioned so an agent can consume them directly:

```json
{
  "schema_version": 1,
  "seq": 1,
  "ts": 1790000000000,
  "run_id": "...",
  "op": "write_file",
  "path": "src/main.rs",
  "source_path": null,
  "base_checkpoint": "ckpt_...",
  "target_checkpoint": "ckpt_...",
  "before": {},
  "after": {}
}
```

## V2 Direction

The FUSE-backed design should keep the same checkpoint and summary contract but replace command-boundary journals with operation-level redo logs. The storage and replay foundation now exists as `WorkspaceOperationEvent`, `WorkspaceOperation`, `WorkspaceOperationRecorder`, `append_operation_event`, `append_write_operation`, `op-journal`, and `op-replay`.

```text
create_file
create_dir
write { path, offset, object, len }
truncate
unlink
rename
chmod
symlink
set_xattr
fsync
```

Operation journals are stored under `.shadox/fs/operation-journals/<run_id>.jsonl`. Write payloads are content-addressed objects in `.shadox/fs/objects`, so operation replay uses the same integrity and storage model as checkpoints. The replay engine validates paths before applying operations, which keeps materialized views inside their destination directory.

`WorkspaceOperationRecorder` is the adapter boundary for FUSE or any other write-intercepting layer:

1. `WorkspaceOperationRecorder::begin(root, run_id)` creates the base checkpoint.
2. The adapter calls `record_create_file`, `record_create_dir`, `record_write`, `record_truncate`, `record_delete_path`, `record_rename_path`, `record_chmod`, or `record_fsync` as operations occur.
3. `finish(commit)` creates the post-run checkpoint and optionally advances `HEAD`.

That keeps checkpoint ownership, run ids, base-checkpoint consistency, object storage, and event sequencing out of the FUSE mount implementation.

An optional Linux FUSE passthrough adapter is available behind the `fuse` Cargo feature. It mounts a backing directory at a mountpoint, forwards basic file operations to the backing directory, and records writes, creates, mkdirs, truncates, deletes, renames, chmods, and fsyncs through `WorkspaceOperationRecorder`.

With the FUSE adapter feeding these events, time travel becomes `checkpoint + redo[0..seq]`, and shadox can recover to event boundaries inside a long-running command. The agent-facing API does not need to change; it simply receives more precise filesystem evidence.
