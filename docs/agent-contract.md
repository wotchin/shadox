# Agent Contract

`shadox` is an execution partner for agents. The agent remains the planner and calls `shadox` around commands that can change the workspace.

## Default Pattern

Use `shadox run` for any command that can create, modify, delete, move, generate, or format workspace files:

```bash
shadox run \
  --profile workspace-write \
  --allow-write . \
  --versioned-workspace . \
  --rollback-on-failure \
  --summary .shadox/last-summary.json \
  --trace .shadox/last-trace.jsonl \
  -- cargo test
```

For trusted commands whose result should become the workspace baseline when they succeed, add `--commit-on-success`.

## Result Fields

After every wrapped command, read `summary.json`:

- `failure.kind`: command outcome such as `success`, `exit_non_zero`, `timeout`, `seccomp_denied`, or `landlock_denied`.
- `fs.checkpoint_before`: workspace checkpoint before the command.
- `fs.checkpoint_after`: workspace checkpoint after the command.
- `fs.changed_files`: number of changed file paths.
- `fs.changes`: structured path-level change list.
- `fs.journal_path`: JSONL redo stream for this run.
- `fs.committed`: whether `checkpoint_after` became workspace `HEAD`.
- `fs.rolled_back`: whether shadox restored `checkpoint_before`.

The agent should treat this block as the command transaction record. Do not infer recovery state from stdout text.

## Recovery Rules

When `--rollback-on-failure` is set and the command fails, shadox restores the live workspace to `checkpoint_before`. The agent can still inspect what happened:

```bash
shadox fs journal <run_id> --workspace .
shadox fs replay <run_id> ./replayed-view --workspace . --until-seq 3
shadox fs op-journal <run_id> --workspace .
shadox fs op-replay <run_id> ./operation-view --workspace . --until-seq 3
shadox fs op-replay <run_id> ./as-of-view --workspace . --until-ts 1790000000000
shadox fs op-restore <run_id> --workspace . --until-ts 1790000000000
shadox fs materialize <checkpoint_after> ./failed-result --workspace .
```

When rollback is not enabled, the agent can explicitly recover:

```bash
shadox fs rollback <checkpoint_before> --workspace .
```

When a successful result should be accepted as the new baseline:

```bash
shadox fs commit <checkpoint_after> --workspace .
```

Commit compacts that run's active redo logs into the compacted journal area. The agent should keep using `journal`, `replay`, `op-journal`, and `op-replay`; those commands resolve compacted journals automatically.

If the agent wants to make an explicit checkpoint from a run without using `commit`, use `shadox fs checkpoint . --source-run-id <run_id> --message "merge run"`; this also compacts the run's active redo logs.

## Inspection Rules

Use `status` before starting a risky operation if the workspace may already have uncommitted changes:

```bash
shadox fs status .
```

Use `verify` before relying on old checkpoints for recovery:

```bash
shadox fs verify .
```

Use `materialize` instead of rollback when the agent only needs to compare a historical state:

```bash
shadox fs materialize <checkpoint> ./historical-view --workspace .
```

## V1 Boundary

V1 journals command-boundary diffs. It can recover to `checkpoint_before`, `checkpoint_after`, or a replay prefix of the path-level journal. The V2 redo foundation can also replay operation-level journals with `op-replay`, including write offsets and content-addressed payload objects.

For write-level time travel, build with `--features fuse` and run commands through `shadox fs mount <backing> <mountpoint> --workspace <backing>`. The FUSE passthrough adapter feeds operation events into the same store, so the recovery workflow remains `op-journal` and `op-replay`.
