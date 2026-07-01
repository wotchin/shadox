# Ecosystem Positioning

`shadox` sits between agent frameworks and the real execution environment.

Agent frameworks orchestrate intent. Shadox manages command side effects.

```text
Agent / planner
  -> agent framework or IDE agent
  -> shadox command transaction
  -> local shell, CI runner, container, VM, or remote environment
```

The stable contract is ordinary command execution plus agent-readable state:

- explicit effective policy before a run
- JSONL trace during a run
- final JSON summary after a run
- failure classification and diagnostics
- workspace checkpoint, diff, rollback, commit, replay, and materialize

Shadox is intentionally not an agent framework, not a container runtime, and not a hardened isolation boundary by itself.

## The Niche

Most agent frameworks already have planner loops, tool routing, memory, persistence, streaming, and human-in-the-loop controls. Those layers answer questions such as:

- What should the agent do next?
- Which tool should run?
- Should a human approve this action?
- How does the workflow resume?

Shadox answers a lower-level but high-impact question:

- What did this command actually do to the workspace, and can the agent recover from it?

That gives shadox a narrow and durable role: **the command transaction layer for agents**.

## Integration Modes

### 1. CLI Contract

The CLI is the primary integration surface because every agent framework can execute a command.

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

After the command exits, the framework reads the summary and decides whether to continue, inspect, retry, rollback, or ask for human review.

### 2. Machine-Readable Discovery

Agents should discover the contract before using it:

```bash
shadox agent-guide --format markdown
shadox capabilities --format json
shadox explain --profile workspace-write --allow-write . -- cargo test
```

`agent-guide` is for operational guidance. `capabilities` is for tool construction and compatibility checks. `explain` is for inspecting the effective policy before a run.

### 3. MCP Surface

An MCP server is a good optional distribution format for the same contract:

```text
shadox.capabilities
shadox.agent_guide
shadox.explain
shadox.run
shadox.fs_status
shadox.fs_checkpoint
shadox.fs_rollback
shadox.fs_materialize
shadox.fs_replay
```

The MCP layer should stay thin. It should expose shadox commands and reports; it should not become a planner, a container adapter, or a separate execution semantics.

### 4. Thin Framework Examples

Framework-specific integrations should live as examples, not as core product dependencies.

| Ecosystem | Recommended integration |
| --- | --- |
| LangGraph | Wrap `shadox run` in a tool node; persist `summary.json` in graph state. |
| OpenAI Agents SDK | Expose shadox through MCP or a small function tool that shells out to the CLI. |
| AutoGen | Implement a code executor that wraps commands with `shadox run`. |
| IDE agents | Replace direct shell execution for risky commands with `shadox run`. |
| CI agents | Use shadox around generation, formatting, migrations, and tests to capture recovery evidence. |
| Custom agents | Call the CLI directly and treat the summary as the command transaction record. |

## External Isolation

Hardened isolation should be supplied by the caller's trusted environment when needed.

Shadox should not grow provider-specific command switches such as a Docker mode. That would force shadox to track container, VM, and sandbox semantics that are outside its core value.

The universal composition surface is simpler:

- run shadox inside a trusted external boundary, or
- ask shadox to run a command that is already wrapped by that boundary, or
- use shadox in local developer workflows where the built-in Linux enforcement layer is sufficient.

In every case, shadox keeps the same role: observable, reversible command execution.

## Product Boundaries

Shadox owns:

- command lifecycle
- trace and summary schema
- failure classification
- diagnostic hints
- workspace recovery and time-travel views
- agent-facing discovery docs and capabilities

Shadox does not own:

- agent planning
- model orchestration
- provider-specific container or VM control
- hardened multi-tenant isolation
- long-running workflow state

This boundary is what keeps shadox composable with real-world agent stacks without becoming another framework or another sandbox runtime.
