use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const STORE_DIR: &str = ".shadox/fs";
const OBJECT_DIR: &str = "objects";
const CHECKPOINT_DIR: &str = "checkpoints";
const JOURNAL_DIR: &str = "journals";
const OPERATION_JOURNAL_DIR: &str = "operation-journals";
const COMPACTED_DIR: &str = "compacted";
const RESTORE_DIR: &str = "restores";
const REF_DIR: &str = "refs";
const HEAD_REF: &str = "head";
const IGNORED_DIRS: &[&str] = &[".git", ".shadox", "target", "node_modules"];
const FS_JOURNAL_SCHEMA_VERSION: u32 = 1;
const FS_OPERATION_JOURNAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceCheckpoint {
    pub checkpoint_id: String,
    pub parent: Option<String>,
    pub created_at: u128,
    pub message: Option<String>,
    pub source_run_id: Option<Uuid>,
    pub root: PathBuf,
    #[serde(default)]
    pub entries: BTreeMap<String, WorkspaceEntry>,
}

impl WorkspaceCheckpoint {
    pub fn summary(&self) -> WorkspaceCheckpointSummary {
        WorkspaceCheckpointSummary {
            checkpoint_id: self.checkpoint_id.clone(),
            parent: self.parent.clone(),
            created_at: self.created_at,
            message: self.message.clone(),
            source_run_id: self.source_run_id,
            entry_count: self.entries.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceCheckpointSummary {
    pub checkpoint_id: String,
    pub parent: Option<String>,
    pub created_at: u128,
    pub message: Option<String>,
    pub source_run_id: Option<Uuid>,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceEntry {
    File {
        size: u64,
        hash: String,
        object: String,
        readonly: bool,
    },
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceDiff {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub changes: Vec<WorkspaceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceChange {
    pub kind: WorkspaceChangeKind,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub before: Option<WorkspaceEntry>,
    pub after: Option<WorkspaceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    TypeChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRollbackReport {
    pub checkpoint_id: String,
    pub restored_files: usize,
    pub restored_dirs: usize,
    pub removed_paths: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceVerifyReport {
    pub ok: bool,
    pub checkpoint_count: usize,
    pub object_count: usize,
    #[serde(default)]
    pub missing_objects: Vec<String>,
    #[serde(default)]
    pub corrupt_objects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceGcReport {
    pub referenced_objects: usize,
    pub removed_objects: usize,
    pub removed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceCommitReport {
    pub checkpoint_id: String,
    pub source_run_id: Option<Uuid>,
    pub compacted_journals: usize,
    pub journal_path: Option<PathBuf>,
    pub operation_journal_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceMaterializeReport {
    pub checkpoint_id: String,
    pub destination: PathBuf,
    pub restored_files: usize,
    pub restored_dirs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceStatusReport {
    pub head: Option<String>,
    pub dirty: bool,
    #[serde(default)]
    pub changes: Vec<WorkspaceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceReplayReport {
    pub run_id: String,
    pub checkpoint_id: String,
    pub until_seq: Option<usize>,
    pub until_ts: Option<u128>,
    pub applied_events: usize,
    pub destination: PathBuf,
    pub restored_files: usize,
    pub restored_dirs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceOperationReplayReport {
    pub run_id: String,
    pub base_checkpoint: String,
    pub until_seq: Option<usize>,
    pub until_ts: Option<u128>,
    pub applied_events: usize,
    pub destination: PathBuf,
    pub restored_files: usize,
    pub restored_dirs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceOperationRecorderOutcome {
    pub workspace: PathBuf,
    pub run_id: Uuid,
    pub base_checkpoint: String,
    pub checkpoint_after: String,
    pub journal_path: PathBuf,
    pub operation_count: usize,
    pub committed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceJournalEvent {
    pub schema_version: u32,
    pub seq: usize,
    pub ts: u128,
    pub run_id: Uuid,
    pub op: WorkspaceJournalOp,
    pub path: String,
    #[serde(default)]
    pub source_path: Option<String>,
    pub base_checkpoint: String,
    pub target_checkpoint: String,
    pub before: Option<WorkspaceEntry>,
    pub after: Option<WorkspaceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceJournalOp {
    CreateFile,
    WriteFile,
    DeletePath,
    RenamePath,
    TypeChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceOperationEvent {
    pub schema_version: u32,
    pub seq: usize,
    pub ts: u128,
    pub run_id: Uuid,
    pub base_checkpoint: String,
    #[serde(flatten)]
    pub op: WorkspaceOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WorkspaceOperation {
    CreateFile {
        path: String,
    },
    CreateDir {
        path: String,
    },
    Write {
        path: String,
        offset: u64,
        object: String,
        len: u64,
    },
    Truncate {
        path: String,
        len: u64,
    },
    DeletePath {
        path: String,
    },
    RenamePath {
        source_path: String,
        path: String,
    },
    Chmod {
        path: String,
        readonly: bool,
    },
    Fsync {
        path: String,
    },
}

pub struct WorkspaceOperationRecorder {
    store: WorkspaceStore,
    run_id: Uuid,
    base_checkpoint: String,
}

impl WorkspaceOperationRecorder {
    pub fn begin(
        root: impl AsRef<Path>,
        run_id: Uuid,
    ) -> anyhow::Result<(Self, WorkspaceCheckpoint)> {
        let store = WorkspaceStore::open(root)?;
        let checkpoint = store.create_checkpoint(
            Some(format!("operation base {run_id}")),
            Some(run_id),
            false,
        )?;
        let recorder = Self {
            store,
            run_id,
            base_checkpoint: checkpoint.checkpoint_id.clone(),
        };
        Ok((recorder, checkpoint))
    }

    pub fn from_checkpoint(
        root: impl AsRef<Path>,
        run_id: Uuid,
        base_checkpoint: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let store = WorkspaceStore::open(root)?;
        let base_checkpoint = base_checkpoint.into();
        store.load_checkpoint(&base_checkpoint)?;
        Ok(Self {
            store,
            run_id,
            base_checkpoint,
        })
    }

    pub fn workspace(&self) -> &Path {
        self.store.root()
    }

    pub fn run_id(&self) -> Uuid {
        self.run_id
    }

    pub fn base_checkpoint(&self) -> &str {
        &self.base_checkpoint
    }

    pub fn record(&self, op: WorkspaceOperation) -> anyhow::Result<WorkspaceOperationEvent> {
        self.store
            .append_operation_event(self.run_id, self.base_checkpoint.clone(), op)
    }

    pub fn record_create_file(
        &self,
        path: impl Into<String>,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::CreateFile { path: path.into() })
    }

    pub fn record_create_dir(
        &self,
        path: impl Into<String>,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::CreateDir { path: path.into() })
    }

    pub fn record_write(
        &self,
        path: impl Into<String>,
        offset: u64,
        bytes: &[u8],
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.store.append_write_operation(
            self.run_id,
            self.base_checkpoint.clone(),
            path,
            offset,
            bytes,
        )
    }

    pub fn record_truncate(
        &self,
        path: impl Into<String>,
        len: u64,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::Truncate {
            path: path.into(),
            len,
        })
    }

    pub fn record_delete_path(
        &self,
        path: impl Into<String>,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::DeletePath { path: path.into() })
    }

    pub fn record_rename_path(
        &self,
        source_path: impl Into<String>,
        path: impl Into<String>,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::RenamePath {
            source_path: source_path.into(),
            path: path.into(),
        })
    }

    pub fn record_chmod(
        &self,
        path: impl Into<String>,
        readonly: bool,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::Chmod {
            path: path.into(),
            readonly,
        })
    }

    pub fn record_fsync(&self, path: impl Into<String>) -> anyhow::Result<WorkspaceOperationEvent> {
        self.record(WorkspaceOperation::Fsync { path: path.into() })
    }

    pub fn events(&self) -> anyhow::Result<Vec<WorkspaceOperationEvent>> {
        self.store.list_operation_journal(&self.run_id.to_string())
    }

    pub fn finish(self, commit: bool) -> anyhow::Result<WorkspaceOperationRecorderOutcome> {
        let checkpoint_after = self.store.create_checkpoint(
            Some(format!("operation after {}", self.run_id)),
            Some(self.run_id),
            false,
        )?;
        let operation_count = self.events()?.len();
        let mut journal_path = self.store.operation_journal_path(&self.run_id.to_string());
        if commit {
            let report = self
                .store
                .commit_with_report(&checkpoint_after.checkpoint_id)?;
            if let Some(path) = report.operation_journal_path {
                journal_path = path;
            }
        }
        Ok(WorkspaceOperationRecorderOutcome {
            workspace: self.store.root.clone(),
            run_id: self.run_id,
            base_checkpoint: self.base_checkpoint,
            checkpoint_after: checkpoint_after.checkpoint_id,
            journal_path,
            operation_count,
            committed: commit,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedRunSession {
    pub workspace: PathBuf,
    pub checkpoint_before: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionedRunOutcome {
    pub workspace: PathBuf,
    pub checkpoint_before: String,
    pub checkpoint_after: String,
    pub journal_path: PathBuf,
    pub changed_files: usize,
    pub changes: Vec<WorkspaceChange>,
    pub committed: bool,
    pub rolled_back: bool,
    pub rollback: Option<WorkspaceRollbackReport>,
}

pub struct WorkspaceTransaction {
    store: WorkspaceStore,
    session: Option<VersionedRunSession>,
    run_id: Uuid,
}

impl WorkspaceTransaction {
    pub fn begin(
        root: impl AsRef<Path>,
        run_id: Uuid,
    ) -> anyhow::Result<(Self, WorkspaceCheckpoint)> {
        let (store, session, checkpoint) = WorkspaceStore::begin_run(root, run_id)?;
        Ok((
            Self {
                store,
                session: Some(session),
                run_id,
            },
            checkpoint,
        ))
    }

    pub fn workspace(&self) -> &Path {
        self.store.root()
    }

    pub fn checkpoint_before(&self) -> Option<&str> {
        self.session
            .as_ref()
            .map(|session| session.checkpoint_before.as_str())
    }

    pub fn finish(
        mut self,
        command_succeeded: bool,
        rollback_on_failure: bool,
        commit_on_success: bool,
    ) -> anyhow::Result<VersionedRunOutcome> {
        let session = self
            .session
            .take()
            .ok_or_else(|| anyhow::anyhow!("workspace transaction was already finished"))?;
        self.store.finish_run(
            session,
            self.run_id,
            command_succeeded,
            rollback_on_failure,
            commit_on_success,
        )
    }

    pub fn into_parts(mut self) -> anyhow::Result<(WorkspaceStore, VersionedRunSession, Uuid)> {
        let session = self
            .session
            .take()
            .ok_or_else(|| anyhow::anyhow!("workspace transaction was already finished"))?;
        Ok((self.store, session, self.run_id))
    }
}

pub struct WorkspaceStore {
    root: PathBuf,
    store: PathBuf,
}

impl WorkspaceStore {
    pub fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = normalize_root(root.as_ref())?;
        let store = root.join(STORE_DIR);
        fs::create_dir_all(store.join(OBJECT_DIR))?;
        fs::create_dir_all(store.join(CHECKPOINT_DIR))?;
        fs::create_dir_all(store.join(JOURNAL_DIR))?;
        fs::create_dir_all(store.join(JOURNAL_DIR).join(COMPACTED_DIR))?;
        fs::create_dir_all(store.join(OPERATION_JOURNAL_DIR))?;
        fs::create_dir_all(store.join(OPERATION_JOURNAL_DIR).join(COMPACTED_DIR))?;
        fs::create_dir_all(store.join(RESTORE_DIR))?;
        fs::create_dir_all(store.join(REF_DIR))?;
        Ok(Self { root, store })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_checkpoint(
        &self,
        message: Option<String>,
        source_run_id: Option<Uuid>,
        update_head: bool,
    ) -> anyhow::Result<WorkspaceCheckpoint> {
        let checkpoint_id = new_checkpoint_id();
        let parent = self.head()?;
        let entries = self.snapshot_entries()?;
        let checkpoint = WorkspaceCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            parent,
            created_at: epoch_millis(),
            message,
            source_run_id,
            root: self.root.clone(),
            entries,
        };
        self.write_checkpoint(&checkpoint)?;
        if update_head {
            self.commit(&checkpoint_id)?;
        }
        Ok(checkpoint)
    }

    pub fn load_checkpoint(&self, checkpoint_id: &str) -> anyhow::Result<WorkspaceCheckpoint> {
        let path = self.checkpoint_path(checkpoint_id);
        let text = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("failed to read checkpoint {checkpoint_id}: {err}"))?;
        let checkpoint = serde_json::from_str(&text)
            .map_err(|err| anyhow::anyhow!("failed to parse checkpoint {checkpoint_id}: {err}"))?;
        Ok(checkpoint)
    }

    pub fn diff_checkpoints(&self, from: &str, to: &str) -> anyhow::Result<WorkspaceDiff> {
        let from_checkpoint = self.load_checkpoint(from)?;
        let to_checkpoint = self.load_checkpoint(to)?;
        Ok(diff_manifests(&from_checkpoint, &to_checkpoint))
    }

    pub fn rollback(&self, checkpoint_id: &str) -> anyhow::Result<WorkspaceRollbackReport> {
        let checkpoint = self.load_checkpoint(checkpoint_id)?;
        let current = self.snapshot_entries_without_objects()?;
        let target_paths = checkpoint.entries.keys().cloned().collect::<BTreeSet<_>>();
        let mut removed_paths = 0;

        let mut removable = current
            .keys()
            .filter(|path| !target_paths.contains(*path))
            .cloned()
            .collect::<Vec<_>>();
        removable.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
        for relative in removable {
            let path = self.root.join(relative_path(&relative));
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else if path.exists() {
                fs::remove_file(&path)?;
            }
            removed_paths += 1;
        }

        let mut dirs = checkpoint
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                matches!(entry, WorkspaceEntry::Directory).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        dirs.sort_by_key(|path| path_depth(path));
        for relative in &dirs {
            fs::create_dir_all(self.root.join(relative_path(relative)))?;
        }

        let mut restored_files = 0;
        for (relative, entry) in &checkpoint.entries {
            let WorkspaceEntry::File {
                object, readonly, ..
            } = entry
            else {
                continue;
            };
            let destination = self.root.join(relative_path(relative));
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(self.object_path(object), &destination)?;
            let mut permissions = fs::metadata(&destination)?.permissions();
            permissions.set_readonly(*readonly);
            fs::set_permissions(&destination, permissions)?;
            restored_files += 1;
        }

        Ok(WorkspaceRollbackReport {
            checkpoint_id: checkpoint_id.to_string(),
            restored_files,
            restored_dirs: dirs.len(),
            removed_paths,
        })
    }

    pub fn materialize(
        &self,
        checkpoint_id: &str,
        destination: impl AsRef<Path>,
        force: bool,
    ) -> anyhow::Result<WorkspaceMaterializeReport> {
        let checkpoint = self.load_checkpoint(checkpoint_id)?;
        let destination = destination.as_ref();
        if destination.exists() {
            if !force && destination.read_dir()?.next().is_some() {
                return Err(anyhow::anyhow!(
                    "destination is not empty; pass --force to replace it"
                ));
            }
            if force {
                fs::remove_dir_all(destination)?;
            }
        }
        fs::create_dir_all(destination)?;
        let (restored_files, restored_dirs) =
            self.write_checkpoint_to_root(&checkpoint, destination)?;
        Ok(WorkspaceMaterializeReport {
            checkpoint_id: checkpoint_id.to_string(),
            destination: fs::canonicalize(destination)?,
            restored_files,
            restored_dirs,
        })
    }

    pub fn status(&self) -> anyhow::Result<WorkspaceStatusReport> {
        let Some(head) = self.head()? else {
            return Ok(WorkspaceStatusReport {
                head: None,
                dirty: false,
                changes: Vec::new(),
            });
        };
        let head_checkpoint = self.load_checkpoint(&head)?;
        let current = WorkspaceCheckpoint {
            checkpoint_id: "workspace".to_string(),
            parent: Some(head.clone()),
            created_at: epoch_millis(),
            message: Some("current workspace".to_string()),
            source_run_id: None,
            root: self.root.clone(),
            entries: self.snapshot_entries_without_objects()?,
        };
        let diff = diff_manifests(&head_checkpoint, &current);
        Ok(WorkspaceStatusReport {
            head: Some(head),
            dirty: !diff.changes.is_empty(),
            changes: diff.changes,
        })
    }

    pub fn replay_journal(
        &self,
        run_id: &str,
        until_seq: Option<usize>,
        until_ts: Option<u128>,
        destination: impl AsRef<Path>,
        force: bool,
    ) -> anyhow::Result<WorkspaceReplayReport> {
        let events = self.read_journal(run_id)?;
        let Some(first) = events.first() else {
            return Err(anyhow::anyhow!(
                "journal {run_id} has no change events to replay"
            ));
        };
        let base_checkpoint_id = first.base_checkpoint.clone();
        let source_run_id = first.run_id;
        let base = self.load_checkpoint(&base_checkpoint_id)?;
        let mut entries = base.entries.clone();
        let mut applied_events = 0;

        for event in events {
            if !journal_event_within_limit(&event, until_seq, until_ts) {
                continue;
            }
            apply_journal_event(&mut entries, &event)?;
            applied_events += 1;
        }

        let replay = WorkspaceCheckpoint {
            checkpoint_id: format!(
                "{}_replay_{}",
                base.checkpoint_id,
                until_seq
                    .map(|seq| seq.to_string())
                    .unwrap_or_else(|| "all".to_string())
            ),
            parent: Some(base.checkpoint_id.clone()),
            created_at: epoch_millis(),
            message: Some(format!("replay journal {run_id}")),
            source_run_id: Some(source_run_id),
            root: self.root.clone(),
            entries,
        };

        let destination = destination.as_ref();
        if destination.exists() {
            if !force && destination.read_dir()?.next().is_some() {
                return Err(anyhow::anyhow!(
                    "destination is not empty; pass --force to replace it"
                ));
            }
            if force {
                fs::remove_dir_all(destination)?;
            }
        }
        fs::create_dir_all(destination)?;
        let (restored_files, restored_dirs) =
            self.write_checkpoint_to_root(&replay, destination)?;

        Ok(WorkspaceReplayReport {
            run_id: run_id.to_string(),
            checkpoint_id: replay.checkpoint_id,
            until_seq,
            until_ts,
            applied_events,
            destination: fs::canonicalize(destination)?,
            restored_files,
            restored_dirs,
        })
    }

    pub fn append_operation_event(
        &self,
        run_id: Uuid,
        base_checkpoint: impl Into<String>,
        op: WorkspaceOperation,
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        validate_operation(&op)?;
        let base_checkpoint = base_checkpoint.into();
        let run_id_string = run_id.to_string();
        if self
            .compacted_operation_journal_path(&run_id_string)
            .exists()
        {
            return Err(anyhow::anyhow!(
                "operation journal {run_id} is compacted and cannot be appended"
            ));
        }
        let path = self.operation_journal_path(&run_id_string);
        let existing = if path.exists() {
            self.read_operation_journal(&run_id_string)?
        } else {
            Vec::new()
        };
        if let Some(first) = existing.first() {
            if first.run_id != run_id {
                return Err(anyhow::anyhow!(
                    "operation journal file name and event run_id do not match"
                ));
            }
            if first.base_checkpoint != base_checkpoint {
                return Err(anyhow::anyhow!(
                    "operation journal {run_id} already uses base checkpoint {}",
                    first.base_checkpoint
                ));
            }
        };
        let seq = existing.len() + 1;
        let event = WorkspaceOperationEvent {
            schema_version: FS_OPERATION_JOURNAL_SCHEMA_VERSION,
            seq,
            ts: epoch_millis(),
            run_id,
            base_checkpoint,
            op,
        };
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        Ok(event)
    }

    pub fn append_write_operation(
        &self,
        run_id: Uuid,
        base_checkpoint: impl Into<String>,
        path: impl Into<String>,
        offset: u64,
        bytes: &[u8],
    ) -> anyhow::Result<WorkspaceOperationEvent> {
        let object = self.store_bytes(bytes)?;
        self.append_operation_event(
            run_id,
            base_checkpoint,
            WorkspaceOperation::Write {
                path: path.into(),
                offset,
                object,
                len: bytes.len() as u64,
            },
        )
    }

    pub fn list_operation_journal(
        &self,
        run_id: &str,
    ) -> anyhow::Result<Vec<WorkspaceOperationEvent>> {
        self.read_operation_journal(run_id)
    }

    pub fn replay_operation_journal(
        &self,
        run_id: &str,
        until_seq: Option<usize>,
        until_ts: Option<u128>,
        destination: impl AsRef<Path>,
        force: bool,
    ) -> anyhow::Result<WorkspaceOperationReplayReport> {
        let events = self.read_operation_journal(run_id)?;
        let Some(first) = events.first() else {
            return Err(anyhow::anyhow!(
                "operation journal {run_id} has no events to replay"
            ));
        };
        let base_checkpoint = first.base_checkpoint.clone();
        let materialized = self.materialize(&base_checkpoint, destination, force)?;
        let mut applied_events = 0;

        for event in events {
            if !operation_event_within_limit(&event, until_seq, until_ts) {
                continue;
            }
            apply_operation_event(self, &materialized.destination, &event)?;
            applied_events += 1;
        }

        Ok(WorkspaceOperationReplayReport {
            run_id: run_id.to_string(),
            base_checkpoint,
            until_seq,
            until_ts,
            applied_events,
            destination: materialized.destination,
            restored_files: materialized.restored_files,
            restored_dirs: materialized.restored_dirs,
        })
    }

    pub fn restore_operation_journal(
        &self,
        run_id: &str,
        until_seq: Option<usize>,
        until_ts: Option<u128>,
    ) -> anyhow::Result<WorkspaceOperationReplayReport> {
        let temp = self
            .store
            .join(RESTORE_DIR)
            .join(format!("restore_{}", Uuid::new_v4().simple()));
        let mut report =
            self.replay_operation_journal(run_id, until_seq, until_ts, &temp, false)?;
        replace_workspace_from_dir(self, &temp)?;
        fs::remove_dir_all(&temp)?;
        report.destination = self.root.clone();
        Ok(report)
    }

    pub fn commit(&self, checkpoint_id: &str) -> anyhow::Result<()> {
        self.commit_with_report(checkpoint_id).map(|_| ())
    }

    pub fn commit_with_report(&self, checkpoint_id: &str) -> anyhow::Result<WorkspaceCommitReport> {
        let path = self.checkpoint_path(checkpoint_id);
        if !path.exists() {
            return Err(anyhow::anyhow!("unknown checkpoint: {checkpoint_id}"));
        }
        let checkpoint = self.load_checkpoint(checkpoint_id)?;
        fs::write(self.head_path(), format!("{checkpoint_id}\n"))?;
        let mut compacted_journals = 0;
        let mut journal_path = None;
        let mut operation_journal_path = None;

        if let Some(run_id) = checkpoint.source_run_id {
            let report = self.compact_run_journals(run_id)?;
            compacted_journals = report.compacted_journals;
            journal_path = report.journal_path;
            operation_journal_path = report.operation_journal_path;
        }

        Ok(WorkspaceCommitReport {
            checkpoint_id: checkpoint_id.to_string(),
            source_run_id: checkpoint.source_run_id,
            compacted_journals,
            journal_path,
            operation_journal_path,
        })
    }

    pub fn compact_run_journals(&self, run_id: Uuid) -> anyhow::Result<WorkspaceCommitReport> {
        let run_id_string = run_id.to_string();
        let journal_path = self.compact_journal_file(
            self.journal_path(&run_id_string),
            self.compacted_journal_path(&run_id_string),
        )?;
        let operation_journal_path = self.compact_journal_file(
            self.operation_journal_path(&run_id_string),
            self.compacted_operation_journal_path(&run_id_string),
        )?;
        let compacted_journals =
            usize::from(journal_path.is_some()) + usize::from(operation_journal_path.is_some());
        Ok(WorkspaceCommitReport {
            checkpoint_id: String::new(),
            source_run_id: Some(run_id),
            compacted_journals,
            journal_path,
            operation_journal_path,
        })
    }

    pub fn head(&self) -> anyhow::Result<Option<String>> {
        let path = self.head_path();
        if !path.exists() {
            return Ok(None);
        }
        let value = fs::read_to_string(path)?.trim().to_string();
        Ok((!value.is_empty()).then_some(value))
    }

    pub fn list_checkpoints(&self) -> anyhow::Result<Vec<WorkspaceCheckpointSummary>> {
        let mut checkpoints = Vec::new();
        for entry in fs::read_dir(self.store.join(CHECKPOINT_DIR))? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            let checkpoint = serde_json::from_str::<WorkspaceCheckpoint>(&text)?;
            checkpoints.push(checkpoint.summary());
        }
        checkpoints.sort_by_key(|checkpoint| checkpoint.created_at);
        Ok(checkpoints)
    }

    pub fn list_journal(&self, run_id: &str) -> anyhow::Result<Vec<WorkspaceJournalEvent>> {
        self.read_journal(run_id)
    }

    pub fn verify(&self) -> anyhow::Result<WorkspaceVerifyReport> {
        let checkpoints = self.load_all_checkpoints()?;
        let referenced = referenced_objects(&checkpoints);
        let mut missing_objects = Vec::new();
        let mut corrupt_objects = Vec::new();

        for object in &referenced {
            let path = self.object_path(object);
            if !path.exists() {
                missing_objects.push(object.clone());
                continue;
            }
            let actual = file_fingerprint(&path)?;
            if actual != *object {
                corrupt_objects.push(object.clone());
            }
        }

        let object_count = fs::read_dir(self.store.join(OBJECT_DIR))?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .count();

        Ok(WorkspaceVerifyReport {
            ok: missing_objects.is_empty() && corrupt_objects.is_empty(),
            checkpoint_count: checkpoints.len(),
            object_count,
            missing_objects,
            corrupt_objects,
        })
    }

    pub fn gc(&self) -> anyhow::Result<WorkspaceGcReport> {
        let checkpoints = self.load_all_checkpoints()?;
        let referenced = referenced_objects(&checkpoints);
        let mut removed_objects = 0;
        let mut removed_bytes = 0;

        for entry in fs::read_dir(self.store.join(OBJECT_DIR))? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if referenced.contains(name) {
                continue;
            }
            let len = fs::metadata(&path)?.len();
            fs::remove_file(path)?;
            removed_objects += 1;
            removed_bytes += len;
        }

        Ok(WorkspaceGcReport {
            referenced_objects: referenced.len(),
            removed_objects,
            removed_bytes,
        })
    }

    pub fn begin_run(
        root: impl AsRef<Path>,
        run_id: Uuid,
    ) -> anyhow::Result<(Self, VersionedRunSession, WorkspaceCheckpoint)> {
        let store = Self::open(root)?;
        let checkpoint =
            store.create_checkpoint(Some(format!("before run {run_id}")), Some(run_id), false)?;
        let session = VersionedRunSession {
            workspace: store.root.clone(),
            checkpoint_before: checkpoint.checkpoint_id.clone(),
        };
        Ok((store, session, checkpoint))
    }

    pub fn finish_run(
        &self,
        session: VersionedRunSession,
        run_id: Uuid,
        command_succeeded: bool,
        rollback_on_failure: bool,
        commit_on_success: bool,
    ) -> anyhow::Result<VersionedRunOutcome> {
        let after =
            self.create_checkpoint(Some(format!("after run {run_id}")), Some(run_id), false)?;
        let diff = self.diff_checkpoints(&session.checkpoint_before, &after.checkpoint_id)?;
        let journal_path = self.write_journal(run_id, &diff)?;
        let mut journal_path = journal_path;

        let committed = command_succeeded && commit_on_success;
        if committed {
            let report = self.commit_with_report(&after.checkpoint_id)?;
            if let Some(path) = report.journal_path {
                journal_path = path;
            }
        }

        let rolled_back = !command_succeeded && rollback_on_failure;
        let rollback = if rolled_back {
            Some(self.rollback(&session.checkpoint_before)?)
        } else {
            None
        };

        Ok(VersionedRunOutcome {
            workspace: self.root.clone(),
            checkpoint_before: session.checkpoint_before,
            checkpoint_after: after.checkpoint_id,
            journal_path,
            changed_files: diff
                .changes
                .iter()
                .filter(|change| !matches!(change.after, Some(WorkspaceEntry::Directory)))
                .count(),
            changes: diff.changes,
            committed,
            rolled_back,
            rollback,
        })
    }

    fn snapshot_entries(&self) -> anyhow::Result<BTreeMap<String, WorkspaceEntry>> {
        let mut entries = BTreeMap::new();
        self.walk_entries(&self.root, true, &mut entries)?;
        Ok(entries)
    }

    fn snapshot_entries_without_objects(&self) -> anyhow::Result<BTreeMap<String, WorkspaceEntry>> {
        let mut entries = BTreeMap::new();
        self.walk_entries(&self.root, false, &mut entries)?;
        Ok(entries)
    }

    fn walk_entries(
        &self,
        dir: &Path,
        store_objects: bool,
        entries: &mut BTreeMap<String, WorkspaceEntry>,
    ) -> anyhow::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let relative = relative_string(&self.root, &path)?;
            if should_ignore(&relative) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                entries.insert(relative.clone(), WorkspaceEntry::Directory);
                self.walk_entries(&path, store_objects, entries)?;
            } else if metadata.is_file() {
                let object = if store_objects {
                    self.store_object(&path)?
                } else {
                    file_fingerprint(&path)?
                };
                entries.insert(
                    relative,
                    WorkspaceEntry::File {
                        size: metadata.len(),
                        hash: object.clone(),
                        object,
                        readonly: metadata.permissions().readonly(),
                    },
                );
            }
        }
        Ok(())
    }

    fn store_object(&self, path: &Path) -> anyhow::Result<String> {
        let mut file = File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        self.store_bytes(&bytes)
    }

    fn store_bytes(&self, bytes: &[u8]) -> anyhow::Result<String> {
        let object = content_id(bytes);
        let object_path = self.object_path(&object);
        if !object_path.exists() {
            let mut output = File::create(object_path)?;
            output.write_all(bytes)?;
        }
        Ok(object)
    }

    fn write_checkpoint(&self, checkpoint: &WorkspaceCheckpoint) -> anyhow::Result<()> {
        let path = self.checkpoint_path(&checkpoint.checkpoint_id);
        let mut file = File::create(path)?;
        file.write_all(serde_json::to_string_pretty(checkpoint)?.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn write_checkpoint_to_root(
        &self,
        checkpoint: &WorkspaceCheckpoint,
        root: &Path,
    ) -> anyhow::Result<(usize, usize)> {
        let mut dirs = checkpoint
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                matches!(entry, WorkspaceEntry::Directory).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        dirs.sort_by_key(|path| path_depth(path));
        for relative in &dirs {
            fs::create_dir_all(root.join(relative_path(relative)))?;
        }

        let mut restored_files = 0;
        for (relative, entry) in &checkpoint.entries {
            let WorkspaceEntry::File {
                object, readonly, ..
            } = entry
            else {
                continue;
            };
            let destination = root.join(relative_path(relative));
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(self.object_path(object), &destination)?;
            let mut permissions = fs::metadata(&destination)?.permissions();
            permissions.set_readonly(*readonly);
            fs::set_permissions(&destination, permissions)?;
            restored_files += 1;
        }

        Ok((restored_files, dirs.len()))
    }

    fn write_journal(&self, run_id: Uuid, diff: &WorkspaceDiff) -> anyhow::Result<PathBuf> {
        let path = self.journal_path(&run_id.to_string());
        let mut file = File::create(&path)?;
        for (index, change) in diff.changes.iter().enumerate() {
            let event = WorkspaceJournalEvent {
                schema_version: FS_JOURNAL_SCHEMA_VERSION,
                seq: index + 1,
                ts: epoch_millis(),
                run_id,
                op: WorkspaceJournalOp::from(&change.kind),
                path: change.path.clone(),
                source_path: change.source_path.clone(),
                base_checkpoint: diff.from.clone(),
                target_checkpoint: diff.to.clone(),
                before: change.before.clone(),
                after: change.after.clone(),
            };
            let event = serde_json::json!({
                "seq": index + 1,
                "schema_version": event.schema_version,
                "ts": event.ts,
                "run_id": event.run_id,
                "op": event.op,
                "path": event.path,
                "source_path": event.source_path,
                "base_checkpoint": event.base_checkpoint,
                "target_checkpoint": event.target_checkpoint,
                "before": event.before,
                "after": event.after,
            });
            serde_json::to_writer(&mut file, &event)?;
            file.write_all(b"\n")?;
        }
        Ok(path)
    }

    fn checkpoint_path(&self, checkpoint_id: &str) -> PathBuf {
        self.store
            .join(CHECKPOINT_DIR)
            .join(format!("{checkpoint_id}.json"))
    }

    fn object_path(&self, object: &str) -> PathBuf {
        self.store.join(OBJECT_DIR).join(object)
    }

    fn journal_path(&self, run_id: &str) -> PathBuf {
        self.store.join(JOURNAL_DIR).join(format!("{run_id}.jsonl"))
    }

    fn compacted_journal_path(&self, run_id: &str) -> PathBuf {
        self.store
            .join(JOURNAL_DIR)
            .join(COMPACTED_DIR)
            .join(format!("{run_id}.jsonl"))
    }

    fn operation_journal_path(&self, run_id: &str) -> PathBuf {
        self.store
            .join(OPERATION_JOURNAL_DIR)
            .join(format!("{run_id}.jsonl"))
    }

    fn compacted_operation_journal_path(&self, run_id: &str) -> PathBuf {
        self.store
            .join(OPERATION_JOURNAL_DIR)
            .join(COMPACTED_DIR)
            .join(format!("{run_id}.jsonl"))
    }

    fn compact_journal_file(
        &self,
        active: PathBuf,
        compacted: PathBuf,
    ) -> anyhow::Result<Option<PathBuf>> {
        if active.exists() {
            if let Some(parent) = compacted.parent() {
                fs::create_dir_all(parent)?;
            }
            if compacted.exists() {
                fs::remove_file(&compacted)?;
            }
            fs::rename(active, &compacted)?;
            Ok(Some(compacted))
        } else if compacted.exists() {
            Ok(Some(compacted))
        } else {
            Ok(None)
        }
    }

    fn head_path(&self) -> PathBuf {
        self.store.join(REF_DIR).join(HEAD_REF)
    }

    fn load_all_checkpoints(&self) -> anyhow::Result<Vec<WorkspaceCheckpoint>> {
        let mut checkpoints = Vec::new();
        for entry in fs::read_dir(self.store.join(CHECKPOINT_DIR))? {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            checkpoints.push(serde_json::from_str::<WorkspaceCheckpoint>(&text)?);
        }
        Ok(checkpoints)
    }

    fn read_journal(&self, run_id: &str) -> anyhow::Result<Vec<WorkspaceJournalEvent>> {
        let path = self
            .existing_journal_path(run_id)
            .map_err(|err| anyhow::anyhow!("failed to read journal {run_id}: {err}"))?;
        let text = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("failed to read journal {run_id}: {err}"))?;
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    fn read_operation_journal(&self, run_id: &str) -> anyhow::Result<Vec<WorkspaceOperationEvent>> {
        let path = self
            .existing_operation_journal_path(run_id)
            .map_err(|err| anyhow::anyhow!("failed to read operation journal {run_id}: {err}"))?;
        let text = fs::read_to_string(&path)
            .map_err(|err| anyhow::anyhow!("failed to read operation journal {run_id}: {err}"))?;
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    fn existing_journal_path(&self, run_id: &str) -> anyhow::Result<PathBuf> {
        let active = self.journal_path(run_id);
        if active.exists() {
            return Ok(active);
        }
        let compacted = self.compacted_journal_path(run_id);
        if compacted.exists() {
            return Ok(compacted);
        }
        Err(anyhow::anyhow!("journal {run_id} does not exist"))
    }

    fn existing_operation_journal_path(&self, run_id: &str) -> anyhow::Result<PathBuf> {
        let active = self.operation_journal_path(run_id);
        if active.exists() {
            return Ok(active);
        }
        let compacted = self.compacted_operation_journal_path(run_id);
        if compacted.exists() {
            return Ok(compacted);
        }
        Err(anyhow::anyhow!("operation journal {run_id} does not exist"))
    }
}

fn apply_journal_event(
    entries: &mut BTreeMap<String, WorkspaceEntry>,
    event: &WorkspaceJournalEvent,
) -> anyhow::Result<()> {
    match event.op {
        WorkspaceJournalOp::CreateFile
        | WorkspaceJournalOp::WriteFile
        | WorkspaceJournalOp::TypeChange => {
            if let Some(after) = &event.after {
                entries.insert(event.path.clone(), after.clone());
            } else {
                entries.remove(&event.path);
            }
        }
        WorkspaceJournalOp::DeletePath => {
            entries.remove(&event.path);
        }
        WorkspaceJournalOp::RenamePath => {
            let source = event.source_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "renamed journal event is missing source_path at seq {}",
                    event.seq
                )
            })?;
            entries.remove(source);
            if let Some(after) = &event.after {
                entries.insert(event.path.clone(), after.clone());
            }
        }
    }
    Ok(())
}

fn journal_event_within_limit(
    event: &WorkspaceJournalEvent,
    until_seq: Option<usize>,
    until_ts: Option<u128>,
) -> bool {
    until_seq.is_none_or(|limit| event.seq <= limit)
        && until_ts.is_none_or(|limit| event.ts <= limit)
}

fn operation_event_within_limit(
    event: &WorkspaceOperationEvent,
    until_seq: Option<usize>,
    until_ts: Option<u128>,
) -> bool {
    until_seq.is_none_or(|limit| event.seq <= limit)
        && until_ts.is_none_or(|limit| event.ts <= limit)
}

fn apply_operation_event(
    store: &WorkspaceStore,
    destination: &Path,
    event: &WorkspaceOperationEvent,
) -> anyhow::Result<()> {
    match &event.op {
        WorkspaceOperation::CreateFile { path } => {
            let path = destination.join(checked_relative_path(path)?);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(path)?;
        }
        WorkspaceOperation::CreateDir { path } => {
            fs::create_dir_all(destination.join(checked_relative_path(path)?))?;
        }
        WorkspaceOperation::Write {
            path,
            offset,
            object,
            len,
        } => {
            validate_content_id(object)?;
            let payload = fs::read(store.object_path(object))?;
            if payload.len() as u64 != *len {
                return Err(anyhow::anyhow!(
                    "write event seq {} expected object length {}, found {}",
                    event.seq,
                    len,
                    payload.len()
                ));
            }
            let path = destination.join(checked_relative_path(path)?);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let offset = usize::try_from(*offset)
                .map_err(|_| anyhow::anyhow!("write offset is too large at seq {}", event.seq))?;
            let end = offset
                .checked_add(payload.len())
                .ok_or_else(|| anyhow::anyhow!("write range overflow at seq {}", event.seq))?;
            let mut contents = if path.exists() {
                fs::read(&path)?
            } else {
                Vec::new()
            };
            if contents.len() < offset {
                contents.resize(offset, 0);
            }
            if contents.len() < end {
                contents.resize(end, 0);
            }
            contents[offset..end].copy_from_slice(&payload);
            fs::write(path, contents)?;
        }
        WorkspaceOperation::Truncate { path, len } => {
            let path = destination.join(checked_relative_path(path)?);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(path)?;
            file.set_len(*len)?;
        }
        WorkspaceOperation::DeletePath { path } => {
            let path = destination.join(checked_relative_path(path)?);
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else if path.exists() {
                fs::remove_file(path)?;
            }
        }
        WorkspaceOperation::RenamePath { source_path, path } => {
            let source = destination.join(checked_relative_path(source_path)?);
            let target = destination.join(checked_relative_path(path)?);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(source, target)?;
        }
        WorkspaceOperation::Chmod { path, readonly } => {
            let path = destination.join(checked_relative_path(path)?);
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_readonly(*readonly);
            fs::set_permissions(path, permissions)?;
        }
        WorkspaceOperation::Fsync { path } => {
            let path = destination.join(checked_relative_path(path)?);
            if path.is_file() {
                File::open(path)?.sync_all()?;
            }
        }
    }
    Ok(())
}

fn replace_workspace_from_dir(store: &WorkspaceStore, source: &Path) -> anyhow::Result<()> {
    let current = store.snapshot_entries_without_objects()?;
    let mut removable = current.keys().cloned().collect::<Vec<_>>();
    removable.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
    for relative in removable {
        let path = store.root.join(relative_path(&relative));
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else if path.exists() {
            fs::remove_file(path)?;
        }
    }
    copy_tree(source, &store.root, source)
}

fn copy_tree(source_root: &Path, destination_root: &Path, dir: &Path) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let source = entry.path();
        let relative = source.strip_prefix(source_root)?;
        let destination = destination_root.join(relative);
        let metadata = fs::metadata(&source)?;
        if metadata.is_dir() {
            fs::create_dir_all(&destination)?;
            copy_tree(source_root, destination_root, &source)?;
        } else if metadata.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source, &destination)?;
            fs::set_permissions(&destination, metadata.permissions())?;
        }
    }
    Ok(())
}

fn validate_operation(op: &WorkspaceOperation) -> anyhow::Result<()> {
    match op {
        WorkspaceOperation::CreateFile { path }
        | WorkspaceOperation::CreateDir { path }
        | WorkspaceOperation::Truncate { path, .. }
        | WorkspaceOperation::DeletePath { path }
        | WorkspaceOperation::Chmod { path, .. }
        | WorkspaceOperation::Fsync { path } => {
            checked_relative_path(path)?;
        }
        WorkspaceOperation::Write { path, object, .. } => {
            checked_relative_path(path)?;
            validate_content_id(object)?;
        }
        WorkspaceOperation::RenamePath { source_path, path } => {
            checked_relative_path(source_path)?;
            checked_relative_path(path)?;
        }
    }
    Ok(())
}

impl From<&WorkspaceChangeKind> for WorkspaceJournalOp {
    fn from(kind: &WorkspaceChangeKind) -> Self {
        match kind {
            WorkspaceChangeKind::Added => Self::CreateFile,
            WorkspaceChangeKind::Modified => Self::WriteFile,
            WorkspaceChangeKind::Deleted => Self::DeletePath,
            WorkspaceChangeKind::Renamed => Self::RenamePath,
            WorkspaceChangeKind::TypeChanged => Self::TypeChange,
        }
    }
}

fn diff_manifests(from: &WorkspaceCheckpoint, to: &WorkspaceCheckpoint) -> WorkspaceDiff {
    let mut paths = from.entries.keys().cloned().collect::<BTreeSet<_>>();
    paths.extend(to.entries.keys().cloned());

    let changes = detect_renames(
        paths
            .into_iter()
            .filter_map(|path| {
                let before = from.entries.get(&path);
                let after = to.entries.get(&path);
                let kind = match (before, after) {
                    (None, Some(_)) => WorkspaceChangeKind::Added,
                    (Some(_), None) => WorkspaceChangeKind::Deleted,
                    (Some(WorkspaceEntry::File { .. }), Some(WorkspaceEntry::Directory))
                    | (Some(WorkspaceEntry::Directory), Some(WorkspaceEntry::File { .. })) => {
                        WorkspaceChangeKind::TypeChanged
                    }
                    (Some(before), Some(after)) if before != after => WorkspaceChangeKind::Modified,
                    _ => return None,
                };
                Some(WorkspaceChange {
                    kind,
                    path,
                    source_path: None,
                    before: before.cloned(),
                    after: after.cloned(),
                })
            })
            .collect(),
    );

    WorkspaceDiff {
        from: from.checkpoint_id.clone(),
        to: to.checkpoint_id.clone(),
        changes,
    }
}

fn detect_renames(changes: Vec<WorkspaceChange>) -> Vec<WorkspaceChange> {
    let mut added_by_fingerprint = BTreeMap::<String, Vec<usize>>::new();
    for (index, change) in changes.iter().enumerate() {
        if change.kind == WorkspaceChangeKind::Added
            && let Some(entry) = &change.after
            && let Some(fingerprint) = entry_fingerprint(entry)
        {
            added_by_fingerprint
                .entry(fingerprint)
                .or_default()
                .push(index);
        }
    }

    let mut consumed_added = BTreeSet::new();
    let mut consumed_deleted = BTreeSet::new();
    let mut renames = Vec::new();
    for (index, change) in changes.iter().enumerate() {
        if change.kind != WorkspaceChangeKind::Deleted {
            continue;
        }
        let Some(entry) = &change.before else {
            continue;
        };
        let Some(fingerprint) = entry_fingerprint(entry) else {
            continue;
        };
        let Some(added_indices) = added_by_fingerprint.get(&fingerprint) else {
            continue;
        };
        let Some(added_index) = added_indices
            .iter()
            .copied()
            .find(|candidate| !consumed_added.contains(candidate))
        else {
            continue;
        };
        let added = &changes[added_index];
        consumed_added.insert(added_index);
        consumed_deleted.insert(index);
        renames.push(WorkspaceChange {
            kind: WorkspaceChangeKind::Renamed,
            path: added.path.clone(),
            source_path: Some(change.path.clone()),
            before: change.before.clone(),
            after: added.after.clone(),
        });
    }

    let mut output = changes
        .into_iter()
        .enumerate()
        .filter_map(|(index, change)| {
            (!consumed_added.contains(&index) && !consumed_deleted.contains(&index))
                .then_some(change)
        })
        .collect::<Vec<_>>();
    output.extend(renames);
    output.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.source_path.cmp(&right.source_path))
    });
    output
}

fn entry_fingerprint(entry: &WorkspaceEntry) -> Option<String> {
    match entry {
        WorkspaceEntry::File { size, hash, .. } => Some(format!("file:{size}:{hash}")),
        WorkspaceEntry::Directory => None,
    }
}

fn referenced_objects(checkpoints: &[WorkspaceCheckpoint]) -> BTreeSet<String> {
    checkpoints
        .iter()
        .flat_map(|checkpoint| checkpoint.entries.values())
        .filter_map(|entry| match entry {
            WorkspaceEntry::File { object, .. } => Some(object.clone()),
            WorkspaceEntry::Directory => None,
        })
        .collect()
}

fn normalize_root(root: &Path) -> anyhow::Result<PathBuf> {
    if root.exists() {
        return Ok(fs::canonicalize(root)?);
    }
    fs::create_dir_all(root)?;
    Ok(fs::canonicalize(root)?)
}

fn relative_string(root: &Path, path: &Path) -> anyhow::Result<String> {
    let relative = path.strip_prefix(root)?;
    let parts = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    Ok(parts.join("/"))
}

fn relative_path(relative: &str) -> PathBuf {
    relative.split('/').collect()
}

fn checked_relative_path(relative: &str) -> anyhow::Result<PathBuf> {
    if relative.is_empty() {
        return Err(anyhow::anyhow!("operation path must not be empty"));
    }
    let mut path = PathBuf::new();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(value) => path.push(value),
            Component::CurDir => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "operation path must be relative and stay inside the workspace: {relative}"
                ));
            }
        }
    }
    if path.as_os_str().is_empty() {
        return Err(anyhow::anyhow!("operation path must not be empty"));
    }
    Ok(path)
}

fn path_depth(relative: &str) -> usize {
    relative.split('/').count()
}

fn should_ignore(relative: &str) -> bool {
    relative
        .split('/')
        .next()
        .is_some_and(|part| IGNORED_DIRS.contains(&part))
}

fn file_fingerprint(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(content_id(&bytes))
}

fn content_id(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_content_id(value: &str) -> anyhow::Result<()> {
    if value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("invalid content object id: {value}"))
    }
}

fn new_checkpoint_id() -> String {
    format!("ckpt_{}", Uuid::new_v4().simple())
}

fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn checkpoint_diff_and_rollback_restore_workspace() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        fs::write(workspace.join("a.txt"), "one").unwrap();
        fs::create_dir(workspace.join("src")).unwrap();
        fs::write(workspace.join("src/lib.rs"), "old").unwrap();

        let store = WorkspaceStore::open(workspace).unwrap();
        let before = store
            .create_checkpoint(Some("before".to_string()), None, true)
            .unwrap();

        fs::write(workspace.join("a.txt"), "two").unwrap();
        fs::write(workspace.join("new.txt"), "new").unwrap();
        fs::remove_file(workspace.join("src/lib.rs")).unwrap();

        let after = store
            .create_checkpoint(Some("after".to_string()), None, false)
            .unwrap();
        let diff = store
            .diff_checkpoints(&before.checkpoint_id, &after.checkpoint_id)
            .unwrap();

        assert_eq!(diff.changes.len(), 3);
        assert!(
            diff.changes
                .iter()
                .any(|change| change.kind == WorkspaceChangeKind::Modified)
        );

        let rollback = store.rollback(&before.checkpoint_id).unwrap();
        assert_eq!(rollback.restored_files, 2);
        assert_eq!(fs::read_to_string(workspace.join("a.txt")).unwrap(), "one");
        assert_eq!(
            fs::read_to_string(workspace.join("src/lib.rs")).unwrap(),
            "old"
        );
        assert!(!workspace.join("new.txt").exists());
    }

    #[test]
    fn diff_detects_file_rename() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        fs::write(workspace.join("old.txt"), "same").unwrap();

        let store = WorkspaceStore::open(workspace).unwrap();
        let before = store.create_checkpoint(None, None, true).unwrap();

        fs::rename(workspace.join("old.txt"), workspace.join("new.txt")).unwrap();
        let after = store.create_checkpoint(None, None, false).unwrap();
        let diff = store
            .diff_checkpoints(&before.checkpoint_id, &after.checkpoint_id)
            .unwrap();

        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].kind, WorkspaceChangeKind::Renamed);
        assert_eq!(diff.changes[0].source_path.as_deref(), Some("old.txt"));
        assert_eq!(diff.changes[0].path, "new.txt");
    }

    #[test]
    fn verify_and_gc_report_store_health() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        fs::write(workspace.join("keep.txt"), "keep").unwrap();

        let store = WorkspaceStore::open(workspace).unwrap();
        store.create_checkpoint(None, None, true).unwrap();

        let stray = store.store.join(OBJECT_DIR).join(content_id(b"stray"));
        fs::write(&stray, "stray").unwrap();

        let verify = store.verify().unwrap();
        assert!(verify.ok);
        assert_eq!(verify.checkpoint_count, 1);

        let gc = store.gc().unwrap();
        assert_eq!(gc.removed_objects, 1);
        assert!(!stray.exists());
    }

    #[test]
    fn materialize_writes_checkpoint_to_separate_directory() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let view = dir.path().join("view");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();

        let store = WorkspaceStore::open(&workspace).unwrap();
        let checkpoint = store.create_checkpoint(None, None, true).unwrap();
        fs::write(workspace.join("a.txt"), "two").unwrap();

        let report = store
            .materialize(&checkpoint.checkpoint_id, &view, false)
            .unwrap();

        assert_eq!(report.restored_files, 1);
        assert_eq!(fs::read_to_string(view.join("a.txt")).unwrap(), "one");
        assert_eq!(fs::read_to_string(workspace.join("a.txt")).unwrap(), "two");
    }

    #[test]
    fn status_reports_changes_since_head() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        fs::write(workspace.join("a.txt"), "one").unwrap();

        let store = WorkspaceStore::open(workspace).unwrap();
        store.create_checkpoint(None, None, true).unwrap();
        let clean = store.status().unwrap();
        assert!(!clean.dirty);

        fs::write(workspace.join("a.txt"), "two").unwrap();
        fs::write(workspace.join("b.txt"), "new").unwrap();

        let dirty = store.status().unwrap();
        assert!(dirty.dirty);
        assert_eq!(dirty.changes.len(), 2);
        assert!(
            dirty
                .changes
                .iter()
                .any(|change| change.kind == WorkspaceChangeKind::Modified)
        );
        assert!(
            dirty
                .changes
                .iter()
                .any(|change| change.kind == WorkspaceChangeKind::Added)
        );
    }

    #[test]
    fn replay_journal_prefix_materializes_intermediate_state() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        let view = dir.path().join("view");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();

        let run_id = Uuid::new_v4();
        let (store, session, _) = WorkspaceStore::begin_run(&workspace, run_id).unwrap();
        fs::write(workspace.join("a.txt"), "two").unwrap();
        fs::write(workspace.join("b.txt"), "new").unwrap();
        let outcome = store
            .finish_run(session, run_id, true, false, false)
            .unwrap();
        assert_eq!(outcome.changes.len(), 2);

        let report = store
            .replay_journal(&run_id.to_string(), Some(1), None, &view, false)
            .unwrap();

        assert_eq!(report.applied_events, 1);
        assert_eq!(fs::read_to_string(view.join("a.txt")).unwrap(), "two");
        assert!(!view.join("b.txt").exists());
    }

    #[test]
    fn operation_journal_replays_prefix_and_full_history() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "hello world").unwrap();

        let store = WorkspaceStore::open(&workspace).unwrap();
        let base = store
            .create_checkpoint(Some("base".to_string()), None, true)
            .unwrap();
        let run_id = Uuid::new_v4();

        let write = store
            .append_write_operation(run_id, base.checkpoint_id.clone(), "a.txt", 6, b"rust")
            .unwrap();
        assert_eq!(write.seq, 1);
        store
            .append_operation_event(
                run_id,
                base.checkpoint_id.clone(),
                WorkspaceOperation::Truncate {
                    path: "a.txt".to_string(),
                    len: 10,
                },
            )
            .unwrap();
        store
            .append_operation_event(
                run_id,
                base.checkpoint_id.clone(),
                WorkspaceOperation::RenamePath {
                    source_path: "a.txt".to_string(),
                    path: "b.txt".to_string(),
                },
            )
            .unwrap();

        let prefix = dir.path().join("prefix");
        let report = store
            .replay_operation_journal(&run_id.to_string(), Some(1), None, &prefix, false)
            .unwrap();
        assert_eq!(report.applied_events, 1);
        assert_eq!(
            fs::read_to_string(prefix.join("a.txt")).unwrap(),
            "hello rustd"
        );

        let full = dir.path().join("full");
        let events = store.list_operation_journal(&run_id.to_string()).unwrap();
        let report = store
            .replay_operation_journal(&run_id.to_string(), None, None, &full, false)
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(report.applied_events, 3);
        assert!(!full.join("a.txt").exists());
        assert_eq!(
            fs::read_to_string(full.join("b.txt")).unwrap(),
            "hello rust"
        );
        assert_eq!(
            events[0].schema_version,
            FS_OPERATION_JOURNAL_SCHEMA_VERSION
        );
        assert!(matches!(events[0].op, WorkspaceOperation::Write { .. }));
    }

    #[test]
    fn operation_journal_replays_until_timestamp() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "hello world").unwrap();

        let store = WorkspaceStore::open(&workspace).unwrap();
        let base = store.create_checkpoint(None, None, true).unwrap();
        let run_id = Uuid::new_v4();
        let first = store
            .append_write_operation(run_id, base.checkpoint_id.clone(), "a.txt", 6, b"rust")
            .unwrap();
        while epoch_millis() <= first.ts {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        store
            .append_operation_event(
                run_id,
                base.checkpoint_id,
                WorkspaceOperation::Truncate {
                    path: "a.txt".to_string(),
                    len: 10,
                },
            )
            .unwrap();

        let view = dir.path().join("view");
        let report = store
            .replay_operation_journal(&run_id.to_string(), None, Some(first.ts), &view, false)
            .unwrap();

        assert_eq!(report.until_ts, Some(first.ts));
        assert_eq!(report.applied_events, 1);
        assert_eq!(
            fs::read_to_string(view.join("a.txt")).unwrap(),
            "hello rustd"
        );
    }

    #[test]
    fn operation_journal_restores_workspace_until_timestamp() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "hello world").unwrap();

        let store = WorkspaceStore::open(&workspace).unwrap();
        let base = store.create_checkpoint(None, None, true).unwrap();
        let run_id = Uuid::new_v4();
        let first = store
            .append_write_operation(run_id, base.checkpoint_id.clone(), "a.txt", 6, b"rust")
            .unwrap();
        while epoch_millis() <= first.ts {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        store
            .append_operation_event(
                run_id,
                base.checkpoint_id,
                WorkspaceOperation::Truncate {
                    path: "a.txt".to_string(),
                    len: 10,
                },
            )
            .unwrap();

        fs::write(workspace.join("a.txt"), "current").unwrap();
        fs::write(workspace.join("extra.txt"), "remove me").unwrap();
        let report = store
            .restore_operation_journal(&run_id.to_string(), None, Some(first.ts))
            .unwrap();

        assert_eq!(report.destination, store.root);
        assert_eq!(report.applied_events, 1);
        assert_eq!(
            fs::read_to_string(store.root.join("a.txt")).unwrap(),
            "hello rustd"
        );
        assert!(!store.root.join("extra.txt").exists());
    }

    #[test]
    fn operation_recorder_wraps_adapter_lifecycle() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "hello world").unwrap();

        let run_id = Uuid::new_v4();
        let (recorder, base) = WorkspaceOperationRecorder::begin(&workspace, run_id).unwrap();
        assert_eq!(recorder.run_id(), run_id);
        assert_eq!(recorder.base_checkpoint(), base.checkpoint_id);

        recorder.record_write("a.txt", 6, b"rust").unwrap();
        recorder.record_truncate("a.txt", 10).unwrap();
        recorder.record_rename_path("a.txt", "b.txt").unwrap();

        let events = recorder.events().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[2].seq, 3);
        assert_eq!(events[0].base_checkpoint, base.checkpoint_id);

        fs::rename(workspace.join("a.txt"), workspace.join("b.txt")).unwrap();
        fs::write(workspace.join("b.txt"), "hello rust").unwrap();
        let outcome = recorder.finish(true).unwrap();
        assert_eq!(outcome.operation_count, 3);
        assert_eq!(outcome.base_checkpoint, base.checkpoint_id);
        assert!(outcome.committed);
        assert!(outcome.journal_path.is_file());

        let store = WorkspaceStore::open(&workspace).unwrap();
        assert_eq!(store.head().unwrap(), Some(outcome.checkpoint_after));
        assert!(!store.operation_journal_path(&run_id.to_string()).exists());
        assert_eq!(
            outcome.journal_path,
            store.compacted_operation_journal_path(&run_id.to_string())
        );
        assert_eq!(
            store
                .list_operation_journal(&run_id.to_string())
                .unwrap()
                .len(),
            3
        );

        let view = dir.path().join("view");
        let report = store
            .replay_operation_journal(&run_id.to_string(), Some(2), None, &view, false)
            .unwrap();
        assert_eq!(report.applied_events, 2);
        assert_eq!(
            fs::read_to_string(view.join("a.txt")).unwrap(),
            "hello rust"
        );
    }

    #[test]
    fn operation_journal_rejects_paths_outside_workspace() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let store = WorkspaceStore::open(&workspace).unwrap();
        let base = store.create_checkpoint(None, None, true).unwrap();

        let error = store
            .append_operation_event(
                Uuid::new_v4(),
                base.checkpoint_id,
                WorkspaceOperation::CreateFile {
                    path: "../escape.txt".to_string(),
                },
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("stay inside the workspace"),
            "{error:?}"
        );
    }

    #[test]
    fn operation_journal_rejects_mixed_base_checkpoints() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();
        let store = WorkspaceStore::open(&workspace).unwrap();
        let first = store
            .create_checkpoint(Some("first".to_string()), None, true)
            .unwrap();
        let run_id = Uuid::new_v4();

        store
            .append_operation_event(
                run_id,
                first.checkpoint_id,
                WorkspaceOperation::Fsync {
                    path: "a.txt".to_string(),
                },
            )
            .unwrap();

        fs::write(workspace.join("a.txt"), "two").unwrap();
        let second = store
            .create_checkpoint(Some("second".to_string()), None, true)
            .unwrap();
        let error = store
            .append_operation_event(
                run_id,
                second.checkpoint_id,
                WorkspaceOperation::Fsync {
                    path: "a.txt".to_string(),
                },
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("already uses base checkpoint"),
            "{error:?}"
        );
    }

    #[test]
    fn operation_journal_rejects_append_after_compaction() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();
        let run_id = Uuid::new_v4();
        let (recorder, base) = WorkspaceOperationRecorder::begin(&workspace, run_id).unwrap();
        recorder.record_write("a.txt", 0, b"two").unwrap();
        fs::write(workspace.join("a.txt"), "two").unwrap();
        recorder.finish(true).unwrap();

        let store = WorkspaceStore::open(&workspace).unwrap();
        let error = store
            .append_write_operation(run_id, base.checkpoint_id, "a.txt", 0, b"bad")
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("compacted and cannot be appended"),
            "{error:?}"
        );
    }

    #[test]
    fn journal_events_expose_stable_redo_schema() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();

        let run_id = Uuid::new_v4();
        let (store, session, _) = WorkspaceStore::begin_run(&workspace, run_id).unwrap();
        fs::write(workspace.join("a.txt"), "two").unwrap();
        let outcome = store
            .finish_run(session, run_id, true, false, false)
            .unwrap();
        assert_eq!(outcome.changes.len(), 1);

        let events = store.list_journal(&run_id.to_string()).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].schema_version, FS_JOURNAL_SCHEMA_VERSION);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].op, WorkspaceJournalOp::WriteFile);
        assert_eq!(events[0].path, "a.txt");
        assert_eq!(events[0].base_checkpoint, outcome.checkpoint_before);
        assert_eq!(events[0].target_checkpoint, outcome.checkpoint_after);
    }

    #[test]
    fn transaction_helper_finishes_and_commits_workspace_run() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("a.txt"), "one").unwrap();

        let run_id = Uuid::new_v4();
        let (transaction, before) = WorkspaceTransaction::begin(&workspace, run_id).unwrap();
        assert_eq!(
            transaction.checkpoint_before(),
            Some(before.checkpoint_id.as_str())
        );

        fs::write(workspace.join("a.txt"), "two").unwrap();
        let outcome = transaction.finish(true, false, true).unwrap();
        let store = WorkspaceStore::open(&workspace).unwrap();

        assert_eq!(
            store.head().unwrap(),
            Some(outcome.checkpoint_after.clone())
        );
        assert_eq!(outcome.checkpoint_before, before.checkpoint_id);
        assert!(outcome.committed);
        assert!(!store.journal_path(&run_id.to_string()).exists());
        assert_eq!(
            outcome.journal_path,
            store.compacted_journal_path(&run_id.to_string())
        );
        assert_eq!(store.list_journal(&run_id.to_string()).unwrap().len(), 1);
    }
}
