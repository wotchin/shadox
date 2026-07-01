#![cfg(all(target_os = "linux", feature = "fuse"))]

use crate::versioned_fs::WorkspaceOperationRecorder;
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow, WriteFlags,
};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

const ROOT_INO: INodeNo = INodeNo(1);
const TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct FuseMountSpec {
    pub backing: PathBuf,
    pub mountpoint: PathBuf,
    pub workspace: PathBuf,
    pub run_id: Uuid,
    pub commit_on_unmount: bool,
}

pub fn mount_recording_fuse(spec: FuseMountSpec) -> anyhow::Result<()> {
    let fs = RecordingFuse::new(&spec)?;
    let mut options = Config::default();
    options.mount_options = vec![
        MountOption::FSName("shadox".to_string()),
        MountOption::Subtype("shadox".to_string()),
        MountOption::RW,
        MountOption::DefaultPermissions,
    ];
    fuser::mount2(fs, &spec.mountpoint, &options)?;
    Ok(())
}

struct RecordingFuse {
    backing: PathBuf,
    recorder: Arc<Mutex<Option<WorkspaceOperationRecorder>>>,
    commit_on_unmount: bool,
    inodes: Mutex<InodeTable>,
    next_ino: AtomicU64,
}

impl RecordingFuse {
    fn new(spec: &FuseMountSpec) -> anyhow::Result<Self> {
        let backing = fs::canonicalize(&spec.backing)?;
        fs::create_dir_all(&spec.mountpoint)?;
        let (recorder, _) = WorkspaceOperationRecorder::begin(&spec.workspace, spec.run_id)?;
        let mut inodes = InodeTable::default();
        inodes.by_ino.insert(ROOT_INO, PathBuf::new());
        inodes.by_path.insert(PathBuf::new(), ROOT_INO);
        Ok(Self {
            backing,
            recorder: Arc::new(Mutex::new(Some(recorder))),
            commit_on_unmount: spec.commit_on_unmount,
            inodes: Mutex::new(inodes),
            next_ino: AtomicU64::new(2),
        })
    }

    fn path_for_ino(&self, ino: INodeNo) -> anyhow::Result<PathBuf> {
        let inodes = self.inodes.lock().expect("inode table poisoned");
        let relative = inodes
            .by_ino
            .get(&ino)
            .ok_or_else(|| anyhow::anyhow!("unknown inode {ino:?}"))?;
        Ok(self.backing.join(relative))
    }

    fn relative_for_ino(&self, ino: INodeNo) -> anyhow::Result<PathBuf> {
        let inodes = self.inodes.lock().expect("inode table poisoned");
        inodes
            .by_ino
            .get(&ino)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown inode {ino:?}"))
    }

    fn child_relative(&self, parent: INodeNo, name: &OsStr) -> anyhow::Result<PathBuf> {
        let mut relative = self.relative_for_ino(parent)?;
        relative.push(name);
        Ok(relative)
    }

    fn child_path(&self, parent: INodeNo, name: &OsStr) -> anyhow::Result<(PathBuf, PathBuf)> {
        let relative = self.child_relative(parent, name)?;
        Ok((self.backing.join(&relative), relative))
    }

    fn remember_path(&self, relative: PathBuf) -> INodeNo {
        let mut inodes = self.inodes.lock().expect("inode table poisoned");
        if let Some(ino) = inodes.by_path.get(&relative) {
            return *ino;
        }
        let ino = INodeNo(self.next_ino.fetch_add(1, Ordering::Relaxed));
        inodes.by_path.insert(relative.clone(), ino);
        inodes.by_ino.insert(ino, relative);
        ino
    }

    fn forget_path(&self, relative: &Path) {
        let mut inodes = self.inodes.lock().expect("inode table poisoned");
        if let Some(ino) = inodes.by_path.remove(relative) {
            inodes.by_ino.remove(&ino);
        }
    }

    fn move_path(&self, source: &Path, target: PathBuf) {
        let mut inodes = self.inodes.lock().expect("inode table poisoned");
        if let Some(ino) = inodes.by_path.remove(source) {
            inodes.by_path.insert(target.clone(), ino);
            inodes.by_ino.insert(ino, target);
        }
    }

    fn record<F>(&self, op: F) -> anyhow::Result<()>
    where
        F: FnOnce(&WorkspaceOperationRecorder) -> anyhow::Result<()>,
    {
        let recorder = self.recorder.lock().expect("recorder poisoned");
        let Some(recorder) = recorder.as_ref() else {
            return Ok(());
        };
        op(recorder)
    }
}

impl Filesystem for RecordingFuse {
    fn destroy(&mut self) {
        if let Some(recorder) = self.recorder.lock().expect("recorder poisoned").take() {
            let _ = recorder.finish(self.commit_on_unmount);
        }
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.child_path(parent, name).and_then(|(path, relative)| {
            let attr = file_attr(self.remember_path(relative), &path)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self
            .path_for_ino(ino)
            .and_then(|path| file_attr(ino, &path))
        {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.path_for_ino(ino) {
            Ok(path) if path.is_file() => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Ok(_) => reply.error(Errno::EISDIR),
            Err(_) => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let result = self.path_for_ino(ino).and_then(|path| {
            let mut file = File::open(path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0; size as usize];
            let read = file.read(&mut buf)?;
            buf.truncate(read);
            Ok(buf)
        });
        match result {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let result = self.path_for_ino(ino).and_then(|path| {
            let relative = self.relative_for_ino(ino)?;
            let mut file = OpenOptions::new().write(true).open(&path)?;
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(data)?;
            self.record(|recorder| {
                recorder.record_write(relative_to_string(&relative), offset, data)?;
                Ok(())
            })?;
            Ok(data.len() as u32)
        });
        match result {
            Ok(written) => reply.written(written),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let result = self.child_path(parent, name).and_then(|(path, relative)| {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            File::create(&path)?;
            self.record(|recorder| {
                recorder.record_create_file(relative_to_string(&relative))?;
                Ok(())
            })?;
            let ino = self.remember_path(relative);
            let attr = file_attr(ino, &path)?;
            Ok((ino, attr))
        });
        match result {
            Ok((ino, attr)) => reply.created(
                &TTL,
                &attr,
                Generation(0),
                FileHandle(ino.0),
                FopenFlags::empty(),
            ),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let result = self.child_path(parent, name).and_then(|(path, relative)| {
            fs::create_dir_all(&path)?;
            self.record(|recorder| {
                recorder.record_create_dir(relative_to_string(&relative))?;
                Ok(())
            })?;
            let attr = file_attr(self.remember_path(relative), &path)?;
            Ok(attr)
        });
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = self.child_path(parent, name).and_then(|(path, relative)| {
            fs::remove_file(&path)?;
            self.forget_path(&relative);
            self.record(|recorder| {
                recorder.record_delete_path(relative_to_string(&relative))?;
                Ok(())
            })
        });
        reply_from_unit(result, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let result = self.child_path(parent, name).and_then(|(path, relative)| {
            fs::remove_dir_all(&path)?;
            self.forget_path(&relative);
            self.record(|recorder| {
                recorder.record_delete_path(relative_to_string(&relative))?;
                Ok(())
            })
        });
        reply_from_unit(result, reply);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let result = self
            .child_path(parent, name)
            .and_then(|(source, source_relative)| {
                let (target, target_relative) = self.child_path(newparent, newname)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::rename(&source, &target)?;
                self.move_path(&source_relative, target_relative.clone());
                self.record(|recorder| {
                    recorder.record_rename_path(
                        relative_to_string(&source_relative),
                        relative_to_string(&target_relative),
                    )?;
                    Ok(())
                })
            });
        reply_from_unit(result, reply);
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let result = self.path_for_ino(ino).and_then(|path| {
            let relative = self.relative_for_ino(ino)?;
            if let Some(size) = size {
                OpenOptions::new()
                    .write(true)
                    .truncate(false)
                    .open(&path)?
                    .set_len(size)?;
                self.record(|recorder| {
                    recorder.record_truncate(relative_to_string(&relative), size)?;
                    Ok(())
                })?;
            }
            if let Some(mode) = mode {
                let mut permissions = fs::metadata(&path)?.permissions();
                permissions.set_mode(mode);
                fs::set_permissions(&path, permissions)?;
                self.record(|recorder| {
                    recorder.record_chmod(relative_to_string(&relative), mode & 0o222 == 0)?;
                    Ok(())
                })?;
            }
            file_attr(ino, &path)
        });
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let result = self.path_for_ino(ino).and_then(|path| {
            File::open(&path)?.sync_all()?;
            let relative = self.relative_for_ino(ino)?;
            self.record(|recorder| {
                recorder.record_fsync(relative_to_string(&relative))?;
                Ok(())
            })
        });
        reply_from_unit(result, reply);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let result = self.path_for_ino(ino).and_then(|path| {
            let relative = self.relative_for_ino(ino)?;
            let mut entries = Vec::new();
            entries.push((ino, FileType::Directory, ".".into()));
            if ino != ROOT_INO {
                entries.push((ROOT_INO, FileType::Directory, "..".into()));
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let mut child = relative.clone();
                child.push(entry.file_name());
                let child_ino = self.remember_path(child);
                let kind = file_kind(&entry.metadata()?)?;
                entries.push((child_ino, kind, entry.file_name()));
            }
            Ok(entries)
        });
        match result {
            Ok(entries) => {
                for (index, (ino, kind, name)) in
                    entries.into_iter().enumerate().skip(offset as usize)
                {
                    if reply.add(ino, (index + 1) as u64, kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(_) => reply.error(Errno::EIO),
        }
    }
}

#[derive(Default)]
struct InodeTable {
    by_ino: BTreeMap<INodeNo, PathBuf>,
    by_path: BTreeMap<PathBuf, INodeNo>,
}

fn file_attr(ino: INodeNo, path: &Path) -> anyhow::Result<FileAttr> {
    let metadata = fs::metadata(path)?;
    let kind = file_kind(&metadata)?;
    let perm = (metadata.mode() & 0o7777) as u16;
    Ok(FileAttr {
        ino,
        size: metadata.len(),
        blocks: metadata.blocks(),
        atime: metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
        mtime: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        ctime: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
        crtime: metadata.created().unwrap_or(SystemTime::UNIX_EPOCH),
        kind,
        perm,
        nlink: metadata.nlink() as u32,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: metadata.rdev() as u32,
        blksize: metadata.blksize() as u32,
        flags: 0,
    })
}

fn file_kind(metadata: &fs::Metadata) -> anyhow::Result<FileType> {
    FileType::from_std(metadata.file_type()).ok_or_else(|| anyhow::anyhow!("unsupported file type"))
}

fn relative_to_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn reply_from_unit(result: anyhow::Result<()>, reply: ReplyEmpty) {
    match result {
        Ok(()) => reply.ok(),
        Err(_) => reply.error(Errno::EIO),
    }
}
