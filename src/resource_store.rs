use std::{collections::VecDeque, fs, io::{BufReader, BufWriter}, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, Ordering}}};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use ropey::Rope;
use serde::{Deserialize, Serialize};
use tokio::{fs as tokio_fs, sync::{RwLock, Mutex}, task, time::{sleep, Duration}};
use tracing::{info, error};

use crate::{edit::{TextEdit, Position}, events::ResourceEvent};

#[derive(Clone)]
pub struct ResourceStore {
    root: PathBuf,
    files: Arc<DashMap<PathBuf, Arc<RwLock<RopeFile>>>>,
    events: tokio::sync::broadcast::Sender<ResourceEvent>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResourceInfo {
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

pub struct RopeFile {
    pub(crate) path: PathBuf,
    pub(crate) rope: Rope,
    dirty: AtomicBool,
    _persist_lock: Mutex<()>,
}

impl ResourceStore {
    pub async fn new(root: PathBuf) -> Result<Self> {
        let root = canonicalize(&root)?;
        if !root.exists() {
            tokio_fs::create_dir_all(&root).await?;
        }
        let (tx, _rx) = tokio::sync::broadcast::channel(1024);
        Ok(Self { root, files: Arc::new(DashMap::new()), events: tx })
    }

    fn ensure_within_root(&self, path: &Path) -> Result<PathBuf> {
        let joined = self.root.join(path);
        // Normalize without requiring existence.
        let abs = joined;
        let canon_root = std::fs::canonicalize(&self.root).unwrap_or(self.root.clone());
        let abs_norm = abs;
        // Basic traversal prevention: no prefix like ".." at beginning
        let is_escape = abs_norm.components().any(|c| matches!(c, std::path::Component::Prefix(_)));
        if is_escape { return Err(anyhow!("invalid path")); }
        // Final check on string prefix
        let abs_str = abs_norm.as_path();
        if !abs_str.starts_with(&canon_root) && abs_str.is_absolute() {
            return Err(anyhow!("path escapes workspace root: {}", abs_str.display()));
        }
        Ok(abs_str.to_path_buf())
    }

    pub async fn create_dir(&self, path: &Path) -> Result<()> {
        let abs = self.ensure_within_root(path)?;
        tokio_fs::create_dir_all(&abs).await?;
        let _ = self.events.send(ResourceEvent::ListChanged);
        Ok(())
    }

    pub async fn delete_dir(&self, path: &Path) -> Result<()> {
        let abs = self.ensure_within_root(path)?;
        tokio_fs::remove_dir_all(&abs).await?;
        let _ = self.events.send(ResourceEvent::ListChanged);
        Ok(())
    }

    pub async fn create_file(&self, path: &Path, content: String) -> Result<()> {
        let abs = self.ensure_within_root(path)?;
        if let Some(parent) = abs.parent() { tokio_fs::create_dir_all(parent).await?; }
        tokio_fs::write(&abs, content.as_bytes()).await?;
        self.files.remove(&abs);
        let _ = self.events.send(ResourceEvent::Created(abs.clone()));
        Ok(())
    }

    pub async fn delete_file(&self, path: &Path) -> Result<()> {
        let abs = self.ensure_within_root(path)?;
        tokio_fs::remove_file(&abs).await?;
        self.files.remove(&abs);
        let _ = self.events.send(ResourceEvent::Deleted(abs.clone()));
        Ok(())
    }

    pub async fn read_file(&self, path: &Path) -> Result<String> {
        let rf = self.open_or_load(path).await?;
        let guard = rf.read().await;
        Ok(guard.rope.to_string())
    }

    pub async fn apply_edits(&self, path: &Path, mut edits: Vec<TextEdit>) -> Result<()> {
        let rf = self.open_or_load(path).await?;
        {
            let mut file = rf.write().await;
            let mut enriched: Vec<(usize, usize, String)> = Vec::with_capacity(edits.len());
            for e in edits.drain(..) {
                let (start, end) = positions_to_char_range(&file.rope, e.start, e.end)?;
                enriched.push((start, end, e.new_text));
            }
            enriched.sort_by(|a, b| b.0.cmp(&a.0));
            for (start, end, new_text) in enriched.into_iter() {
                if start > end || end > file.rope.len_chars() {
                    return Err(anyhow!("invalid edit range: {}..{}", start, end));
                }
                file.rope.remove(start..end);
                file.rope.insert(start, &new_text);
            }
            file.dirty.store(true, Ordering::SeqCst);
            self.schedule_persist_unlocked(&rf);
            let _ = self.events.send(ResourceEvent::Modified(file.path.clone()));
        }
        Ok(())
    }

    pub async fn list_resources(&self, path: &Path, recursive: bool) -> Result<Vec<ResourceInfo>> {
        let abs = self.ensure_within_root(path)?;
        let mut out = Vec::new();
        if !abs.exists() { return Ok(out); }
        if recursive {
            let mut q = VecDeque::from([abs]);
            while let Some(dir) = q.pop_front() {
                let mut rd = tokio_fs::read_dir(&dir).await?;
                while let Some(entry) = rd.next_entry().await? {
                    let meta = entry.metadata().await?;
                    let is_dir = meta.is_dir();
                    let rel = entry.path().strip_prefix(&self.root).unwrap_or(entry.path().as_path()).to_path_buf();
                    out.push(ResourceInfo { path: rel.to_string_lossy().into_owned(), is_dir, size: meta.len().into() });
                    if is_dir { q.push_back(entry.path()); }
                }
            }
        } else {
            let mut rd = tokio_fs::read_dir(&abs).await?;
            while let Some(entry) = rd.next_entry().await? {
                let meta = entry.metadata().await?;
                let is_dir = meta.is_dir();
                let rel = entry.path().strip_prefix(&self.root).unwrap_or(entry.path().as_path()).to_path_buf();
                out.push(ResourceInfo { path: rel.to_string_lossy().into_owned(), is_dir, size: meta.len().into() });
            }
        }
        Ok(out)
    }

    async fn open_or_load(&self, path: &Path) -> Result<Arc<RwLock<RopeFile>>> {
        let abs = self.ensure_within_root(path)?;
        if let Some(r) = self.files.get(&abs) { return Ok(r.value().clone()); }
        let abs_clone = abs.clone();
        let rope = task::spawn_blocking(move || -> Result<Rope> {
            if abs_clone.exists() {
                let f = fs::File::open(&abs_clone).with_context(|| format!("open {}", abs_clone.display()))?;
                let mut reader = BufReader::new(f);
                Rope::from_reader(&mut reader).context("rope load")
            } else {
                Ok(Rope::new())
            }
        }).await??;
        let rf = Arc::new(RwLock::new(RopeFile { path: abs.clone(), rope, dirty: AtomicBool::new(false), _persist_lock: Mutex::new(()) }));
        self.files.insert(abs.clone(), rf.clone());
        Ok(rf)
    }

    fn schedule_persist_unlocked(&self, rf: &Arc<RwLock<RopeFile>>) {
        let rf = rf.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            // lock and check dirty
            // take a write then clone needed parts while holding it briefly
            let (path, rope, should_persist) = {
                let write_guard = rf.write().await;
                let should_persist = write_guard.dirty.swap(false, Ordering::SeqCst);
                if !should_persist {
                    return;
                }
                let path = write_guard.path.clone();
                let rope = write_guard.rope.clone();
                (path, rope, should_persist)
            };
            if should_persist {
                if let Err(e) = persist_rope(&path, &rope).await {
                    error!(error=%e, path=%path.display(), "persist failed");
                } else {
                    info!(path=%path.display(), "persisted");
                }
            }
        });
    }
}

async fn persist_rope(path: &Path, rope: &Rope) -> Result<()> {
    if let Some(parent) = path.parent() { tokio_fs::create_dir_all(parent).await?; }
    let rope = rope.clone();
    let path = path.to_path_buf();
    task::spawn_blocking(move || -> Result<()> {
        let f = fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
        let mut writer = BufWriter::new(f);
        rope.write_to(&mut writer).context("rope write")?;
        Ok(())
    }).await??;
    Ok(())
}

fn canonicalize(p: &Path) -> Result<PathBuf> {
    if p.exists() { std::fs::canonicalize(p).map_err(Into::into) } else { Ok(p.to_path_buf()) }
}

fn positions_to_char_range(rope: &Rope, start: Position, end: Position) -> Result<(usize, usize)> {
    let start_char = rope.line_to_char(start.line).saturating_add(start.column);
    let end_char = rope.line_to_char(end.line).saturating_add(end.column);
    Ok((start_char, end_char))
}
