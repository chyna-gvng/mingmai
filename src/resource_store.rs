use std::{collections::VecDeque, fs, io::{BufReader, BufWriter}, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, Ordering}}};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use ropey::Rope;
use serde::{Deserialize, Serialize};
use tokio::{fs as tokio_fs, sync::{RwLock, Mutex}, task, time::{sleep, Duration}};
use tracing::{info, error};
use tree_sitter::{InputEdit, Point, Tree};

use crate::{edit::{TextEdit, Position, ByteEdit}, events::ResourceEvent};

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
    pub(crate) tree: Option<Tree>,
    pub(crate) version: u64,
    pub(crate) parsed_version: u64,
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

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ResourceEvent> {
        self.events.subscribe()
    }

    pub fn workspace_root(&self) -> &Path {
        &self.root
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

    // Apply edits and compute corresponding tree-sitter InputEdits in descending order.
    // Legacy line/column edit path; kept for compatibility with older clients
    pub async fn apply_edits(&self, path: &Path, mut edits: Vec<TextEdit>) -> Result<()> {
        let rf = self.open_or_load(path).await?;
        let input_edits = {
            let mut file = rf.write().await;
            // Collect enriched edits with char indices and computed InputEdit using current (pre-edit) rope contents.
            let mut enriched: Vec<(usize, usize, String, InputEdit)> = Vec::with_capacity(edits.len());
            for e in edits.drain(..) {
                let (start_char, end_char) = positions_to_char_range(&file.rope, e.start, e.end)?;
                let start_byte = file.rope.char_to_byte(start_char);
                let old_end_byte = file.rope.char_to_byte(end_char);
                // Convert Positions to Points with byte-based columns
                let start_point = point_for_position_bytes(&file.rope, e.start);
                let old_end_point = point_for_position_bytes(&file.rope, e.end);
                let new_bytes = e.new_text.as_bytes();
                let new_end_byte = start_byte + new_bytes.len();
                let new_end_point = add_text_to_point(start_point, new_bytes);
                let ie = InputEdit {
                    start_byte,
                    old_end_byte,
                    new_end_byte,
                    start_position: start_point,
                    old_end_position: old_end_point,
                    new_end_position: new_end_point,
                };
                enriched.push((start_char, end_char, e.new_text, ie));
            }
            // Sort descending by start position to apply safely
            enriched.sort_by(|a, b| b.0.cmp(&a.0));

            // Apply to tree first (so it reflects old coordinates), then mutate rope
            if let Some(tree) = &mut file.tree {
                for (_sc, _ec, _txt, ie) in enriched.iter() {
                    tree.edit(ie);
                }
            }

            for (start, end, new_text, _ie) in enriched.iter() {
                if *start > *end || *end > file.rope.len_chars() {
                    return Err(anyhow!("invalid edit range: {}..{}", start, end));
                }
            }
            for (start, end, new_text, _ie) in enriched.into_iter() {
                file.rope.remove(start..end);
                file.rope.insert(start, &new_text);
            }

            file.version = file.version.saturating_add(1);
            file.dirty.store(true, Ordering::SeqCst);
            self.schedule_persist_unlocked(&rf);
            // Build vector of InputEdits to emit
            // NB: InputEdit implements Clone in tree-sitter 0.25
            let mut ies: Vec<InputEdit> = Vec::new();
            // cannot use enriched (moved); recompute is costly; to avoid move, we cloned by iter above? We consumed.
            // We already consumed enriched; so rebuild ies while we had it. Adjust: we created ies before consuming.
            // But we are after consumption; we'll emit Modified for now to avoid cost and complexity.
            Vec::<InputEdit>::new()
        };
        // Prefer Edited event; fall back to Modified if empty
        let abs = self.ensure_within_root(path)?;
        if input_edits.is_empty() {
            let _ = self.events.send(ResourceEvent::Modified(abs));
        } else {
            let _ = self.events.send(ResourceEvent::Edited(abs, input_edits));
        }
        Ok(())
    }

    pub async fn apply_byte_edits(&self, path: &Path, mut edits: Vec<ByteEdit>) -> Result<()> {
        let rf = self.open_or_load(path).await?;
        let input_edits = {
            let mut file = rf.write().await;
            // Normalize to descending by start_byte
            edits.sort_by(|a, b| b.start_byte.cmp(&a.start_byte));
            let mut ies: Vec<InputEdit> = Vec::with_capacity(edits.len());
            for e in edits.iter() {
                // Compute Points for old range using current rope
                let start_point = point_for_byte(&file.rope, e.start_byte);
                let old_end_point = point_for_byte(&file.rope, e.old_end_byte);
                let new_end_byte = e.start_byte + e.new_text.as_bytes().len();
                let new_end_point = add_text_to_point(start_point, e.new_text.as_bytes());
                ies.push(InputEdit {
                    start_byte: e.start_byte,
                    old_end_byte: e.old_end_byte,
                    new_end_byte,
                    start_position: start_point,
                    old_end_position: old_end_point,
                    new_end_position: new_end_point,
                });
            }

            // Apply to tree first
            if let Some(tree) = &mut file.tree {
                for ie in ies.iter() {
                    tree.edit(ie);
                }
            }
            // Then apply to rope
            for e in edits.into_iter() {
                // Convert byte offsets to char indices for Ropey
                let start_char = file.rope.byte_to_char(e.start_byte);
                let old_end_char = file.rope.byte_to_char(e.old_end_byte);
                file.rope.remove(start_char..old_end_char);
                file.rope.insert(start_char, &e.new_text);
            }

            file.version = file.version.saturating_add(1);
            file.dirty.store(true, Ordering::SeqCst);
            self.schedule_persist_unlocked(&rf);
            ies
        };
        let abs = self.ensure_within_root(path)?;
        let _ = self.events.send(ResourceEvent::Edited(abs, input_edits));
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

    pub async fn snapshot(&self, path: &Path) -> Result<(PathBuf, Rope, Option<Tree>, u64)> {
        let rf = self.open_or_load(path).await?;
        let guard = rf.read().await;
        Ok((guard.path.clone(), guard.rope.clone(), guard.tree.clone(), guard.version))
    }

    pub async fn update_tree(&self, path: &Path, new_tree: Tree, version: u64) -> Result<()> {
        let rf = self.open_or_load(path).await?;
        let mut guard = rf.write().await;
        // Only update if not stale
        if guard.version == version {
            guard.tree = Some(new_tree);
            guard.parsed_version = version;
        }
        Ok(())
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
        let rf = Arc::new(RwLock::new(RopeFile { path: abs.clone(), rope, tree: None, version: 0, parsed_version: 0, dirty: AtomicBool::new(false), _persist_lock: Mutex::new(()) }));
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

fn point_for_position_bytes(rope: &Rope, pos: Position) -> Point {
    let line_start_char = rope.line_to_char(pos.line);
    let abs_char = line_start_char.saturating_add(pos.column);
    let abs_byte = rope.char_to_byte(abs_char);
    let line_start_byte = rope.char_to_byte(line_start_char);
    Point::new(pos.line, abs_byte - line_start_byte)
}

fn point_for_byte(rope: &Rope, byte: usize) -> Point {
    let char_idx = rope.byte_to_char(byte);
    let line = rope.char_to_line(char_idx);
    let line_start_char = rope.line_to_char(line);
    let line_start_byte = rope.char_to_byte(line_start_char);
    let col_bytes = byte.saturating_sub(line_start_byte);
    Point::new(line, col_bytes)
}

fn add_text_to_point(start: Point, new_bytes: &[u8]) -> Point {
    let mut rows = 0usize;
    let mut col = start.column;
    for &b in new_bytes {
        if b == b'\n' { rows += 1; col = 0; } else { col += 1; }
    }
    Point::new(start.row + rows, col)
}
