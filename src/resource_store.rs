use std::{
    collections::VecDeque,
    fs,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use ropey::Rope;
use serde::{Deserialize, Serialize};
use tokio::{
    fs as tokio_fs,
    sync::{Mutex, RwLock},
    task,
    time::{Duration, sleep},
};
use tracing::{error, info};
use tree_sitter::{InputEdit, Parser, Point, Tree};

use crate::{
    edit::{Anchor, Change},
    events::ResourceEvent,
    parse_manager::LanguageManager,
};

// Internal-only byte edit representation for normalization pipeline
#[derive(Debug, Clone)]
struct ByteEdit {
    start_byte: usize,
    old_end_byte: usize,
    new_text: String,
}

#[derive(Clone)]
pub struct ResourceStore {
    root: PathBuf,
    files: Arc<DashMap<PathBuf, Arc<RwLock<RopeFile>>>>,
    events: tokio::sync::broadcast::Sender<ResourceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResourceInfo {
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SyntaxDiag {
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ChangeApplyOutcome {
    pub applied: bool,
    pub preview_len_bytes: Option<usize>,
    pub backup_id: Option<String>,
    pub diagnostics: Vec<SyntaxDiag>,
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

#[allow(dead_code)]
impl ResourceStore {
    pub async fn new(root: PathBuf) -> Result<Self> {
        let root = canonicalize(&root)?;
        if !root.exists() {
            tokio_fs::create_dir_all(&root).await?;
        }
        let (tx, _rx) = tokio::sync::broadcast::channel(1024);
        Ok(Self {
            root,
            files: Arc::new(DashMap::new()),
            events: tx,
        })
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ResourceEvent> {
        self.events.subscribe()
    }

    pub fn workspace_root(&self) -> &Path {
        &self.root
    }

    pub fn ensure_within_root(&self, path: &Path) -> Result<PathBuf> {
        // Accept absolute paths if and only if they are within the workspace root
        if path.is_absolute() {
            let canon_root = std::fs::canonicalize(&self.root).unwrap_or(self.root.clone());
            let abs_canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            if abs_canon.starts_with(&canon_root) {
                return Ok(abs_canon);
            }
            return Err(anyhow!(
                "absolute path outside workspace root: given={}, root={}",
                abs_canon.display(),
                canon_root.display()
            ));
        }
        // Reject NUL bytes (invalid for OS operations)
        if path.as_os_str().to_string_lossy().contains('\u{0000}') {
            return Err(anyhow!(
                "invalid path: contains NUL byte (path={})",
                path.display()
            ));
        }
        // Normalize the provided path and prevent traversal outside the workspace root
        use std::path::Component::*;
        let mut rel_stack: Vec<std::ffi::OsString> = Vec::new();
        for comp in path.components() {
            match comp {
                CurDir => { /* ignore */ }
                ParentDir => {
                    if rel_stack.pop().is_none() {
                        return Err(anyhow!(
                            "path escapes workspace root (path={})",
                            path.display()
                        ));
                    }
                }
                Normal(c) => {
                    if !c.is_empty() {
                        rel_stack.push(c.to_os_string());
                    }
                }
                Prefix(_) | RootDir => {
                    return Err(anyhow!(
                        "invalid path: absolute or prefixed component (path={})",
                        path.display()
                    ));
                }
            }
        }
        let mut abs = self.root.clone();
        for c in rel_stack {
            abs.push(c);
        }
        Ok(abs)
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
        if let Some(parent) = abs.parent() {
            tokio_fs::create_dir_all(parent).await?;
        }
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

    // Legacy byte/position editing removed. Use high-level apply_changes.

    pub async fn list_resources(&self, path: &Path, recursive: bool) -> Result<Vec<ResourceInfo>> {
        let abs = self.ensure_within_root(path)?;
        let mut out = Vec::new();
        if !abs.exists() {
            return Ok(out);
        }
        if recursive {
            let mut q = VecDeque::from([abs]);
            while let Some(dir) = q.pop_front() {
                let mut rd = tokio_fs::read_dir(&dir).await?;
                while let Some(entry) = rd.next_entry().await? {
                    let meta = entry.metadata().await?;
                    let is_dir = meta.is_dir();
                    let rel = entry
                        .path()
                        .strip_prefix(&self.root)
                        .unwrap_or(entry.path().as_path())
                        .to_path_buf();
                    out.push(ResourceInfo {
                        path: rel.to_string_lossy().into_owned(),
                        is_dir,
                        size: (!is_dir).then_some(meta.len()),
                    });
                    if is_dir {
                        q.push_back(entry.path());
                    }
                }
            }
        } else {
            let mut rd = tokio_fs::read_dir(&abs).await?;
            while let Some(entry) = rd.next_entry().await? {
                let meta = entry.metadata().await?;
                let is_dir = meta.is_dir();
                let rel = entry
                    .path()
                    .strip_prefix(&self.root)
                    .unwrap_or(entry.path().as_path())
                    .to_path_buf();
                out.push(ResourceInfo {
                    path: rel.to_string_lossy().into_owned(),
                    is_dir,
                    size: (!is_dir).then_some(meta.len()),
                });
            }
        }
        Ok(out)
    }

    pub async fn snapshot(&self, path: &Path) -> Result<(PathBuf, Rope, Option<Tree>, u64)> {
        let rf = self.open_or_load(path).await?;
        let guard = rf.read().await;
        Ok((
            guard.path.clone(),
            guard.rope.clone(),
            guard.tree.clone(),
            guard.version,
        ))
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
        if let Some(r) = self.files.get(&abs) {
            return Ok(r.value().clone());
        }
        let abs_clone = abs.clone();
        let rope = task::spawn_blocking(move || -> Result<Rope> {
            if abs_clone.exists() {
                let f = fs::File::open(&abs_clone)
                    .with_context(|| format!("open {}", abs_clone.display()))?;
                let mut reader = BufReader::new(f);
                Rope::from_reader(&mut reader).context("rope load")
            } else {
                Ok(Rope::new())
            }
        })
        .await??;
        let rf = Arc::new(RwLock::new(RopeFile {
            path: abs.clone(),
            rope,
            tree: None,
            version: 0,
            parsed_version: 0,
            dirty: AtomicBool::new(false),
            _persist_lock: Mutex::new(()),
        }));
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

    // -------------------------------
    // New high-level change pipeline
    // -------------------------------

    pub async fn apply_changes(
        &self,
        path: &Path,
        changes: Vec<Change>,
        dry_run: bool,
        enforce_parse: bool,
        create_backup: bool,
    ) -> Result<crate::server::AstApplyChangesResult> {
        let abs = self.ensure_within_root(path)?;
        if !abs.exists() {
            return Err(anyhow!("file not found: {}", abs.display()));
        }
        let rf = self.open_or_load(path).await?;
        // Snapshot
        let (orig_rope, orig_tree, version) = {
            let guard = rf.read().await;
            (guard.rope.clone(), guard.tree.clone(), guard.version)
        };

        // Resolve high-level changes to byte edits
        let mut byte_edits: Vec<ByteEdit> = Vec::new();
        for ch in changes.iter() {
            match ch {
                Change::ReplaceNode { anchor, new_text } => {
                    let (start, end) = self
                        .resolve_anchor(&abs, &orig_rope, orig_tree.as_ref(), anchor)
                        .await?;
                    byte_edits.push(ByteEdit {
                        start_byte: start,
                        old_end_byte: end,
                        new_text: new_text.clone(),
                    });
                }
                Change::InsertBefore { anchor, new_text } => {
                    let (start, _end) = self
                        .resolve_anchor(&abs, &orig_rope, orig_tree.as_ref(), anchor)
                        .await?;
                    byte_edits.push(ByteEdit {
                        start_byte: start,
                        old_end_byte: start,
                        new_text: new_text.clone(),
                    });
                }
                Change::InsertAfter { anchor, new_text } => {
                    let (_start, end) = self
                        .resolve_anchor(&abs, &orig_rope, orig_tree.as_ref(), anchor)
                        .await?;
                    byte_edits.push(ByteEdit {
                        start_byte: end,
                        old_end_byte: end,
                        new_text: new_text.clone(),
                    });
                }
                Change::ReplaceRange { range, new_text } => {
                    let (s, e) = self
                        .resolve_range(&abs, &orig_rope, orig_tree.as_ref(), range)
                        .await?;
                    byte_edits.push(ByteEdit {
                        start_byte: s,
                        old_end_byte: e,
                        new_text: new_text.clone(),
                    });
                }
                Change::DeleteRange { range } => {
                    let (s, e) = self
                        .resolve_range(&abs, &orig_rope, orig_tree.as_ref(), range)
                        .await?;
                    byte_edits.push(ByteEdit {
                        start_byte: s,
                        old_end_byte: e,
                        new_text: String::new(),
                    });
                }
            }
        }

        // Build normalized, descending edits and InputEdits, validate parse
        let (ies, test_rope, new_tree_opt, diags) = self
            .validate_on_clone(
                &abs,
                &orig_rope,
                &orig_tree,
                byte_edits.clone(),
                enforce_parse,
            )
            .await?;

        if dry_run {
            return Ok(crate::server::AstApplyChangesResult {
                applied: false,
                preview: Some(crate::server::EditPreview {
                    final_len_bytes: test_rope.len_bytes(),
                }),
                backup_id: None,
                diagnostics: if diags.is_empty() {
                    None
                } else {
                    Some(
                        diags
                            .into_iter()
                            .map(|d| crate::server::SyntaxErrorSpan {
                                start_byte: d.start_byte,
                                end_byte: d.end_byte,
                                kind: d.kind,
                            })
                            .collect(),
                    )
                },
            });
        }

        if enforce_parse && !diags.is_empty() {
            return Ok(crate::server::AstApplyChangesResult {
                applied: false,
                preview: None,
                backup_id: None,
                diagnostics: Some(
                    diags
                        .into_iter()
                        .map(|d| crate::server::SyntaxErrorSpan {
                            start_byte: d.start_byte,
                            end_byte: d.end_byte,
                            kind: d.kind,
                        })
                        .collect(),
                ),
            });
        }

        // Commit: check version and apply
        let mut file = rf.write().await;
        if file.version != version {
            return Err(anyhow!(
                "concurrent_edit_conflict: file changed during validation"
            ));
        }

        let mut backup_id: Option<String> = None;
        if create_backup {
            let old_bytes = orig_rope.to_string();
            backup_id = Some(self.write_backup(&abs, old_bytes.as_bytes()).await?);
        }

        // Apply to real rope
        file.rope = test_rope;
        if let Some(nt) = new_tree_opt {
            file.tree = Some(nt);
        }
        file.version = file.version.saturating_add(1);
        file.dirty.store(true, Ordering::SeqCst);
        let ies_clone = ies.clone();
        self.schedule_persist_unlocked(&rf);
        drop(file);

        let _ = self
            .events
            .send(ResourceEvent::Edited(abs.clone(), ies_clone));

        Ok(crate::server::AstApplyChangesResult {
            applied: true,
            preview: None,
            backup_id,
            diagnostics: None,
        })
    }

    #[allow(private_interfaces)]
    pub(crate) async fn apply_byte_edits_with_validation(
        &self,
        path: &Path,
        edits: Vec<ByteEdit>,
        enforce_parse: bool,
        create_backup: bool,
        validate_utf8: bool,
        truncate_tail: bool,
    ) -> Result<()> {
        let abs = self.ensure_within_root(path)?;
        if !abs.exists() {
            return Err(anyhow!("file not found: {}", abs.display()));
        }
        let rf = self.open_or_load(path).await?;
        let (orig_rope, orig_tree, version) = {
            let g = rf.read().await;
            (g.rope.clone(), g.tree.clone(), g.version)
        };
        // Validate offsets and normalize
        let file_len = orig_rope.len_bytes();
        let mut norm: Vec<ByteEdit> = Vec::with_capacity(edits.len());
        for e in edits.into_iter() {
            if e.start_byte > e.old_end_byte {
                return Err(anyhow!(
                    "start_byte {} must be <= old_end_byte {}",
                    e.start_byte,
                    e.old_end_byte
                ));
            }
            if e.old_end_byte > file_len || e.start_byte > file_len {
                return Err(anyhow!(
                    "byte range {}..{} exceeds file size {}",
                    e.start_byte,
                    e.old_end_byte,
                    file_len
                ));
            }
            if validate_utf8
                && (!is_valid_byte_boundary(&orig_rope, e.start_byte)
                    || !is_valid_byte_boundary(&orig_rope, e.old_end_byte))
            {
                return Err(anyhow!("byte offsets are not valid UTF-8 boundaries"));
            }
            norm.push(e);
        }
        if truncate_tail {
            let max_old = norm.iter().map(|e| e.old_end_byte).max().unwrap_or(0);
            if max_old < file_len {
                norm.push(ByteEdit {
                    start_byte: max_old,
                    old_end_byte: file_len,
                    new_text: String::new(),
                });
            }
        }
        // Validate and prepare
        let (ies, test_rope, new_tree_opt, diags) = self
            .validate_on_clone(&abs, &orig_rope, &orig_tree, norm.clone(), enforce_parse)
            .await?;
        if enforce_parse && !diags.is_empty() {
            return Err(anyhow!("parse_rejected: {} errors", diags.len()));
        }
        // Commit with version check
        let mut file = rf.write().await;
        if file.version != version {
            return Err(anyhow!(
                "concurrent_edit_conflict: file changed during validation"
            ));
        }
        if create_backup {
            let old_bytes = orig_rope.to_string();
            let _ = self.write_backup(&abs, old_bytes.as_bytes()).await?;
        }
        file.rope = test_rope;
        if let Some(nt) = new_tree_opt {
            file.tree = Some(nt);
        }
        file.version = file.version.saturating_add(1);
        file.dirty.store(true, Ordering::SeqCst);
        let ies_clone = ies.clone();
        self.schedule_persist_unlocked(&rf);
        drop(file);
        let _ = self
            .events
            .send(ResourceEvent::Edited(abs.clone(), ies_clone));
        Ok(())
    }

    async fn resolve_anchor(
        &self,
        abs: &Path,
        rope: &Rope,
        old_tree: Option<&Tree>,
        anchor: &Anchor,
    ) -> Result<(usize, usize)> {
        match anchor {
            Anchor::LineColumn { line, column } => {
                let start_char = rope.line_to_char(*line).saturating_add(*column);
                let b = rope.char_to_byte(start_char);
                Ok((b, b))
            }
            Anchor::RegexMatch {
                pattern,
                occurrence,
            } => {
                let text = rope.to_string();
                let re = regex::Regex::new(pattern).map_err(|e| anyhow!("invalid regex: {e}"))?;
                for (i, m) in re.find_iter(text.as_str()).enumerate() {
                    if i == *occurrence {
                        return Ok((m.start(), m.end()));
                    }
                }
                Err(anyhow!("regex match not found"))
            }
            Anchor::QueryCapture {
                query,
                capture_name,
                occurrence,
            } => {
                let Some((_id, lang)) = LanguageManager::language_for_path(abs) else {
                    return Err(anyhow!("unsupported language for path"));
                };
                let mut parser = Parser::new();
                parser
                    .set_language(&lang)
                    .map_err(|e| anyhow!("language error: {e:?}"))?;
                let text = rope.to_string();
                let tree = parser
                    .parse(text.as_bytes(), old_tree)
                    .ok_or_else(|| anyhow!("parse failed"))?;
                use tree_sitter::{Query, QueryCursor, StreamingIterator};
                let q = Query::new(&lang, query).map_err(|e| anyhow!("query error: {e:?}"))?;
                let mut cursor = QueryCursor::new();
                let mut it = cursor.captures(&q, tree.root_node(), text.as_bytes());
                let mut idx = 0usize;
                loop {
                    it.next();
                    if let Some((m, cap_ix)) = it.get() {
                        let cap = m.captures[*cap_ix];
                        let name = q.capture_names()[cap.index as usize].to_string();
                        if name == *capture_name {
                            if idx == *occurrence {
                                return Ok((cap.node.start_byte(), cap.node.end_byte()));
                            }
                            idx += 1;
                        }
                    } else {
                        break;
                    }
                }
                Err(anyhow!("query capture not found"))
            }
            Anchor::NodeRef { node_ref } => {
                // Simple token format (for now): "start:end[:version]"
                let parts: Vec<&str> = node_ref.token.split(':').collect();
                if parts.len() < 2 {
                    return Err(anyhow!("invalid node_ref token"));
                }
                let start: usize = parts[0]
                    .parse()
                    .map_err(|_| anyhow!("invalid node_ref token"))?;
                let end: usize = parts[1]
                    .parse()
                    .map_err(|_| anyhow!("invalid node_ref token"))?;
                Ok((start, end))
            }
        }
    }

    async fn resolve_range(
        &self,
        abs: &Path,
        rope: &Rope,
        old_tree: Option<&Tree>,
        range: &crate::edit::RangeSpec,
    ) -> Result<(usize, usize)> {
        match range {
            crate::edit::RangeSpec::ByteRange {
                start_byte,
                end_byte,
            } => Ok((*start_byte, *end_byte)),
            crate::edit::RangeSpec::LineRange {
                start_line,
                end_line,
            } => {
                let sc = rope.line_to_char(*start_line);
                let ec = rope.line_to_char(*end_line);
                Ok((rope.char_to_byte(sc), rope.char_to_byte(ec)))
            }
            crate::edit::RangeSpec::NodeRange { anchor } => {
                // anchor is NodeRef
                self.resolve_anchor(
                    abs,
                    rope,
                    old_tree,
                    &Anchor::NodeRef {
                        node_ref: anchor.clone(),
                    },
                )
                .await
            }
        }
    }

    async fn validate_on_clone(
        &self,
        abs: &Path,
        orig_rope: &Rope,
        orig_tree: &Option<Tree>,
        mut edits: Vec<ByteEdit>,
        enforce_parse: bool,
    ) -> Result<(Vec<InputEdit>, Rope, Option<Tree>, Vec<SyntaxDiag>)> {
        // Sort descending by start_byte
        edits.sort_by(|a, b| b.start_byte.cmp(&a.start_byte));
        // Compute InputEdits relative to original
        let mut ies: Vec<InputEdit> = Vec::with_capacity(edits.len());
        for e in edits.iter() {
            let start_point = point_for_byte(orig_rope, e.start_byte);
            let old_end_point = point_for_byte(orig_rope, e.old_end_byte);
            let new_end_byte = e.start_byte + e.new_text.len();
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
        // Apply to clone
        let mut test_rope = orig_rope.clone();
        let mut test_tree = orig_tree.clone();
        if let Some(t) = &mut test_tree {
            for ie in ies.iter() {
                t.edit(ie);
            }
        }
        for e in edits.into_iter() {
            let sc = test_rope.byte_to_char(e.start_byte);
            let oc = test_rope.byte_to_char(e.old_end_byte);
            test_rope.remove(sc..oc);
            test_rope.insert(sc, &e.new_text);
        }
        // Optionally parse
        let mut diags: Vec<SyntaxDiag> = Vec::new();
        let mut new_tree_opt: Option<Tree> = None;
        if enforce_parse && let Some((_id, lang)) = LanguageManager::language_for_path(abs) {
            let mut parser = Parser::new();
            parser
                .set_language(&lang)
                .map_err(|e| anyhow!("language error: {e:?}"))?;
            let text = test_rope.to_string();
            let parsed = task::spawn_blocking(move || parser.parse(text.as_bytes(), test_tree.as_ref()))
                .await?;
            if let Some(ntree) = parsed.clone() {
                let root = ntree.root_node();
                diags = collect_error_diags(root);
                new_tree_opt = Some(ntree);
            } else {
                diags.push(SyntaxDiag {
                    start_byte: 0,
                    end_byte: 0,
                    kind: "parse_failed".into(),
                });
            }
        }

        Ok((ies, test_rope, new_tree_opt, diags))
    }
}

async fn persist_rope(path: &Path, rope: &Rope) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio_fs::create_dir_all(parent).await?;
    }
    let rope = rope.clone();
    let path = path.to_path_buf();
    task::spawn_blocking(move || -> Result<()> {
        let parent = path.parent().ok_or_else(|| anyhow!("no parent for path"))?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".mingmai.tmp-")
            .tempfile_in(parent)
            .context("tempfile create")?;
        {
            let mut writer = BufWriter::new(&mut tmp);
            rope.write_to(&mut writer).context("rope write")?;
            writer.flush().ok();
        }
        tmp.persist(&path)
            .map_err(|e| anyhow!("atomic persist failed: {}", e))?;
        Ok(())
    })
    .await??;
    Ok(())
}

fn canonicalize(p: &Path) -> Result<PathBuf> {
    if p.exists() {
        std::fs::canonicalize(p).map_err(Into::into)
    } else {
        Ok(p.to_path_buf())
    }
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
        if b == b'\n' {
            rows += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    Point::new(start.row + rows, col)
}

fn is_valid_byte_boundary(rope: &Rope, byte: usize) -> bool {
    let ch = rope.byte_to_char(byte);
    rope.char_to_byte(ch) == byte
}

fn collect_error_diags(root: tree_sitter::Node) -> Vec<SyntaxDiag> {
    let mut out = Vec::new();
    let cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() || node.kind() == "ERROR" {
            out.push(SyntaxDiag {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                kind: node.kind().to_string(),
            });
        }
        for i in 0..node.child_count() {
            if let Some(ch) = node.child(i) {
                stack.push(ch);
            }
        }
    }
    drop(cursor);
    out
}

impl ResourceStore {
    async fn write_backup(&self, path: &Path, data: &[u8]) -> Result<String> {
        let parent = path.parent().ok_or_else(|| anyhow!("no parent for path"))?;
        let dir = parent.join(".mingmai").join("backups");
        tokio_fs::create_dir_all(&dir).await?;
        // build id as sha256 hex
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(data);
        let id = hex::encode(hasher.finalize());
        // timestamp seconds
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let file = dir.join(format!("{}-{}.snap", ts, &id[..16]));
        let outp = file.clone();
        let buf = data.to_vec();
        task::spawn_blocking(move || -> Result<()> {
            let mut tmp = tempfile::Builder::new()
                .prefix("backup-")
                .tempfile_in(outp.parent().unwrap())
                .context("backup tempfile")?;
            tmp.write_all(&buf).context("backup write")?;
            tmp.persist(&outp)
                .map_err(|e| anyhow!("persist backup: {}", e))?;
            Ok(())
        })
        .await??;
        Ok(id)
    }
}
