use std::path::PathBuf;
use tree_sitter::InputEdit;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ResourceEvent {
    Created(PathBuf),
    Deleted(PathBuf),
    // A file's text was modified; includes the Tree-sitter-compatible input edits (descending order)
    Edited(PathBuf, Vec<InputEdit>),
    // Fallback generic modified event (legacy)
    Modified(PathBuf),
    ListChanged,
}
