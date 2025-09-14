use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ResourceEvent {
    Created(PathBuf),
    Deleted(PathBuf),
    Modified(PathBuf),
    ListChanged,
}
