use std::path::PathBuf;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ResourceEvent {
    Created(PathBuf),
    Deleted(PathBuf),
    Modified(PathBuf),
    ListChanged,
}
