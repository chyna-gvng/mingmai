use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum MingmaiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Other: {0}")]
    Other(String),
}

impl From<anyhow::Error> for MingmaiError {
    fn from(e: anyhow::Error) -> Self {
        MingmaiError::Other(e.to_string())
    }
}
