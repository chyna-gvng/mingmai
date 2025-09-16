use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TextEdit {
    pub start: Position,
    pub end: Position,
    pub new_text: String,
}

// Legacy type retained only for historical context; no longer used by tools.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FileEditReq {
    pub path: String,
    pub edits: Vec<TextEdit>,
}

// Byte-accurate edit used for AST-based editing flows
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ByteEdit {
    pub start_byte: usize,
    pub old_end_byte: usize,
    pub new_text: String,
}
