use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// -------------------------------
// High-level edit model (public API)
// -------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct NodeRef {
    pub token: String,
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Anchor {
    NodeRef {
        node_ref: NodeRef,
    },
    QueryCapture {
        query: String,
        capture_name: String,
        #[serde(default)]
        occurrence: usize,
    },
    LineColumn {
        line: usize,
        column: usize,
    },
    RegexMatch {
        pattern: String,
        #[serde(default)]
        occurrence: usize,
    },
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RangeSpec {
    ByteRange { start_byte: usize, end_byte: usize },
    LineRange { start_line: usize, end_line: usize },
    NodeRange { anchor: NodeRef },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Change {
    ReplaceNode { anchor: Anchor, new_text: String },
    InsertAfter { anchor: Anchor, new_text: String },
    InsertBefore { anchor: Anchor, new_text: String },
    ReplaceRange { range: RangeSpec, new_text: String },
    DeleteRange { range: RangeSpec },
}
