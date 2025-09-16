use std::{collections::BTreeMap, path::Path, sync::Arc};

use rmcp::{
    Json,
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    model::{ErrorData, ServerInfo},
    tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    edit::{ByteEdit, Change},
    parse_manager::{GrammarInfo, LanguageManager, ParseManager},
    resource_store::{ResourceInfo, ResourceStore},
};

const MAX_AST_BYTES: usize = 10 * 1024 * 1024; // 10 MB safety limit for AST operations

#[derive(Clone)]
pub struct MingmaiServer {
    pub store: Arc<ResourceStore>,
    pub tool_router: ToolRouter<Self>,
}

// --------------------
// Standard response envelope
// --------------------
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ToolError {
    pub message: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct Envelope<T: JsonSchema + Serialize + Clone> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ToolError>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

fn ok<T: JsonSchema + Serialize + Clone>(data: T) -> Envelope<T> {
    Envelope {
        ok: true,
        data: Some(data),
        error: None,
        metadata: BTreeMap::new(),
    }
}

fn err<T: JsonSchema + Serialize + Clone>(r#type: &str, message: impl Into<String>) -> Envelope<T> {
    Envelope {
        ok: false,
        data: None,
        error: Some(ToolError {
            r#type: r#type.to_string(),
            message: message.into(),
        }),
        metadata: BTreeMap::new(),
    }
}

// --------------------
// Shared request/response types
// --------------------
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PathOnly {
    pub path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PingReq {}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateFileReq {
    pub path: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListReq {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ParseReq {
    pub path: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstEditReq {
    pub path: String,
    pub edits: Vec<ByteEdit>,
    #[serde(default)]
    pub truncate_tail: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_true")]
    pub validate_utf8: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstQueryReq {
    pub path: String,
    pub query: String,
    #[serde(default)]
    pub range: Option<AstByteRange>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema, Clone)]
pub struct AstByteRange {
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstCaptureOut {
    pub name: String,
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstQueryResult {
    pub captures: Vec<AstCaptureOut>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstNodeAtReq {
    pub path: String,
    pub byte: usize,
    #[serde(default = "default_true")]
    pub named: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstNodeOut {
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub text: String,
    pub sexp: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstGetTreeReq {
    pub path: String,
    #[serde(default)]
    pub pretty: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstGetTreeResult {
    pub sexp: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct PingResult {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct CreateFileResult {
    pub ok: bool,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct FileViewResult {
    pub path: String,
    pub content: String,
    pub exists: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListResourcesResult {
    pub items: Vec<ResourceInfo>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct SyntaxErrorSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ParseResult {
    pub has_tree: bool,
    pub exists: bool,
    pub language_detected: Option<String>,
    pub error_count: Option<usize>,
    #[serde(default)]
    pub errors: Option<Vec<SyntaxErrorSpan>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListGrammarsResult {
    pub grammars: Vec<GrammarInfo>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct EditPreview {
    pub final_len_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstEditResult {
    pub applied: bool,
    #[serde(default)]
    pub preview: Option<EditPreview>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstApplyChangesReq {
    pub path: String,
    pub changes: Vec<Change>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_true")]
    pub enforce_parse: bool,
    #[serde(default = "default_true")]
    pub create_backup: bool,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct AstApplyChangesResult {
    pub applied: bool,
    #[serde(default)]
    pub preview: Option<EditPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Vec<SyntaxErrorSpan>>,
}

#[tool_router]
impl MingmaiServer {
    pub fn new(store: Arc<ResourceStore>) -> Self {
        Self {
            store,
            tool_router: Self::tool_router(),
        }
    }

    #[rmcp::tool(description = "Ping the server for a quick health check")]
    pub async fn ping(
        &self,
        _params: Parameters<PingReq>,
    ) -> Result<Json<Envelope<PingResult>>, ErrorData> {
        Ok(Json(ok(PingResult {
            message: "pong".into(),
        })))
    }

    // Workspace tools
    #[rmcp::tool(
        description = "Create a directory under the workspace root (relative or absolute within root)"
    )]
    pub async fn workspace_create(
        &self,
        params: Parameters<PathOnly>,
    ) -> Result<Json<Envelope<OkResponse>>, ErrorData> {
        let path = params.0.path;
        match self.store.create_dir(Path::new(&path)).await {
            Ok(_) => Ok(Json(ok(OkResponse { ok: true }))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, path),
            ))),
        }
    }

    #[rmcp::tool(
        description = "Delete a directory under the workspace root (non-recursive deletion of root is disallowed)"
    )]
    pub async fn workspace_delete(
        &self,
        params: Parameters<PathOnly>,
    ) -> Result<Json<Envelope<OkResponse>>, ErrorData> {
        let path = params.0.path;
        if path.trim().is_empty() || path == "." || path == "/" {
            return Ok(Json(err(
                "invalid_params",
                "Refusing to delete workspace root without explicit path",
            )));
        }
        match self.store.delete_dir(Path::new(&path)).await {
            Ok(_) => Ok(Json(ok(OkResponse { ok: true }))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, path),
            ))),
        }
    }

    // File tools
    #[rmcp::tool(
        description = "Create a file with optional content; path must not escape the workspace root"
    )]
    pub async fn file_create(
        &self,
        params: Parameters<CreateFileReq>,
    ) -> Result<Json<Envelope<CreateFileResult>>, ErrorData> {
        let req = params.0;
        match self
            .store
            .create_file(Path::new(&req.path), req.content)
            .await
        {
            Ok(_) => Ok(Json(ok(CreateFileResult {
                ok: true,
                path: req.path,
            }))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, req.path),
            ))),
        }
    }

    #[rmcp::tool(
        description = "Delete a file (checks existence and returns a clear error if missing)"
    )]
    pub async fn file_delete(
        &self,
        params: Parameters<PathOnly>,
    ) -> Result<Json<Envelope<OkResponse>>, ErrorData> {
        let path = params.0.path;
        let abs = match self.store.ensure_within_root(Path::new(&path)) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, path),
                )));
            }
        };
        if !abs.exists() {
            return Ok(Json(err("not_found", format!("file not found: {}", path))));
        }
        match self.store.delete_file(Path::new(&path)).await {
            Ok(_) => Ok(Json(ok(OkResponse { ok: true }))),
            Err(e) => Ok(Json(err("io_error", format!("{} (path={})", e, path)))),
        }
    }

    #[rmcp::tool(
        description = "Read and return the full file content; returns not_found if the file does not exist"
    )]
    pub async fn file_view(
        &self,
        params: Parameters<PathOnly>,
    ) -> Result<Json<Envelope<FileViewResult>>, ErrorData> {
        let path = params.0.path;
        let abs = match self.store.ensure_within_root(Path::new(&path)) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, path),
                )));
            }
        };
        if !abs.exists() {
            return Ok(Json(err("not_found", format!("file not found: {}", path))));
        }
        match self.store.read_file(Path::new(&path)).await {
            Ok(text) => Ok(Json(ok(FileViewResult {
                path,
                content: text,
                exists: true,
            }))),
            Err(e) => Ok(Json(err("io_error", format!("{} (path={})", e, path)))),
        }
    }

    // AST / Parsing tools (legacy low-level byte edits)
    #[rmcp::tool(
        description = "Apply byte-accurate edits; validates bounds and file existence. Use dry_run=true for a preview."
    )]
    pub async fn ast_edit(
        &self,
        params: Parameters<AstEditReq>,
    ) -> Result<Json<Envelope<AstEditResult>>, ErrorData> {
        let req = params.0;
        if req.dry_run {
            return match self
                .store
                .apply_byte_edits_preview(
                    Path::new(&req.path),
                    req.edits.clone(),
                    req.truncate_tail,
                    req.validate_utf8,
                )
                .await
            {
                Ok(final_len) => Ok(Json(ok(AstEditResult {
                    applied: false,
                    preview: Some(EditPreview {
                        final_len_bytes: final_len,
                    }),
                }))),
                Err(e) => Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, req.path),
                ))),
            };
        }
        match self
            .store
            .apply_byte_edits_with_validation(
                Path::new(&req.path),
                req.edits,
                /*enforce_parse=*/ true,
                /*create_backup=*/ true,
                /*validate_utf8=*/ req.validate_utf8,
                /*truncate_tail=*/ req.truncate_tail,
            )
            .await
        {
            Ok(_) => Ok(Json(ok(AstEditResult {
                applied: true,
                preview: None,
            }))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, req.path),
            ))),
        }
    }

    // New high-level change application API
    #[rmcp::tool(
        description = "Apply high-level AST changes (anchors/queries/nodes); server computes byte edits and validates parse before commit."
    )]
    pub async fn ast_apply_changes(
        &self,
        params: Parameters<AstApplyChangesReq>,
    ) -> Result<Json<Envelope<AstApplyChangesResult>>, ErrorData> {
        let req = params.0;
        match self
            .store
            .apply_changes(
                Path::new(&req.path),
                req.changes,
                req.dry_run,
                req.enforce_parse,
                req.create_backup,
            )
            .await
        {
            Ok(res) => Ok(Json(ok(res))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, req.path),
            ))),
        }
    }

    #[rmcp::tool(description = "List resources under a path (relative to workspace root)")]
    pub async fn list_resources(
        &self,
        params: Parameters<ListReq>,
    ) -> Result<Json<Envelope<ListResourcesResult>>, ErrorData> {
        let req = params.0;
        match self
            .store
            .list_resources(Path::new(&req.path), req.recursive)
            .await
        {
            Ok(items) => Ok(Json(ok(ListResourcesResult { items }))),
            Err(e) => Ok(Json(err(
                "invalid_params",
                format!("{} (path={})", e, req.path),
            ))),
        }
    }

    #[rmcp::tool(
        description = "Parse a document now and update internal tree snapshot; returns error counts and spans"
    )]
    pub async fn parse_document(
        &self,
        params: Parameters<ParseReq>,
    ) -> Result<Json<Envelope<ParseResult>>, ErrorData> {
        let path = params.0.path;
        let (abs, rope, _old_tree, _version) = match self.store.snapshot(Path::new(&path)).await {
            Ok(s) => s,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, path),
                )));
            }
        };
        let exists = abs.exists();
        if rope.len_bytes() > MAX_AST_BYTES {
            return Ok(Json(err(
                "size_limit",
                format!(
                    "file size {} exceeds AST limit {} bytes (path={})",
                    rope.len_bytes(),
                    MAX_AST_BYTES,
                    path
                ),
            )));
        }
        let pm = ParseManager::new(self.store.clone());
        let tree = match pm.parse_now(Path::new(&path)).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(Json(err(
                    "internal_error",
                    format!("parse error: {} (path={})", e, path),
                )));
            }
        };
        let language_detected = LanguageManager::language_for_path(&abs).map(|(id, _)| match id {
            crate::parse_manager::LanguageId::Rust => "rust".to_string(),
            crate::parse_manager::LanguageId::Javascript => "javascript".to_string(),
            crate::parse_manager::LanguageId::Typescript => "typescript".to_string(),
            crate::parse_manager::LanguageId::Tsx => "tsx".to_string(),
            crate::parse_manager::LanguageId::Python => "python".to_string(),
            crate::parse_manager::LanguageId::Bash => "bash".to_string(),
            crate::parse_manager::LanguageId::Html => "html".to_string(),
        });
        let (error_count, errors) = if let Some(t) = &tree {
            let root = t.root_node();
            let errs = collect_error_spans(root);
            (Some(errs.len()), Some(errs))
        } else {
            (None, None)
        };
        Ok(Json(ok(ParseResult {
            has_tree: tree.is_some(),
            exists,
            language_detected,
            error_count,
            errors,
        })))
    }

    #[rmcp::tool(
        description = "Run a Tree-sitter query and return captures. Errors if file missing or range invalid. Example: (function_declaration name: (identifier) @name)"
    )]
    pub async fn ast_query(
        &self,
        params: Parameters<AstQueryReq>,
    ) -> Result<Json<Envelope<AstQueryResult>>, ErrorData> {
        use tree_sitter::{Query, QueryCursor, StreamingIterator};
        let req = params.0;
        let (abs, rope, _old_tree, _version) = match self.store.snapshot(Path::new(&req.path)).await
        {
            Ok(s) => s,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, req.path),
                )));
            }
        };
        if !abs.exists() {
            return Ok(Json(err(
                "not_found",
                format!("file not found: {}", req.path),
            )));
        }
        if rope.len_bytes() > MAX_AST_BYTES {
            return Ok(Json(err(
                "size_limit",
                format!(
                    "file size {} exceeds AST limit {} bytes (path={})",
                    rope.len_bytes(),
                    MAX_AST_BYTES,
                    req.path
                ),
            )));
        }
        if let Some(r) = &req.range {
            if r.start_byte > r.end_byte {
                return Ok(Json(err(
                    "invalid_params",
                    "start_byte must be <= end_byte",
                )));
            }
            if r.end_byte > rope.len_bytes() {
                return Ok(Json(err(
                    "bounds_error",
                    format!(
                        "range {}..{} exceeds file size {}",
                        r.start_byte,
                        r.end_byte,
                        rope.len_bytes()
                    ),
                )));
            }
        }
        let pm = ParseManager::new(self.store.clone());
        let tree = match pm.parse_now(Path::new(&req.path)).await {
            Ok(o) => match o {
                Some(t) => t,
                None => return Ok(Json(err("language_error", "Unsupported language for path"))),
            },
            Err(e) => {
                return Ok(Json(err(
                    "internal_error",
                    format!("parse error: {} (path={})", e, req.path),
                )));
            }
        };
        let Some((_id, lang)) = LanguageManager::language_for_path(&abs) else {
            return Ok(Json(err("language_error", "Unsupported language for path")));
        };
        let query = match Query::new(&lang, &req.query) {
            Ok(q) => q,
            Err(e) => return Ok(Json(err("invalid_params", format!("query error: {e:?}")))),
        };
        let mut cursor = QueryCursor::new();
        if let Some(r) = req.range {
            cursor.set_byte_range(r.start_byte..r.end_byte);
        }
        let text = rope.to_string();
        let root = tree.root_node();
        let mut out = Vec::new();
        let mut it = cursor.captures(&query, root, text.as_bytes());
        loop {
            it.next();
            if let Some((m, ix)) = it.get() {
                let cap = m.captures[*ix];
                let node = cap.node;
                let name = query.capture_names()[cap.index as usize].to_string();
                let start = node.start_byte();
                let end = node.end_byte();
                let slice = &text.as_bytes()[start..end.min(text.len())];
                let text_snip = String::from_utf8_lossy(slice).into_owned();
                out.push(AstCaptureOut {
                    name,
                    kind: node.kind().to_string(),
                    start_byte: start,
                    end_byte: end,
                    text: text_snip,
                });
            } else {
                break;
            }
        }
        Ok(Json(ok(AstQueryResult { captures: out })))
    }

    #[rmcp::tool(description = "Get the smallest node at a byte offset; validates bounds")]
    pub async fn ast_node_at(
        &self,
        params: Parameters<AstNodeAtReq>,
    ) -> Result<Json<Envelope<AstNodeOut>>, ErrorData> {
        let req = params.0;
        let (abs, rope, _old_tree, _version) = match self.store.snapshot(Path::new(&req.path)).await
        {
            Ok(s) => s,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, req.path),
                )));
            }
        };
        if !abs.exists() {
            return Ok(Json(err(
                "not_found",
                format!("file not found: {}", req.path),
            )));
        }
        if rope.len_bytes() > MAX_AST_BYTES {
            return Ok(Json(err(
                "size_limit",
                format!(
                    "file size {} exceeds AST limit {} bytes (path={})",
                    rope.len_bytes(),
                    MAX_AST_BYTES,
                    req.path
                ),
            )));
        }
        let len = rope.len_bytes();
        if req.byte >= len {
            return Ok(Json(err(
                "bounds_error",
                format!("byte {} exceeds file size {}", req.byte, len),
            )));
        }
        let pm = ParseManager::new(self.store.clone());
        let tree = match pm.parse_now(Path::new(&req.path)).await {
            Ok(o) => match o {
                Some(t) => t,
                None => return Ok(Json(err("language_error", "Unsupported language for path"))),
            },
            Err(e) => {
                return Ok(Json(err(
                    "internal_error",
                    format!("parse error: {} (path={})", e, req.path),
                )));
            }
        };
        let text = rope.to_string();
        let root = tree.root_node();
        let node = if req.named {
            root.named_descendant_for_byte_range(req.byte, req.byte)
                .unwrap_or(root)
        } else {
            root.descendant_for_byte_range(req.byte, req.byte)
                .unwrap_or(root)
        };
        let start = node.start_byte();
        let end = node.end_byte();
        let s = node.to_sexp();
        let slice = &text.as_bytes()[start..end.min(text.len())];
        let text_snip = String::from_utf8_lossy(slice).into_owned();
        Ok(Json(ok(AstNodeOut {
            kind: node.kind().to_string(),
            start_byte: start,
            end_byte: end,
            text: text_snip,
            sexp: s,
        })))
    }

    #[rmcp::tool(
        description = "Return the entire parse tree as an S-expression (set pretty=true for readable formatting)"
    )]
    pub async fn ast_get_tree(
        &self,
        params: Parameters<AstGetTreeReq>,
    ) -> Result<Json<Envelope<AstGetTreeResult>>, ErrorData> {
        let req = params.0;
        let (abs, rope, _old_tree, _version) = match self.store.snapshot(Path::new(&req.path)).await
        {
            Ok(s) => s,
            Err(e) => {
                return Ok(Json(err(
                    "invalid_params",
                    format!("{} (path={})", e, req.path),
                )));
            }
        };
        if !abs.exists() {
            return Ok(Json(err(
                "not_found",
                format!("file not found: {}", req.path),
            )));
        }
        if rope.len_bytes() > MAX_AST_BYTES {
            return Ok(Json(err(
                "size_limit",
                format!(
                    "file size {} exceeds AST limit {} bytes (path={})",
                    rope.len_bytes(),
                    MAX_AST_BYTES,
                    req.path
                ),
            )));
        }
        let pm = ParseManager::new(self.store.clone());
        let tree = match pm.parse_now(Path::new(&req.path)).await {
            Ok(o) => match o {
                Some(t) => t,
                None => return Ok(Json(err("language_error", "Unsupported language for path"))),
            },
            Err(e) => {
                return Ok(Json(err(
                    "internal_error",
                    format!("parse error: {} (path={})", e, req.path),
                )));
            }
        };
        let sexp = tree.root_node().to_sexp();
        let out = if req.pretty { pretty_sexp(&sexp) } else { sexp };
        Ok(Json(ok(AstGetTreeResult { sexp: out })))
    }

    #[rmcp::tool(description = "List supported grammars at runtime")]
    pub async fn list_grammars(
        &self,
        _params: Parameters<PingReq>,
    ) -> Result<Json<Envelope<ListGrammarsResult>>, ErrorData> {
        Ok(Json(ok(ListGrammarsResult {
            grammars: LanguageManager::list_grammars(),
        })))
    }
}

#[allow(dead_code)]
fn count_error_nodes(root: tree_sitter::Node) -> usize {
    let mut count = 0usize;
    let cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() || node.kind() == "ERROR" {
            count += 1;
        }
        for i in 0..node.child_count() {
            if let Some(ch) = node.child(i) {
                stack.push(ch);
            }
        }
    }
    drop(cursor);
    count
}

fn collect_error_spans(root: tree_sitter::Node) -> Vec<SyntaxErrorSpan> {
    let mut out = Vec::new();
    let cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let is_err = node.is_error() || node.is_missing() || node.kind() == "ERROR";
        if is_err {
            out.push(SyntaxErrorSpan {
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

fn pretty_sexp(input: &str) -> String {
    // Very simple pretty printer for S-expressions
    let mut out = String::with_capacity(input.len() * 2);
    let mut indent: usize = 0;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' => {
                if !out.ends_with('\n') && !out.is_empty() {
                    out.push('\n');
                }
                for _ in 0..indent {
                    out.push_str("  ");
                }
                out.push('(');
                indent += 1;
            }
            ')' => {
                if out.ends_with('\n') {
                    for _ in 0..indent.saturating_sub(1) {
                        out.push_str("  ");
                    }
                }
                indent = indent.saturating_sub(1);
                out.push(')');
                if matches!(chars.peek(), Some(')') | Some('(') | Some(' ')) {
                } else {
                    out.push('\n');
                }
            }
            ' ' => {
                out.push(' ');
            }
            _ => {
                out.push(c);
            }
        }
    }
    out
}

#[rmcp::tool_handler]
impl ServerHandler for MingmaiServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Headless IDE for LLMs over MCP".into()),
            capabilities: rmcp::model::ServerCapabilities::builder()
                .enable_logging()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .build(),
            ..ServerInfo::default()
        }
    }

    fn set_level(
        &self,
        _request: rmcp::model::SetLevelRequestParam,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), ErrorData>> + Send + '_ {
        std::future::ready(Ok(()))
    }
}
