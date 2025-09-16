use std::{path::Path, sync::Arc};

use rmcp::{
    model::{ErrorData, ServerInfo},
    tool_router,
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    Json,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{resource_store::{ResourceStore, ResourceInfo}, edit::ByteEdit, parse_manager::{ParseManager, LanguageManager, GrammarInfo}};

#[derive(Clone)]
pub struct MingmaiServer {
    pub store: Arc<ResourceStore>,
    pub tool_router: ToolRouter<Self>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PathOnly { pub path: String }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PingReq {}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CreateFileReq { pub path: String, #[serde(default)] pub content: String }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListReq { #[serde(default)] pub path: String, #[serde(default)] pub recursive: bool }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ParseReq { pub path: String }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstEditReq {
    pub path: String,
    pub edits: Vec<ByteEdit>,
    #[serde(default)] pub truncate_tail: bool,
    #[serde(default)] pub dry_run: bool,
    #[serde(default = "default_true")] pub validate_utf8: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstQueryReq {
    pub path: String,
    pub query: String,
    #[serde(default)] pub range: Option<AstByteRange>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstByteRange { pub start_byte: usize, pub end_byte: usize }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AstCaptureOut {
    pub name: String,
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AstQueryResult { pub captures: Vec<AstCaptureOut> }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstNodeAtReq { pub path: String, pub byte: usize, #[serde(default = "default_true")] pub named: bool }

fn default_true() -> bool { true }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AstNodeOut {
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub text: String,
    pub sexp: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AstGetTreeReq { pub path: String }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AstGetTreeResult { pub sexp: String }

// Structured outputs for all tools
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct OkResponse { pub ok: bool }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct PingResult { pub message: String }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CreateFileResult { pub ok: bool, pub path: String }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileViewResult { pub path: String, pub content: String }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListResourcesResult { pub items: Vec<ResourceInfo> }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ParseResult {
    pub ok: bool,
    pub has_tree: bool,
    pub exists: bool,
    pub language_detected: Option<String>,
    pub error_count: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListGrammarsResult { pub grammars: Vec<GrammarInfo> }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct EditPreview { pub final_len_bytes: usize }

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct AstEditResult { pub ok: bool, #[serde(default)] pub preview: Option<EditPreview> }

#[tool_router]
impl MingmaiServer {
    pub fn new(store: Arc<ResourceStore>) -> Self {
        Self { store, tool_router: Self::tool_router() }
    }

    #[rmcp::tool(description = "Ping")]
    pub async fn ping(&self, _params: Parameters<PingReq>) -> Result<Json<PingResult>, ErrorData> {
        Ok(Json(PingResult { message: "pong".into() }))
    }

    // Workspace tools
    #[rmcp::tool(description = "Create a directory under the workspace root")]
    pub async fn workspace_create(&self, params: Parameters<PathOnly>) -> Result<Json<OkResponse>, ErrorData> {
        let path = params.0.path;
        self.store
            .create_dir(Path::new(&path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(OkResponse { ok: true }))
    }

    #[rmcp::tool(description = "Delete a directory under the workspace root")]
    pub async fn workspace_delete(&self, params: Parameters<PathOnly>) -> Result<Json<OkResponse>, ErrorData> {
        let path = params.0.path;
        // Safeguard: disallow deleting root without explicit force flag in path string (e.g., "/" or empty)
        if path.trim().is_empty() || path == "." || path == "/" {
            return Err(ErrorData::invalid_params("Refusing to delete workspace root without explicit path", None));
        }
        self.store
            .delete_dir(Path::new(&path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(OkResponse { ok: true }))
    }

    // File tools
    #[rmcp::tool(description = "Create a file with optional content")]
    pub async fn file_create(&self, params: Parameters<CreateFileReq>) -> Result<Json<CreateFileResult>, ErrorData> {
        let req = params.0;
        self.store
            .create_file(Path::new(&req.path), req.content)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(CreateFileResult { ok: true, path: req.path }))
    }

    #[rmcp::tool(description = "Delete a file")]
    pub async fn file_delete(&self, params: Parameters<PathOnly>) -> Result<Json<OkResponse>, ErrorData> {
        let path = params.0.path;
        self.store
            .delete_file(Path::new(&path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(OkResponse { ok: true }))
    }

    #[rmcp::tool(description = "Read and return the full file content")]
    pub async fn file_view(&self, params: Parameters<PathOnly>) -> Result<Json<FileViewResult>, ErrorData> {
        let path = params.0.path;
        let text = self
            .store
            .read_file(Path::new(&path))
            .await
            .map_err(|e| ErrorData::resource_not_found(e.to_string(), None))?;
        Ok(Json(FileViewResult { path, content: text }))
    }

    // NOTE: The legacy line/column `file_edit` tool has been removed in favor of AST-based byte edits.

    #[rmcp::tool(description = "Apply byte-accurate AST edits to a file")]
    pub async fn ast_edit(&self, params: Parameters<AstEditReq>) -> Result<Json<AstEditResult>, ErrorData> {
        let req = params.0;
        if req.dry_run {
            let final_len = self.store
                .apply_byte_edits_preview(Path::new(&req.path), req.edits.clone(), req.truncate_tail, req.validate_utf8)
                .await
                .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
            return Ok(Json(AstEditResult { ok: true, preview: Some(EditPreview { final_len_bytes: final_len }) }));
        }
        self.store
            .apply_byte_edits_with_opts(Path::new(&req.path), req.edits, req.truncate_tail, req.validate_utf8)
            .await
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        // After byte edits, parse to maintain updated tree snapshot
        let pm = ParseManager::new(self.store.clone());
        let _ = pm.parse_now(Path::new(&req.path)).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(AstEditResult { ok: true, preview: None }))
    }

    #[rmcp::tool(description = "List resources under a path (relative to workspace root)")]
    pub async fn list_resources(&self, params: Parameters<ListReq>) -> Result<Json<ListResourcesResult>, ErrorData> {
        let req = params.0;
        let entries = self
            .store
            .list_resources(Path::new(&req.path), req.recursive)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(ListResourcesResult { items: entries }))
    }

    // Parsing tools (initial minimal set)
    #[rmcp::tool(description = "Parse a document now and update internal tree snapshot")]
    pub async fn parse_document(&self, params: Parameters<ParseReq>) -> Result<Json<ParseResult>, ErrorData> {
        let req = params.0;
        let pm = ParseManager::new(self.store.clone());
        let tree = pm.parse_now(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let (abs, _rope, _old_tree, _version) = self.store.snapshot(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let exists = abs.exists();
        let language_detected = LanguageManager::language_for_path(&abs).map(|(id, _)| match id {
            crate::parse_manager::LanguageId::Rust => "rust".to_string(),
            crate::parse_manager::LanguageId::Javascript => "javascript".to_string(),
            crate::parse_manager::LanguageId::Typescript => "typescript".to_string(),
            crate::parse_manager::LanguageId::Tsx => "tsx".to_string(),
            crate::parse_manager::LanguageId::Python => "python".to_string(),
            crate::parse_manager::LanguageId::Bash => "bash".to_string(),
            crate::parse_manager::LanguageId::Html => "html".to_string(),
        });
        let error_count = tree.as_ref().map(|t| {
            let root = t.root_node();
            count_error_nodes(root)
        });
        Ok(Json(ParseResult { ok: true, has_tree: tree.is_some(), exists, language_detected, error_count }))
    }

    #[rmcp::tool(description = "Run a Tree-sitter query and return captures")]
    pub async fn ast_query(&self, params: Parameters<AstQueryReq>) -> Result<Json<AstQueryResult>, ErrorData> {
        use tree_sitter::{Query, QueryCursor, StreamingIterator};
        let req = params.0;
        // Ensure we have the latest parse
        let pm = ParseManager::new(self.store.clone());
        let tree = pm.parse_now(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .ok_or_else(|| ErrorData::resource_not_found("No parse tree available", None))?;
        let (abs, rope, _old_tree, _version) = self.store.snapshot(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        // Get language
        let Some((_id, lang)) = LanguageManager::language_for_path(&abs) else {
            return Err(ErrorData::invalid_params("Unsupported language for path", None));
        };
        let query = Query::new(&lang, &req.query)
            .map_err(|e| ErrorData::invalid_params(format!("query error: {e:?}"), None))?;
        let mut cursor = QueryCursor::new();
        // Limit search range if provided
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
                out.push(AstCaptureOut { name, kind: node.kind().to_string(), start_byte: start, end_byte: end, text: text_snip });
            } else { break; }
        }
        Ok(Json(AstQueryResult { captures: out }))
    }

    #[rmcp::tool(description = "Get the smallest node at a byte offset")]
    pub async fn ast_node_at(&self, params: Parameters<AstNodeAtReq>) -> Result<Json<AstNodeOut>, ErrorData> {
        let req = params.0;
        let pm = ParseManager::new(self.store.clone());
        let tree = pm.parse_now(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .ok_or_else(|| ErrorData::resource_not_found("No parse tree available", None))?;
        let (_abs, rope, _old_tree, _version) = self.store.snapshot(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let text = rope.to_string();
        let root = tree.root_node();
        let node = if req.named {
            root.named_descendant_for_byte_range(req.byte, req.byte).unwrap_or(root)
        } else {
            root.descendant_for_byte_range(req.byte, req.byte).unwrap_or(root)
        };
        let start = node.start_byte();
        let end = node.end_byte();
        let s = node.to_sexp();
        let slice = &text.as_bytes()[start..end.min(text.len())];
        let text_snip = String::from_utf8_lossy(slice).into_owned();
        Ok(Json(AstNodeOut { kind: node.kind().to_string(), start_byte: start, end_byte: end, text: text_snip, sexp: s }))
    }

    #[rmcp::tool(description = "Return the entire parse tree as an S-expression (for debugging)")]
    pub async fn ast_get_tree(&self, params: Parameters<AstGetTreeReq>) -> Result<Json<AstGetTreeResult>, ErrorData> {
        let req = params.0;
        let pm = ParseManager::new(self.store.clone());
        let tree = pm.parse_now(Path::new(&req.path))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .ok_or_else(|| ErrorData::resource_not_found("No parse tree available", None))?;
        Ok(Json(AstGetTreeResult { sexp: tree.root_node().to_sexp() }))
    }

    #[rmcp::tool(description = "List supported grammars at runtime")]
    pub async fn list_grammars(&self, _params: Parameters<PingReq>) -> Result<Json<ListGrammarsResult>, ErrorData> {
        Ok(Json(ListGrammarsResult { grammars: LanguageManager::list_grammars() }))
    }
}

fn count_error_nodes(root: tree_sitter::Node) -> usize {
    let mut count = 0usize;
    let cursor = root.walk();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_error() || node.is_missing() || node.kind() == "ERROR" { count += 1; }
        for i in 0..node.child_count() {
            if let Some(ch) = node.child(i) { stack.push(ch); }
        }
    }
    drop(cursor);
    count
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
        // Accept and ignore for now; logging is configured via RUST_LOG at startup.
        std::future::ready(Ok(()))
    }
}
