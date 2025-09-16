use std::{path::Path, sync::Arc};

use rmcp::{
    model::{ErrorData, ServerInfo},
    tool_router,
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    Json,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{resource_store::{ResourceStore, ResourceInfo}, edit::ByteEdit, parse_manager::ParseManager};

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
pub struct AstByteEditsReq { pub path: String, pub edits: Vec<ByteEdit> }

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
pub struct ParseResult { pub ok: bool, pub has_tree: bool }

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
    pub async fn ast_apply_byte_edits(&self, params: Parameters<AstByteEditsReq>) -> Result<Json<OkResponse>, ErrorData> {
        let req = params.0;
        self.store
            .apply_byte_edits(Path::new(&req.path), req.edits)
            .await
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        // After byte edits, parse to maintain updated tree snapshot
        let pm = ParseManager::new(self.store.clone());
        let _ = pm.parse_now(Path::new(&req.path)).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(Json(OkResponse { ok: true }))
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
        Ok(Json(ParseResult { ok: true, has_tree: tree.is_some() }))
    }
}

#[rmcp::tool_handler]
impl ServerHandler for MingmaiServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some("Headless IDE for LLMs over MCP".into());
        // Advertise capabilities so hosts know tools/resources exist
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_logging()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_resources()
            .enable_resources_list_changed()
            .build();
        info
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
