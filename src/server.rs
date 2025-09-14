use std::{path::Path, sync::Arc};

use rmcp::{
    model::{CallToolResult, Content, ErrorData, ServerInfo},
    tool_router,
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
};

use crate::{resource_store::ResourceStore, edit::FileEditReq};

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

#[tool_router]
impl MingmaiServer {
    pub fn new(store: Arc<ResourceStore>) -> Self {
        Self { store, tool_router: Self::tool_router() }
    }

    #[rmcp::tool(description = "Ping")] 
    pub async fn ping(&self, _params: Parameters<PingReq>) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![Content::text("pong")]))
    }

    // Workspace tools
    #[rmcp::tool(description = "Create a directory under the workspace root")] 
    pub async fn workspace_create(&self, params: Parameters<PathOnly>) -> Result<CallToolResult, ErrorData> {
        let path = params.0.path;
        self.store.create_dir(Path::new(&path)).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("ok".to_string())]))
    }

    #[rmcp::tool(description = "Delete a directory under the workspace root")]
    pub async fn workspace_delete(&self, params: Parameters<PathOnly>) -> Result<CallToolResult, ErrorData> {
        let path = params.0.path;
        self.store.delete_dir(Path::new(&path)).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("ok".to_string())]))
    }

    // File tools
    #[rmcp::tool(description = "Create a file with optional content")]
    pub async fn file_create(&self, params: Parameters<CreateFileReq>) -> Result<CallToolResult, ErrorData> {
        let req = params.0;
        self.store.create_file(Path::new(&req.path), req.content).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("ok".to_string())]))
    }

    #[rmcp::tool(description = "Delete a file")]
    pub async fn file_delete(&self, params: Parameters<PathOnly>) -> Result<CallToolResult, ErrorData> {
        let path = params.0.path;
        self.store.delete_file(Path::new(&path)).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("ok".to_string())]))
    }

    #[rmcp::tool(description = "Read and return the full file content")]
    pub async fn file_view(&self, params: Parameters<PathOnly>) -> Result<CallToolResult, ErrorData> {
        let path = params.0.path;
        let text = self.store.read_file(Path::new(&path)).await.map_err(|e| ErrorData::resource_not_found(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[rmcp::tool(description = "Apply edits to a file (line/column based)")]
    pub async fn file_edit(&self, params: Parameters<FileEditReq>) -> Result<CallToolResult, ErrorData> {
        let req = params.0;
        self.store.apply_edits(Path::new(&req.path), req.edits).await.map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("ok".to_string())]))
    }

    #[rmcp::tool(description = "List resources under a path (relative to workspace root)")]
    pub async fn list_resources(&self, params: Parameters<ListReq>) -> Result<CallToolResult, ErrorData> {
        let req = params.0;
        let entries = self.store.list_resources(Path::new(&req.path), if req.recursive { true } else { false }).await.map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::structured(serde_json::to_value(&entries).map_err(|e| ErrorData::internal_error(e.to_string(), None))?))
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
