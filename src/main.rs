use std::{env, path::PathBuf, sync::Arc};

use anyhow::Result;
use rmcp::service::ServiceExt;
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};

mod server;
mod resource_store;
mod edit;
mod errors;
mod events;

use server::MingmaiServer;
use resource_store::ResourceStore;

#[tokio::main]
async fn main() -> Result<()> {
    // Logging to stderr (never stdout for STDIO servers)
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let workspace_root = env::var("MINGMAI_WORKSPACE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().expect("cwd").join("workspace"));

    tracing::info!(root = %workspace_root.display(), "starting mingmai server");

    let store = Arc::new(ResourceStore::new(workspace_root).await?);
    let service = MingmaiServer::new(store.clone());

    // Debug: log generated tools schemas so we can diagnose clients
    {
        let tools = service.tool_router.list_all();
        if let Ok(json) = serde_json::to_string(&tools) {
            tracing::debug!(tools=%json, "generated tools");
        }
    }

    // STDIO transport
    let transport = rmcp::transport::io::stdio();

    // Serve until cancelled
    let running = service.serve(transport).await?;

    // We need to borrow the running service for cancel, but waiting() consumes it; clone token.
    let waiting = running.waiting();

    // Wait for ctrl-c or server completion
    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("ctrl-c received, shutting down");
            // We cannot cancel after moving running into waiting; rely on host to close transport.
        }
        r = waiting => {
            if let Err(e) = r { tracing::error!(error = %e, "server exited with error"); }
        }
    }

    Ok(())
}
