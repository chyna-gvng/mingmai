use std::{path::Path, sync::Arc};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::task;
use tree_sitter::{Language, Parser, Tree};

use crate::resource_store::ResourceStore;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LanguageId {
    Rust,
    Javascript,
    Typescript,
    Tsx,
    Python,
    Bash,
    Html,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GrammarInfo {
    pub id: String,
    pub display_name: String,
    pub extensions: Vec<String>,
    #[serde(default)]
    pub supports_queries: bool,
    #[serde(default)]
    pub description: Option<String>,
}

pub struct LanguageManager;

impl LanguageManager {
    pub fn language_for_path(path: &Path) -> Option<(LanguageId, Language)> {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "rs" => Some((LanguageId::Rust, tree_sitter_rust::LANGUAGE.into())),
            "js" | "mjs" | "cjs" => Some((LanguageId::Javascript, tree_sitter_javascript::LANGUAGE.into())),
            "ts" => Some((LanguageId::Typescript, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())),
            "tsx" => Some((LanguageId::Tsx, tree_sitter_typescript::LANGUAGE_TSX.into())),
            "py" => Some((LanguageId::Python, tree_sitter_python::LANGUAGE.into())),
            "sh" | "bash" => Some((LanguageId::Bash, tree_sitter_bash::LANGUAGE.into())),
            "html" | "htm" => Some((LanguageId::Html, tree_sitter_html::LANGUAGE.into())),
            _ => None,
        }
    }

    pub fn list_grammars() -> Vec<GrammarInfo> {
        vec![
            GrammarInfo { id: "rust".into(), display_name: "Rust".into(), extensions: vec!["rs".into()], supports_queries: true, description: None },
            GrammarInfo { id: "javascript".into(), display_name: "JavaScript".into(), extensions: vec!["js".into(), "mjs".into(), "cjs".into()], supports_queries: true, description: None },
            GrammarInfo { id: "typescript".into(), display_name: "TypeScript".into(), extensions: vec!["ts".into()], supports_queries: true, description: None },
            GrammarInfo { id: "tsx".into(), display_name: "TSX".into(), extensions: vec!["tsx".into()], supports_queries: true, description: None },
            GrammarInfo { id: "python".into(), display_name: "Python".into(), extensions: vec!["py".into()], supports_queries: true, description: None },
            GrammarInfo { id: "bash".into(), display_name: "Bash".into(), extensions: vec!["sh".into(), "bash".into()], supports_queries: true, description: None },
            GrammarInfo { id: "html".into(), display_name: "HTML".into(), extensions: vec!["html".into(), "htm".into()], supports_queries: true, description: None },
        ]
    }
}

#[derive(Clone)]
pub struct ParseManager {
    store: Arc<ResourceStore>,
}

impl ParseManager {
    pub fn new(store: Arc<ResourceStore>) -> Self { Self { store } }

    pub async fn parse_now(&self, path: &Path) -> Result<Option<Tree>> {
        // Snapshot file
        let (abs, rope, old_tree, version) = self.store.snapshot(path).await?;
        let Some((_id, language)) = LanguageManager::language_for_path(&abs) else { return Ok(None); };
        let mut parser = Parser::new();
        parser.set_language(&language).map_err(|e| anyhow::anyhow!("language error: {e:?}"))?;

        // Rope -> String, move into blocking closure
        let text = rope.to_string();
        let new_tree = task::spawn_blocking(move || {
            parser.parse(text.as_bytes(), old_tree.as_ref())
        }).await?;
        if let Some(tree) = new_tree.clone() {
            self.store.update_tree(&abs, tree, version).await?;
        }
        Ok(new_tree)
    }
}
