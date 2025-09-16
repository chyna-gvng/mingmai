use std::{path::Path, sync::Arc};

use anyhow::Result;
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
