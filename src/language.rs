//! Language registry: resolves a language id or file extension to a
//! `tree_sitter::Language`, sourced either from the grammars statically compiled
//! into this binary (bundled) or from shared libraries loaded at runtime
//! (dynamic). This is what makes the scanner language-agnostic.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::Language;
use tree_sitter_language::LanguageFn;

/// One resolvable language.
pub struct LanguageEntry {
    pub id: String,
    pub extensions: Vec<String>,
    pub description: String,
    /// `true` if compiled into the binary, `false` if dynamically loaded.
    pub bundled: bool,
    language: Language,
    /// Keeps a dynamically-loaded library alive for as long as the language is
    /// usable (the `Language` points into the library's static data).
    _lib: Option<Arc<libloading::Library>>,
}

impl LanguageEntry {
    pub fn language(&self) -> &Language {
        &self.language
    }

    /// The grammar's tree-sitter ABI version. Used as the grammar identity in a
    /// snapshot's `grammar_versions`: a grammar upgrade that changes node kinds
    /// (and therefore can legitimately flag old code) bumps this.
    pub fn grammar_version(&self) -> String {
        self.language.abi_version().to_string()
    }
}

/// Schema for the dynamic-language TOML config (`--languages-config`).
#[derive(Debug, Deserialize)]
struct DynamicConfig {
    #[serde(default, rename = "language")]
    languages: Vec<DynamicLanguage>,
}

#[derive(Debug, Deserialize)]
struct DynamicLanguage {
    /// Canonical id, e.g. `python`.
    id: String,
    /// Path to the compiled grammar (`.so`/`.dylib`/`.dll`).
    library: PathBuf,
    /// Exported entry point. Defaults to `tree_sitter_<id>`.
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Default)]
pub struct LanguageRegistry {
    entries: Vec<LanguageEntry>,
}

impl LanguageRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry pre-populated with every grammar compiled into this build.
    pub fn with_bundled() -> Self {
        let mut reg = Self::new();
        reg.add_bundled();
        reg
    }

    /// Add the bundled grammars (no-op if the feature is disabled).
    pub fn add_bundled(&mut self) {
        #[cfg(feature = "bundled-objectscript")]
        for b in crate::bundled::all() {
            self.entries.push(LanguageEntry {
                id: b.id.to_string(),
                extensions: b.extensions.iter().map(|s| s.to_string()).collect(),
                description: b.description.to_string(),
                bundled: true,
                language: b.language(),
                _lib: None,
            });
        }
    }

    /// Load languages described by a TOML config file and register them.
    pub fn load_dynamic_config(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading languages config {}", path.display()))?;
        let cfg: DynamicConfig = toml::from_str(&text)
            .with_context(|| format!("parsing languages config {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for lang in cfg.languages {
            self.load_dynamic_language(&lang, base)
                .with_context(|| format!("loading dynamic language '{}'", lang.id))?;
        }
        Ok(())
    }

    fn load_dynamic_language(&mut self, lang: &DynamicLanguage, base: &Path) -> Result<()> {
        // Resolve a relative library path against the config file's directory.
        let lib_path = if lang.library.is_absolute() {
            lang.library.clone()
        } else {
            base.join(&lang.library)
        };
        let symbol = lang
            .symbol
            .clone()
            .unwrap_or_else(|| format!("tree_sitter_{}", lang.id));

        // SAFETY: loading arbitrary native code; the user opts in by listing it.
        let library = unsafe { libloading::Library::new(&lib_path) }
            .with_context(|| format!("dlopen {}", lib_path.display()))?;

        let language = unsafe {
            let func: libloading::Symbol<unsafe extern "C" fn() -> *const ()> = library
                .get(symbol.as_bytes())
                .with_context(|| format!("symbol '{symbol}' not found in {}", lib_path.display()))?;
            // Copy out the raw fn pointer before the Symbol borrow ends.
            let raw: unsafe extern "C" fn() -> *const () = *func;
            Language::from(LanguageFn::from_raw(raw))
        };

        self.entries.push(LanguageEntry {
            id: lang.id.clone(),
            extensions: lang.extensions.clone(),
            description: lang
                .description
                .clone()
                .unwrap_or_else(|| format!("dynamically loaded grammar '{}'", lang.id)),
            bundled: false,
            language,
            _lib: Some(Arc::new(library)),
        });
        Ok(())
    }

    pub fn entries(&self) -> &[LanguageEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up a language by its canonical id.
    pub fn by_id(&self, id: &str) -> Option<&LanguageEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Resolve the language for a path by its file extension. Returns an error
    /// if the extension is owned by more than one language (ambiguous).
    pub fn by_path(&self, path: &Path) -> Result<Option<&LanguageEntry>> {
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_ascii_lowercase(),
            None => return Ok(None),
        };
        let mut matches = self
            .entries
            .iter()
            .filter(|e| e.extensions.iter().any(|x| x.eq_ignore_ascii_case(&ext)));
        let first = matches.next();
        if let Some(second) = matches.next() {
            bail!(
                "extension '.{ext}' is claimed by multiple languages ('{}', '{}'); \
                 pass --language to disambiguate",
                first.unwrap().id,
                second.id
            );
        }
        Ok(first)
    }

    /// Resolve a language given an optional explicit id override and a path.
    pub fn resolve<'a>(
        &'a self,
        explicit: Option<&str>,
        path: &Path,
    ) -> Result<Option<&'a LanguageEntry>> {
        if let Some(id) = explicit {
            return Ok(Some(
                self.by_id(id)
                    .ok_or_else(|| anyhow!("unknown language id '{id}'"))?,
            ));
        }
        self.by_path(path)
    }
}
