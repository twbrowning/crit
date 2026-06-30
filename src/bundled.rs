//! Statically-compiled (bundled) tree-sitter grammars.
//!
//! Currently this is the four InterSystems ObjectScript variants, compiled by
//! `build.rs` from the vendored sources under `vendor/objectscript/`. The whole
//! module is compiled out when the `bundled-objectscript` feature is disabled,
//! leaving a binary that can only load grammars dynamically.

#![cfg(feature = "bundled-objectscript")]

use tree_sitter::Language;
use tree_sitter_language::LanguageFn;

// The exported C entry points produced by the generated parsers. Each returns
// an opaque `*const TSLanguage`; `LanguageFn` wraps that safely.
extern "C" {
    fn tree_sitter_objectscript_expr() -> *const ();
    fn tree_sitter_objectscript_core() -> *const ();
    fn tree_sitter_objectscript_udl() -> *const ();
    fn tree_sitter_objectscript_routine() -> *const ();
}

/// A bundled grammar: its canonical id, the file extensions it owns, and a
/// human description.
pub struct BundledLanguage {
    pub id: &'static str,
    pub extensions: &'static [&'static str],
    pub description: &'static str,
    language_fn: LanguageFn,
}

impl BundledLanguage {
    /// Materialise the `tree_sitter::Language` for this grammar.
    pub fn language(&self) -> Language {
        self.language_fn.into()
    }
}

/// All grammars compiled into this build, in family order
/// (`expr` → `core` → {`udl`, `routine`}).
pub fn all() -> Vec<BundledLanguage> {
    vec![
        BundledLanguage {
            id: "objectscript_expr",
            extensions: &[],
            description: "InterSystems ObjectScript — expression grammar (family base)",
            language_fn: unsafe { LanguageFn::from_raw(tree_sitter_objectscript_expr) },
        },
        BundledLanguage {
            id: "objectscript_core",
            extensions: &[],
            description: "InterSystems ObjectScript — core statement/line grammar",
            language_fn: unsafe { LanguageFn::from_raw(tree_sitter_objectscript_core) },
        },
        BundledLanguage {
            id: "objectscript_udl",
            extensions: &["cls"],
            description: "InterSystems ObjectScript — Class Definition / UDL (.cls)",
            language_fn: unsafe { LanguageFn::from_raw(tree_sitter_objectscript_udl) },
        },
        BundledLanguage {
            id: "objectscript_routine",
            extensions: &["mac", "int", "inc", "rtn"],
            description: "InterSystems ObjectScript — routine grammar (.mac/.int/.inc/.rtn)",
            language_fn: unsafe { LanguageFn::from_raw(tree_sitter_objectscript_routine) },
        },
    ]
}
