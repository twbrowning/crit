//! catseye — a tree-sitter-based, language-agnostic source security scanner.
//!
//! The crate is organised as:
//! * [`bundled`]   — grammars statically compiled into the binary (ObjectScript).
//! * [`language`]  — the language registry (bundled + dynamically loaded).
//! * [`rule`]      — the rule model and loaders (YAML structured + raw `.scm`).
//! * [`compile`]   — the structured-pattern → tree-sitter-query transpiler.
//! * [`engine`]    — the scanner that turns matches into findings.
//! * [`finding`]   — finding/severity types.
//! * [`report`]    — output formats (human, SARIF, JSON).

#[cfg(feature = "bundled-objectscript")]
pub mod bundled;

pub mod compile;
pub mod engine;
pub mod finding;
pub mod language;
pub mod report;
pub mod rule;
