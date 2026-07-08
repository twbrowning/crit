//! crit — a tree-sitter-based, language-agnostic source security scanner.
//!
//! The crate is organised as:
//! * [`bundled`]   — grammars statically compiled into the binary (ObjectScript).
//! * [`language`]  — the language registry (bundled + dynamically loaded).
//! * [`rule`]      — the rule model and loaders (YAML structured + raw `.scm`).
//! * [`compile`]   — the structured-pattern → tree-sitter-query transpiler.
//! * [`engine`]    — the scanner that turns matches into findings.
//! * [`finding`]   — finding/severity types.
//! * [`fingerprint`] — stable, position-independent finding identity.
//! * [`snapshot`]  — the persisted `crit.snapshot/v1` finding-set artifact.
//! * [`diff`]      — differential ("what changed since a baseline") analysis.
//! * [`report`]    — output formats (human, SARIF, JSON).

#[cfg(feature = "bundled-objectscript")]
pub mod bundled;

pub mod compile;
pub mod diff;
pub mod engine;
pub mod finding;
pub mod fingerprint;
pub mod language;
pub mod report;
pub mod rule;
pub mod snapshot;
