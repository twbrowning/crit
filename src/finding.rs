//! Finding and severity types shared across the engine and reporters.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity of a rule / finding, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    // NOTE: variant order defines `Ord`; keep most-severe first.
    Error,
    Warning,
    Info,
    Note,
}

impl Severity {
    /// SARIF `level` string for this severity.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info | Severity::Note => "note",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Note => "note",
        }
    }

    /// Parse a severity from a CLI/threshold string. `off`/`none` map to `None`.
    pub fn parse_threshold(s: &str) -> Option<Option<Severity>> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" | "never" => Some(None),
            "error" => Some(Some(Severity::Error)),
            "warning" | "warn" => Some(Some(Severity::Warning)),
            "info" => Some(Some(Severity::Info)),
            "note" => Some(Some(Severity::Note)),
            _ => None,
        }
    }
}

/// A 1-based source position (as displayed to users and emitted in SARIF).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

/// A single security finding produced by matching a rule against a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub language: String,
    pub file: PathBuf,
    /// 1-based start position.
    pub start: Position,
    /// 1-based end position (exclusive column).
    pub end: Position,
    /// The source line(s) the finding starts on, for display.
    pub snippet: String,
}
