//! Output formats for scan results.

mod human;
mod sarif;

pub use human::{render_human, render_human_diff};
pub use sarif::render_sarif;

use crate::finding::Finding;
use serde::Serialize;

/// Selectable output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Sarif,
    Json,
    /// The `crit.snapshot/v1` artifact — the complete HEAD finding set, suitable
    /// as the next run's baseline. Always the full set, never a diff subset.
    Snapshot,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" => Ok(Format::Human),
            "sarif" => Ok(Format::Sarif),
            "json" => Ok(Format::Json),
            "snapshot" => Ok(Format::Snapshot),
            other => Err(format!(
                "unknown format '{other}' (expected human|sarif|json|snapshot)"
            )),
        }
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    findings: &'a [Finding],
    files_scanned: usize,
    files_skipped: usize,
}

/// Render findings as plain JSON (machine-readable; not one of the two primary
/// formats but trivially useful for piping).
pub fn render_json(findings: &[Finding], files_scanned: usize, files_skipped: usize) -> String {
    let report = JsonReport {
        findings,
        files_scanned,
        files_skipped,
    };
    serde_json::to_string_pretty(&report).expect("findings serialize to JSON")
}
