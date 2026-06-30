//! Output formats for scan results.

mod human;
mod sarif;

pub use human::render_human;
pub use sarif::render_sarif;

use crate::finding::Finding;
use serde::Serialize;

/// Selectable output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Sarif,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "human" | "text" => Ok(Format::Human),
            "sarif" => Ok(Format::Sarif),
            "json" => Ok(Format::Json),
            other => Err(format!("unknown format '{other}' (expected human|sarif|json)")),
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
