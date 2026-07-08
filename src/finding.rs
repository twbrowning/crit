//! Finding and severity types shared across the engine and reporters.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// A finding's relationship to a baseline snapshot, mirroring SARIF's
/// `result.baselineState` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingState {
    /// Present at HEAD, absent from the baseline: introduced by this change.
    New,
    /// Present in both, and its surrounding context is byte-for-byte the same.
    Unchanged,
    /// Present in both by fingerprint, but the surrounding source was edited.
    Updated,
    /// Present in the baseline, absent at HEAD: fixed / resolved by this change.
    Absent,
}

impl FindingState {
    /// The SARIF 2.1.0 `baselineState` string.
    pub fn sarif_baseline_state(self) -> &'static str {
        match self {
            FindingState::New => "new",
            FindingState::Unchanged => "unchanged",
            FindingState::Updated => "updated",
            FindingState::Absent => "absent",
        }
    }

    /// Is this finding actually present in the code at HEAD? `absent` (fixed)
    /// findings are not, so they never trip an exit-code gate.
    pub fn present_at_head(self) -> bool {
        !matches!(self, FindingState::Absent)
    }
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
    /// Stable, line-number-independent identity (see [`crate::fingerprint`]).
    #[serde(default)]
    pub fingerprint: String,
    /// Hash of the surrounding source window; distinguishes `unchanged` from
    /// `updated` when two findings share a `fingerprint`.
    #[serde(default)]
    pub context_hash: String,
    /// Nth identical `fingerprint` within `(file, rule)`, in the sorted order.
    /// Disambiguates several structurally identical matches in one file.
    #[serde(default)]
    pub occurrence: usize,
    /// Relationship to the baseline, populated only when diffing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<FindingState>,
}

/// Canonicalize a scan's raw findings into the deterministic form the rest of
/// the pipeline relies on:
///
/// 1. **sort** by `(file, start, end, rule)` — the documented, load-bearing
///    ordering that occurrence indexing (and thus fingerprint identity across
///    refs) depends on;
/// 2. **dedup** exact positional duplicates (one rule can match a node via
///    several internal combinations, e.g. multiple concatenation operators);
/// 3. **assign `occurrence`** — the Nth identical `fingerprint`, in that order,
///    so structurally identical matches in one file stay individually
///    addressable.
pub fn finalize(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.start.line.cmp(&b.start.line))
            .then(a.start.column.cmp(&b.start.column))
            .then(a.end.line.cmp(&b.end.line))
            .then(a.end.column.cmp(&b.end.column))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.file == b.file
            && a.start.line == b.start.line
            && a.start.column == b.start.column
            && a.end.line == b.end.line
            && a.end.column == b.end.column
    });
    let mut occ: HashMap<String, usize> = HashMap::new();
    for f in findings.iter_mut() {
        let n = occ.entry(f.fingerprint.clone()).or_insert(0);
        f.occurrence = *n;
        *n += 1;
    }
}
