//! The persisted *snapshot* artifact: the complete, fingerprinted finding set
//! of one scan of one tree, plus the provenance needed to decide whether two
//! snapshots are comparable.
//!
//! One format serves both directions — crit *emits* it as the output of any
//! scan (`--emit-snapshot` / `--format snapshot`) and *consumes* a prior one as
//! the baseline (`--baseline`). crit is agnostic about *where* the snapshot
//! lives and never commits anything itself; "produce" and "consume" are
//! separate primitives, so committed-on-main, CI-cache, and scan-the-base
//! storage strategies all fall out of the same feature.

use crate::finding::{Finding, Position, Severity};
use crate::fingerprint;
use crate::language::LanguageRegistry;
use crate::rule::Rule;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Current snapshot schema id. Emitted into every snapshot and checked on load;
/// an unknown schema is a hard error (defined migration-or-rescan path).
pub const SCHEMA: &str = "crit.snapshot/v1";

/// Version-control provenance for a snapshot. Optional: a snapshot produced
/// without git integration simply omits it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vcs {
    pub system: String,
    pub commit: String,
    /// The symbolic ref, e.g. `refs/heads/main`. `ref` is a Rust keyword, hence
    /// the rename.
    #[serde(rename = "ref")]
    pub reference: String,
}

/// One finding as stored in a snapshot. Positions are retained for display but
/// never participate in identity — that is the whole point of `fingerprint`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: Severity,
    pub language: String,
    pub file: PathBuf,
    pub start: Position,
    pub end: Position,
    pub context_hash: String,
    pub occurrence: usize,
}

impl SnapshotFinding {
    fn from_finding(f: &Finding) -> Self {
        Self {
            fingerprint: f.fingerprint.clone(),
            rule_id: f.rule_id.clone(),
            severity: f.severity,
            language: f.language.clone(),
            file: f.file.clone(),
            start: f.start,
            end: f.end,
            context_hash: f.context_hash.clone(),
            occurrence: f.occurrence,
        }
    }

    /// Rebuild a [`Finding`] from stored data. Used to surface *fixed* findings
    /// (present in BASE, absent at HEAD): there is no source at HEAD to read, so
    /// the snippet is empty and the message is synthesised from the rule id.
    pub fn to_finding(&self) -> Finding {
        Finding {
            rule_id: self.rule_id.clone(),
            message: format!("resolved finding for rule '{}'", self.rule_id),
            severity: self.severity,
            language: self.language.clone(),
            file: self.file.clone(),
            start: self.start,
            end: self.end,
            snippet: String::new(),
            fingerprint: self.fingerprint.clone(),
            context_hash: self.context_hash.clone(),
            occurrence: self.occurrence,
            state: None,
        }
    }
}

/// The snapshot document (`crit.snapshot/v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    pub engine_version: String,
    /// Hash over rule ids + query sources + severities. Doubles as a cache-key
    /// component and as the ruleset-identity used for comparability.
    pub ruleset_id: String,
    pub grammar_versions: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcs: Option<Vcs>,
    pub findings: Vec<SnapshotFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<String>,
}

impl Snapshot {
    /// Build a snapshot from the (already sorted + occurrence-assigned) finding
    /// set of a scan.
    pub fn from_findings(
        findings: &[Finding],
        ruleset_id: String,
        grammar_versions: BTreeMap<String, String>,
        vcs: Option<Vcs>,
    ) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            engine_version: engine_version(),
            ruleset_id,
            grammar_versions,
            vcs,
            findings: findings.iter().map(SnapshotFinding::from_finding).collect(),
            suppressions: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("snapshot serializes to JSON")
    }

    /// Load a snapshot from disk, rejecting an unrecognised schema.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline snapshot {}", path.display()))?;
        let snap: Snapshot = serde_json::from_str(&text)
            .with_context(|| format!("parsing baseline snapshot {}", path.display()))?;
        if snap.schema != SCHEMA {
            anyhow::bail!(
                "baseline snapshot {} has schema '{}', but this build understands '{}'; \
                 re-generate the baseline or upgrade crit",
                path.display(),
                snap.schema,
                SCHEMA
            );
        }
        Ok(snap)
    }

    /// Compare this (baseline) snapshot's identity against the *current* scan's
    /// identity. An empty result means the two are directly comparable; any
    /// entries describe why "new since BASE" might conflate code changes with
    /// ruleset/engine/grammar changes.
    pub fn comparability(
        &self,
        current_ruleset_id: &str,
        current_grammars: &BTreeMap<String, String>,
    ) -> Vec<Mismatch> {
        let mut out = Vec::new();
        if self.ruleset_id != current_ruleset_id {
            out.push(Mismatch::Ruleset {
                base: self.ruleset_id.clone(),
                current: current_ruleset_id.to_string(),
            });
        }
        let current_engine = engine_version();
        if self.engine_version != current_engine {
            out.push(Mismatch::Engine {
                base: self.engine_version.clone(),
                current: current_engine,
            });
        }
        // Only compare grammars the current scan actually relied on; a grammar
        // the baseline recorded but this scan never touched is irrelevant.
        for (lang, cur) in current_grammars {
            match self.grammar_versions.get(lang) {
                Some(base) if base == cur => {}
                Some(base) => out.push(Mismatch::Grammar {
                    language: lang.clone(),
                    base: base.clone(),
                    current: cur.clone(),
                }),
                None => out.push(Mismatch::Grammar {
                    language: lang.clone(),
                    base: "(absent)".to_string(),
                    current: cur.clone(),
                }),
            }
        }
        out
    }
}

/// One reason a baseline is not identity-identical to the current scan.
#[derive(Debug, Clone)]
pub enum Mismatch {
    Ruleset { base: String, current: String },
    Engine { base: String, current: String },
    Grammar {
        language: String,
        base: String,
        current: String,
    },
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mismatch::Ruleset { base, current } => {
                write!(f, "ruleset changed ({base} → {current})")
            }
            Mismatch::Engine { base, current } => {
                write!(f, "engine version changed ({base} → {current})")
            }
            Mismatch::Grammar {
                language,
                base,
                current,
            } => write!(f, "grammar '{language}' changed ({base} → {current})"),
        }
    }
}

/// crit's engine/version string, as recorded in and checked against snapshots.
pub fn engine_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Stable hash over the compiled rule set: each rule's id, severity, and query
/// source. Prefixed `sha256:` and used both as the snapshot `ruleset_id` and as
/// a cache-key component. Rules must be supplied in a deterministic order
/// (crit's loader already sorts them by id).
pub fn ruleset_id(rules: &[Rule]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(rules.len() * 3 + 1);
    parts.push("crit.ruleset/v1".to_string());
    for r in rules {
        parts.push(r.id.clone());
        parts.push(r.severity.as_str().to_string());
        parts.push(r.query_source().unwrap_or_else(|e| format!("<uncompilable:{e}>")));
    }
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    format!("sha256:{}", fingerprint::sha256_parts(&refs))
}

/// The grammar-version map for the languages a scan actually touched.
pub fn grammar_versions(
    registry: &LanguageRegistry,
    languages_seen: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for lang in languages_seen {
        if let Some(entry) = registry.by_id(lang) {
            out.insert(lang.clone(), entry.grammar_version());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fp: &str, occ: usize) -> Finding {
        Finding {
            rule_id: "r".into(),
            message: "m".into(),
            severity: Severity::Error,
            language: "objectscript".into(),
            file: PathBuf::from("a.cls"),
            start: Position { line: 1, column: 1 },
            end: Position { line: 1, column: 2 },
            snippet: "x".into(),
            fingerprint: fp.into(),
            context_hash: "c".into(),
            occurrence: occ,
            state: None,
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let snap = Snapshot::from_findings(
            &[finding("fp1", 0)],
            "sha256:rs".into(),
            BTreeMap::from([("objectscript".to_string(), "14".to_string())]),
            None,
        );
        let json = snap.to_json();
        let back: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].fingerprint, "fp1");
    }

    #[test]
    fn comparability_flags_ruleset_and_grammar() {
        let snap = Snapshot::from_findings(
            &[],
            "sha256:old".into(),
            BTreeMap::from([("objectscript".to_string(), "14".to_string())]),
            None,
        );
        let current = BTreeMap::from([("objectscript".to_string(), "15".to_string())]);
        let mm = snap.comparability("sha256:new", &current);
        assert_eq!(mm.len(), 2); // ruleset + grammar
    }
}
