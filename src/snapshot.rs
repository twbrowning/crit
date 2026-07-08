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
    /// Path-independent identity half; enables rename remapping. Optional in
    /// old snapshots (empty = remapping unavailable for that finding).
    #[serde(default)]
    pub content_key: String,
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
            content_key: f.content_key.clone(),
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
            content_key: self.content_key.clone(),
            context_hash: self.context_hash.clone(),
            occurrence: self.occurrence,
            state: None,
            diff_relation: None,
            new_cause: None,
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
        // A snapshot from the pre-content_key fingerprint scheme is
        // *structurally* incomparable: no old fingerprint can ever match a
        // new one, so any diff against it is 100% noise (everything new +
        // everything fixed). Refuse loudly — this is the defined
        // migration-or-rescan path — rather than let a degraded `warn` flow
        // fail CI on the entire pre-existing backlog.
        if !snap.findings.is_empty() && snap.findings.iter().all(|f| f.content_key.is_empty()) {
            anyhow::bail!(
                "baseline snapshot {} was produced by crit {} using an \
                 incompatible fingerprint scheme; regenerate it with \
                 --emit-snapshot, or pass --diff-base to derive one by \
                 rescanning the base ref",
                path.display(),
                snap.engine_version,
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

impl Snapshot {
    /// Remap `old → new` file renames (from `git diff -M`) onto this baseline:
    /// each affected finding's path is rewritten and its fingerprint
    /// *recomposed* from the stored `content_key` under the new path, so a
    /// renamed-but-unchanged finding matches its HEAD counterpart instead of
    /// reading as fixed-old + new. Findings from pre-`content_key` snapshots
    /// are left untouched (returned count says how many were remapped).
    pub fn remap_renames(&mut self, renames: &[(String, String)]) -> usize {
        use std::collections::HashMap;
        let map: HashMap<&str, &str> = renames
            .iter()
            .map(|(o, n)| (o.as_str(), n.as_str()))
            .collect();
        let mut remapped = 0;
        for f in &mut self.findings {
            let key = fingerprint::identity_path(&f.file);
            if let Some(new_path) = map.get(key.as_str()) {
                if f.content_key.is_empty() {
                    continue; // old snapshot: cannot recompose safely
                }
                f.file = std::path::PathBuf::from(new_path);
                f.fingerprint = fingerprint::compose(new_path, &f.content_key);
                remapped += 1;
            }
        }
        if remapped > 0 {
            // Recomposition can merge findings from two files under one path
            // (rename onto a deleted file's name), breaking the
            // "(fingerprint, occurrence) unique within a snapshot" invariant
            // that differencing relies on. Renumber occurrences in the same
            // canonical order `finding::finalize` uses; groups that gained no
            // duplicates renumber to their existing values.
            let mut order: Vec<usize> = (0..self.findings.len()).collect();
            order.sort_by(|&a, &b| {
                let (fa, fb) = (&self.findings[a], &self.findings[b]);
                fa.file
                    .cmp(&fb.file)
                    .then(fa.start.line.cmp(&fb.start.line))
                    .then(fa.start.column.cmp(&fb.start.column))
                    .then(fa.end.line.cmp(&fb.end.line))
                    .then(fa.end.column.cmp(&fb.end.column))
                    .then(fa.rule_id.cmp(&fb.rule_id))
            });
            let mut occ: HashMap<String, usize> = HashMap::new();
            for i in order {
                let f = &mut self.findings[i];
                let n = occ.entry(f.fingerprint.clone()).or_insert(0);
                f.occurrence = *n;
                *n += 1;
            }
        }
        remapped
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

/// Stable hash over the rule set's *semantic* identity — everything that
/// determines which findings exist and where they anchor: each rule's id,
/// severity, language scoping, match capture, and query source. Prefixed
/// `sha256:`; this is the snapshot `ruleset_id` used for baseline
/// comparability. Rules must be supplied in a deterministic order (crit's
/// loader already sorts them by id).
pub fn ruleset_id(rules: &[Rule]) -> String {
    let mut parts: Vec<String> = vec!["crit.ruleset/v2".to_string()];
    for r in rules {
        push_semantic_identity(&mut parts, r);
    }
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    format!("sha256:{}", fingerprint::sha256_parts(&refs))
}

/// Stable hash over the rule set's *full behavioral* identity: the semantic
/// identity plus everything copied verbatim into findings (currently the
/// message). This is the cache-key component — a reworded `message:` must
/// miss the cache even though the finding set is unchanged, or warm scans
/// serve stale text.
pub fn ruleset_cache_id(rules: &[Rule]) -> String {
    let mut parts: Vec<String> = vec!["crit.ruleset-cache/v1".to_string()];
    for r in rules {
        push_semantic_identity(&mut parts, r);
        parts.push(r.message.clone());
    }
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    format!("sha256:{}", fingerprint::sha256_parts(&refs))
}

fn push_semantic_identity(parts: &mut Vec<String>, r: &Rule) {
    parts.push(r.id.clone());
    parts.push(r.severity.as_str().to_string());
    parts.push(r.languages.join(","));
    parts.push(r.match_capture.clone());
    parts.push(r.query_source().unwrap_or_else(|e| format!("<uncompilable:{e}>")));
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
            content_key: format!("ck-{fp}"),
            context_hash: "c".into(),
            occurrence: occ,
            state: None,
            diff_relation: None,
            new_cause: None,
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
