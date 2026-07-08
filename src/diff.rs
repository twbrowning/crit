//! Differential analysis: what changed between a baseline snapshot and the
//! current (HEAD) finding set.
//!
//! Correctness is defined at the level of *findings*, never lines:
//!
//! ```text
//! new(PR) = findings(HEAD) − findings(BASE)   // compared by (fingerprint, occurrence)
//! ```
//!
//! over the *complete* tree at each ref. Diff/line information (a later,
//! git-assisted enhancement) is only a performance and reviewer-attribution
//! signal; it never defines the max-security set.

use crate::finding::{Finding, FindingState, NewCause};
use crate::git::DiffSpec;
use crate::snapshot::Snapshot;
use std::collections::{HashMap, HashSet};

/// What a report should *include*. Repeatable on the CLI; the reported set is
/// the union of the requested modes. `All` is today's behaviour (every finding
/// present at HEAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    /// Everything present at HEAD (new + unchanged + updated). The default.
    All,
    /// Only findings introduced by this change — the PR gate.
    New,
    /// Only findings resolved by this change (present in BASE, absent at HEAD).
    Fixed,
    /// Only findings whose surrounding source was edited but which persist.
    Updated,
}

impl std::str::FromStr for DiffMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "all" => Ok(DiffMode::All),
            "new" => Ok(DiffMode::New),
            "fixed" | "absent" => Ok(DiffMode::Fixed),
            "updated" => Ok(DiffMode::Updated),
            other => Err(format!(
                "unknown diff mode '{other}' (expected all|new|fixed|updated)"
            )),
        }
    }
}

impl DiffMode {
    /// Does `state` fall into this single mode?
    fn admits(self, state: FindingState) -> bool {
        match self {
            DiffMode::All => state.present_at_head(),
            DiffMode::New => state == FindingState::New,
            DiffMode::Fixed => state == FindingState::Absent,
            DiffMode::Updated => state == FindingState::Updated,
        }
    }
}

/// Tally of finding states, for summaries and gating.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub new: usize,
    pub unchanged: usize,
    pub updated: usize,
    pub fixed: usize,
}

/// The complete annotated finding set of a diff: every HEAD finding tagged with
/// its state, plus reconstructed `absent` (fixed) findings from the baseline.
#[derive(Debug, Clone)]
pub struct DiffOutcome {
    /// All findings, each with `state` set, in deterministic order.
    pub annotated: Vec<Finding>,
}

impl DiffOutcome {
    /// Diff a (sorted, occurrence-assigned) HEAD finding set against a baseline.
    pub fn diff(mut head: Vec<Finding>, baseline: &Snapshot) -> Self {
        // (fingerprint, occurrence) is the identity. Within a single snapshot it
        // is unique by construction (occurrence disambiguates equal fingerprints).
        let base: HashMap<(&str, usize), &crate::snapshot::SnapshotFinding> = baseline
            .findings
            .iter()
            .map(|b| ((b.fingerprint.as_str(), b.occurrence), b))
            .collect();

        let mut matched: HashSet<(String, usize)> = HashSet::new();
        for f in &mut head {
            let key = (f.fingerprint.as_str(), f.occurrence);
            match base.get(&key) {
                Some(b) => {
                    matched.insert((f.fingerprint.clone(), f.occurrence));
                    f.state = Some(if b.context_hash == f.context_hash {
                        FindingState::Unchanged
                    } else {
                        FindingState::Updated
                    });
                }
                None => f.state = Some(FindingState::New),
            }
        }

        // Baseline findings never matched at HEAD are fixed/absent.
        for b in &baseline.findings {
            if !matched.contains(&(b.fingerprint.clone(), b.occurrence)) {
                let mut fixed = b.to_finding();
                fixed.state = Some(FindingState::Absent);
                head.push(fixed);
            }
        }

        sort_annotated(&mut head);
        Self { annotated: head }
    }

    /// Treat every HEAD finding as `new`. Used for the "no baseline available"
    /// case so `--diff-mode new` reports loudly rather than silently zero.
    pub fn all_new(mut head: Vec<Finding>) -> Self {
        for f in &mut head {
            f.state = Some(FindingState::New);
        }
        sort_annotated(&mut head);
        Self { annotated: head }
    }

    /// Partitioned diff, for a ruleset/engine mismatch with the base *source*
    /// available: `base_now` is the base tree rescanned with the *current*
    /// ruleset, `base_old` the supplied (old-ruleset) baseline.
    ///
    /// States are computed against `base_now` — the honest code-relative
    /// numbers, so `new` means *new because the code changed*. Findings that
    /// are pre-existing code-wise but absent from `base_old` (i.e. the old
    /// rules didn't flag them) get `new_cause = ruleset`: surfaced by a rules/
    /// engine bump, reported separately, and never tripping the new-code gate.
    pub fn diff_partitioned(head: Vec<Finding>, base_old: &Snapshot, base_now: &Snapshot) -> Self {
        let mut outcome = Self::diff(head, base_now);
        let in_old: HashSet<(&str, usize)> = base_old
            .findings
            .iter()
            .map(|b| (b.fingerprint.as_str(), b.occurrence))
            .collect();
        for f in &mut outcome.annotated {
            match f.state {
                Some(FindingState::New) => f.new_cause = Some(NewCause::Code),
                Some(FindingState::Unchanged) | Some(FindingState::Updated) => {
                    if !in_old.contains(&(f.fingerprint.as_str(), f.occurrence)) {
                        f.new_cause = Some(NewCause::Ruleset);
                    }
                }
                _ => {}
            }
        }
        outcome
    }

    /// Annotate every HEAD-present finding with its relationship to the
    /// change's diff hunks. Reviewer signal only: a *new* finding
    /// `in_unchanged_file` is the loud A→B case. Never filters anything.
    pub fn attribute(&mut self, spec: &DiffSpec) {
        for f in &mut self.annotated {
            if f.state.map(|s| s.present_at_head()).unwrap_or(true) {
                f.diff_relation = Some(spec.relation(
                    &crate::fingerprint::identity_path(&f.file),
                    f.start.line,
                    f.end.line,
                ));
            }
        }
    }

    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for f in &self.annotated {
            match f.state {
                Some(FindingState::New) => c.new += 1,
                Some(FindingState::Unchanged) => c.unchanged += 1,
                Some(FindingState::Updated) => c.updated += 1,
                Some(FindingState::Absent) => c.fixed += 1,
                None => {}
            }
        }
        c
    }

    /// The subset to report, given the requested modes (their union). Under a
    /// partitioned diff, `new` also admits ruleset-induced findings — they are
    /// what the partition exists to surface (separately labelled, not gated).
    pub fn reported(&self, modes: &[DiffMode]) -> Vec<Finding> {
        self.annotated
            .iter()
            .filter(|f| {
                let by_state = f
                    .state
                    .map(|s| modes.iter().any(|m| m.admits(s)))
                    .unwrap_or(true);
                let by_cause = f.new_cause == Some(NewCause::Ruleset)
                    && modes.contains(&DiffMode::New);
                by_state || by_cause
            })
            .cloned()
            .collect()
    }
}

/// Deterministic order for annotated findings: absent findings carry real
/// positions from the baseline, so the same comparator as the live scan applies.
fn sort_annotated(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.start.line.cmp(&b.start.line))
            .then(a.start.column.cmp(&b.start.column))
            .then(a.end.line.cmp(&b.end.line))
            .then(a.end.column.cmp(&b.end.column))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.occurrence.cmp(&b.occurrence))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Position, Severity};
    use crate::snapshot::Snapshot;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn f(fp: &str, ctx: &str, occ: usize) -> Finding {
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
            context_hash: ctx.into(),
            occurrence: occ,
            state: None,
            diff_relation: None,
            new_cause: None,
        }
    }

    fn snap(findings: &[Finding]) -> Snapshot {
        Snapshot::from_findings(findings, "sha256:rs".into(), BTreeMap::new(), None)
    }

    #[test]
    fn classifies_new_unchanged_updated_fixed() {
        let base = snap(&[f("keep", "c0", 0), f("edit", "c0", 0), f("gone", "c0", 0)]);
        let head = vec![f("keep", "c0", 0), f("edit", "c1", 0), f("fresh", "c0", 0)];
        let out = DiffOutcome::diff(head, &base);
        let c = out.counts();
        assert_eq!(c.unchanged, 1, "keep");
        assert_eq!(c.updated, 1, "edit (context changed)");
        assert_eq!(c.new, 1, "fresh");
        assert_eq!(c.fixed, 1, "gone");
    }

    #[test]
    fn reported_new_only_excludes_preexisting_and_fixed() {
        let base = snap(&[f("keep", "c0", 0), f("gone", "c0", 0)]);
        let head = vec![f("keep", "c0", 0), f("fresh", "c0", 0)];
        let out = DiffOutcome::diff(head, &base);
        let rep = out.reported(&[DiffMode::New]);
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].fingerprint, "fresh");
    }

    #[test]
    fn reported_all_includes_head_but_not_fixed() {
        let base = snap(&[f("gone", "c0", 0)]);
        let head = vec![f("keep", "c0", 0)];
        let out = DiffOutcome::diff(head, &base);
        assert_eq!(out.reported(&[DiffMode::All]).len(), 1);
        assert_eq!(out.reported(&[DiffMode::All, DiffMode::Fixed]).len(), 2);
    }

    #[test]
    fn occurrence_disambiguates_identical_fingerprints() {
        // Two identical calls in BASE; one removed at HEAD.
        let base = snap(&[f("dup", "c0", 0), f("dup", "c0", 1)]);
        let head = vec![f("dup", "c0", 0)];
        let out = DiffOutcome::diff(head, &base);
        let c = out.counts();
        assert_eq!(c.unchanged, 1);
        assert_eq!(c.fixed, 1);
    }
}
