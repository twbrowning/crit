//! End-to-end tests for first-class diff-based scanning: stable fingerprints
//! that survive line-number shifts, snapshot emit/consume round-trips, and the
//! new/unchanged/updated/fixed classification that drives the PR gate.

#![cfg(feature = "bundled-objectscript")]

use crit::diff::{DiffMode, DiffOutcome};
use crit::engine::{ScanReport, Scanner};
use crit::finding::{self, Finding};
use crit::language::LanguageRegistry;
use crit::rule::{self, Rule};
use crit::snapshot::{self, Snapshot};
use std::collections::BTreeMap;
mod common;
use common::tempdir;
use std::path::Path;

fn load_rules() -> Vec<Rule> {
    rule::load_paths(&[std::path::PathBuf::from("rules")]).expect("load example rules")
}

/// Scan a source string written to a temp file, mirroring the CLI pipeline:
/// scan → `finalize` (sort + dedup + occurrence assignment).
fn scan_source(dir: &Path, name: &str, source: &str, rules: &[Rule]) -> Vec<Finding> {
    let path = dir.join(name);
    std::fs::write(&path, source).expect("write source");
    let registry = LanguageRegistry::with_bundled();
    let scanner = Scanner::new(&registry, rules);
    let mut report = ScanReport::default();
    scanner.scan_file(&path, None, &mut report).expect("scan");
    finding::finalize(&mut report.findings);
    report.findings
}

fn snapshot_of(findings: &[Finding]) -> Snapshot {
    Snapshot::from_findings(findings, "sha256:test".into(), BTreeMap::new(), None)
}

const BASE: &str = "\
Sample ; routine
 ; pad a
 ; pad b
 ; pad c
 set code = \"set x=1\"
 xecute code
 quit
";

/// The same finding, but with three comment lines inserted near the top —
/// beyond the finding's context window. Every line number below shifts, yet
/// both the fingerprint *and* the context are unchanged, so it must read as
/// `unchanged`, never `new`.
const SHIFTED: &str = "\
Sample ; routine
 ; inserted banner line 1
 ; inserted banner line 2
 ; inserted banner line 3
 ; pad a
 ; pad b
 ; pad c
 set code = \"set x=1\"
 xecute code
 quit
";

#[test]
fn fingerprint_survives_line_shift() {
    let dir = tempdir("ds-shift");
    let rules = load_rules();
    let base = scan_source(dir.path(), "a.mac", BASE, &rules);
    let shifted = scan_source(dir.path(), "a.mac", SHIFTED, &rules);

    let bx = base
        .iter()
        .find(|f| f.rule_id == "os-dynamic-exec-xecute")
        .expect("base xecute finding");
    let sx = shifted
        .iter()
        .find(|f| f.rule_id == "os-dynamic-exec-xecute")
        .expect("shifted xecute finding");

    assert_ne!(bx.start.line, sx.start.line, "the line number really moved");
    assert_eq!(
        bx.fingerprint, sx.fingerprint,
        "fingerprint must be independent of absolute position"
    );
}

#[test]
fn shifted_finding_reads_as_unchanged_not_new() {
    let dir = tempdir("ds-unchanged");
    let rules = load_rules();
    let base = snapshot_of(&scan_source(dir.path(), "a.mac", BASE, &rules));
    let head = scan_source(dir.path(), "a.mac", SHIFTED, &rules);

    let outcome = DiffOutcome::diff(head, &base);
    let counts = outcome.counts();
    assert_eq!(counts.new, 0, "a mere line shift introduces nothing");
    assert!(counts.unchanged >= 1, "the shifted finding is pre-existing");
    assert!(
        outcome.reported(&[DiffMode::New]).is_empty(),
        "the PR gate reports zero new findings"
    );
}

#[test]
fn genuinely_new_finding_is_reported_new() {
    let dir = tempdir("ds-new");
    let rules = load_rules();
    let base = snapshot_of(&scan_source(dir.path(), "a.mac", BASE, &rules));
    let head_src = format!("{SHIFTED} set evil=\"do X^Y\"\n xecute evil\n");
    let head = scan_source(dir.path(), "a.mac", &head_src, &rules);

    let outcome = DiffOutcome::diff(head, &base);
    let new = outcome.reported(&[DiffMode::New]);
    assert_eq!(new.len(), 1, "exactly one newly introduced finding");
    assert_eq!(new[0].rule_id, "os-dynamic-exec-xecute");
}

#[test]
fn edit_next_to_finding_reads_as_updated() {
    let dir = tempdir("ds-updated");
    let rules = load_rules();
    let base = snapshot_of(&scan_source(dir.path(), "a.mac", BASE, &rules));
    // Change the line immediately above the xecute (inside its context window)
    // without touching the matched code itself.
    let edited = BASE.replace(" set code = \"set x=1\"", " set code = \"set y=2\"");
    let head = scan_source(dir.path(), "a.mac", &edited, &rules);

    let outcome = DiffOutcome::diff(head, &base);
    let counts = outcome.counts();
    assert_eq!(counts.new, 0, "editing nearby introduces nothing new");
    assert_eq!(counts.updated, 1, "the finding's neighbourhood changed");
    assert_eq!(counts.unchanged, 0);
}

#[test]
fn removed_finding_is_reported_fixed() {
    let dir = tempdir("ds-fixed");
    let rules = load_rules();
    let base = snapshot_of(&scan_source(dir.path(), "a.mac", BASE, &rules));
    let head = scan_source(dir.path(), "a.mac", "Sample ; routine\n quit\n", &rules);

    let outcome = DiffOutcome::diff(head, &base);
    let fixed = outcome.reported(&[DiffMode::Fixed]);
    assert!(
        fixed.iter().any(|f| f.rule_id == "os-dynamic-exec-xecute"),
        "the removed xecute must surface as fixed/absent"
    );
    assert_eq!(outcome.counts().new, 0);
}

#[test]
fn snapshot_round_trips_through_disk() {
    let dir = tempdir("ds-roundtrip");
    let rules = load_rules();
    let findings = scan_source(dir.path(), "a.mac", BASE, &rules);
    let snap = snapshot_of(&findings);

    let path = dir.path().join("snap.json");
    std::fs::write(&path, snap.to_json()).unwrap();
    let loaded = Snapshot::load(&path).expect("load snapshot");

    assert_eq!(loaded.findings.len(), findings.len());
    assert_eq!(loaded.findings[0].fingerprint, findings[0].fingerprint);
}

#[test]
fn ruleset_id_changes_with_rules() {
    let rules = load_rules();
    let full = snapshot::ruleset_id(&rules);
    let subset = snapshot::ruleset_id(&rules[..rules.len() - 1]);
    assert_ne!(full, subset, "dropping a rule must change the ruleset id");
    assert!(full.starts_with("sha256:"));
}

