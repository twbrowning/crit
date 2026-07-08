//! End-to-end rule-matching tests: load the shipped example rules, scan the
//! fixtures, and assert the expected findings. Covers both authoring formats
//! (raw `.scm` / `query:` and the structured `pattern:` form) and guards against
//! the predicate-association regression.

#![cfg(feature = "bundled-objectscript")]

use crit::engine::{ScanReport, Scanner};
use crit::finding::{Finding, Severity};
use crit::language::LanguageRegistry;
use crit::rule::{self, Rule};
use std::path::{Path, PathBuf};

fn load_example_rules() -> Vec<Rule> {
    rule::load_paths(&[PathBuf::from("rules")]).expect("load example rules")
}

/// Scan one file with the given rules and return its findings.
fn scan(path: &str, rules: &[Rule]) -> Vec<Finding> {
    let registry = LanguageRegistry::with_bundled();
    let scanner = Scanner::new(&registry, rules);
    let mut report = ScanReport::default();
    scanner
        .scan_file(Path::new(path), None, &mut report)
        .expect("scan file");
    report.findings
}

/// (rule_id, start_line) pairs present in a finding list.
fn ids_and_lines(findings: &[Finding]) -> Vec<(String, usize)> {
    findings
        .iter()
        .map(|f| (f.rule_id.clone(), f.start.line))
        .collect()
}

fn contains(findings: &[Finding], rule_id: &str, line: usize) -> bool {
    findings
        .iter()
        .any(|f| f.rule_id == rule_id && f.start.line == line)
}

#[test]
fn example_rules_load_cleanly() {
    let rules = load_example_rules();
    assert!(rules.len() >= 7, "expected the shipped example rules");
    // Mixed authoring formats are represented.
    assert!(
        rules
            .iter()
            .any(|r| matches!(r.matcher, rule::Matcher::Pattern(_))),
        "expected at least one structured `pattern:` rule"
    );
    assert!(
        rules
            .iter()
            .any(|r| matches!(r.matcher, rule::Matcher::Query(_))),
        "expected at least one raw `query:`/`.scm` rule"
    );
}

#[test]
fn vulnerable_class_is_flagged() {
    let rules = load_example_rules();
    let findings = scan("tests/fixtures/vulnerable/Sample.cls", &rules);

    // Raw-query rules.
    assert!(
        contains(&findings, "os-sql-dynamic-concat", 11),
        "{:?}",
        ids_and_lines(&findings)
    );
    assert!(contains(&findings, "os-sql-tainted-exec", 12));
    assert!(contains(&findings, "os-dynamic-exec-xecute", 14));
    assert!(contains(&findings, "os-command-execution-zf", 15));
    assert!(contains(&findings, "os-hardcoded-credential-set", 10));
    // Structured `pattern:` rule (compiled to a query).
    assert!(contains(&findings, "os-hardcoded-credential-parameter", 4));

    // No false positive: the $ZF line is not SQL concatenation.
    assert!(
        !contains(&findings, "os-sql-dynamic-concat", 15),
        "predicate should keep non-SQL concatenation from matching"
    );
}

#[test]
fn vulnerable_routine_is_flagged() {
    let rules = load_example_rules();
    let findings = scan("tests/fixtures/vulnerable/sample.mac", &rules);

    assert!(contains(&findings, "os-dynamic-exec-xecute", 4));
    assert!(contains(&findings, "os-indirection-review", 7));
    assert!(contains(&findings, "os-command-execution-zf", 9)); // $ZF(-1)
    assert!(contains(&findings, "os-command-execution-zf", 10)); // $ZF(-100)
}

#[test]
fn clean_files_have_no_findings() {
    let rules = load_example_rules();
    for f in [
        "tests/fixtures/clean/Clean.cls",
        "tests/fixtures/clean/clean.mac",
    ] {
        let findings = scan(f, &rules);
        assert!(
            findings.is_empty(),
            "{f} produced findings: {:?}",
            ids_and_lines(&findings)
        );
    }
}

/// Regression: predicates must be evaluated against the *captured node's* text,
/// and `(#...)` predicates must associate with their pattern. A bug in either
/// made `os-sql-dynamic-concat` match the benign `"Hello "_name` concatenation.
#[test]
fn predicates_actually_filter() {
    let rules = load_example_rules();
    let findings = scan("tests/fixtures/clean/Clean.cls", &rules);
    assert!(
        !findings
            .iter()
            .any(|f| f.rule_id == "os-sql-dynamic-concat"),
        "benign string concatenation must not be flagged as dynamic SQL"
    );
}

#[test]
fn severities_are_reported_correctly() {
    let rules = load_example_rules();
    let findings = scan("tests/fixtures/vulnerable/Sample.cls", &rules);
    let zf = findings
        .iter()
        .find(|f| f.rule_id == "os-command-execution-zf")
        .expect("zf finding");
    assert_eq!(zf.severity, Severity::Error);

    let xecute = findings
        .iter()
        .find(|f| f.rule_id == "os-dynamic-exec-xecute")
        .expect("xecute finding");
    assert_eq!(xecute.severity, Severity::Warning);
}

/// A rule whose query references node kinds absent from a grammar variant is
/// skipped (with a warning) rather than aborting the scan.
#[test]
fn rule_invalid_for_variant_is_skipped_not_fatal() {
    let rules = load_example_rules();
    let registry = LanguageRegistry::with_bundled();
    let scanner = Scanner::new(&registry, &rules);
    let mut report = ScanReport::default();
    // Force the `expr` variant, which lacks command_xecute / class_method_call
    // etc.; the `objectscript` rules will fail to compile for it. This must warn
    // rather than error.
    scanner
        .scan_file(
            Path::new("tests/fixtures/vulnerable/Sample.cls"),
            Some("objectscript_expr"),
            &mut report,
        )
        .expect("scan must succeed despite per-variant compile skips");
    assert!(
        !scanner.take_warnings().is_empty(),
        "expected warnings about rules that don't compile for objectscript_expr"
    );
}
