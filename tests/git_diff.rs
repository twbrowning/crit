//! End-to-end tests for the git-integrated differential flow, driven through
//! the real binary against a real (temporary) git repository:
//!
//! * `--diff-base` with no baseline artifact: crit scans the base ref itself.
//! * rename tracking: a renamed-but-unchanged file's finding stays
//!   `unchanged` instead of decaying into fixed-old + new.
//! * diff attribution: `on_added_line` vs `in_unchanged_file`.
//! * `partition`: a ruleset bump surfaces old-code findings as
//!   `new_cause=ruleset`, separate from code-caused ones, without gating.

#![cfg(feature = "bundled-objectscript")]

mod common;
use common::{crit, git, parse_findings, rules_dir, tempdir, TempDir};

const VULN_XECUTE: &str = "\
Sample ; routine
 set code = \"set x=1\"
 xecute code
 quit
";

const VULN_ZF: &str = "\
Util ; routine
 set rc = $ZF(-1, \"/bin/sh -c whoami\")
 quit
";

/// Build the standard two-commit fixture repo:
/// base  = app.mac (one xecute vuln) + old-name.mac (one $ZF vuln)
/// HEAD  = app.mac gains a second xecute vuln; old-name.mac renamed to
///         util.mac unchanged.
/// Returns (repo dir, base commit SHA).
fn fixture_repo(tag: &str) -> (TempDir, String) {
    let dir = tempdir(tag);
    let repo = dir.path();
    git(repo, &["init", "-q"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/app.mac"), VULN_XECUTE).unwrap();
    std::fs::write(repo.join("src/old-name.mac"), VULN_ZF).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "base"]);
    let base_sha = git(repo, &["rev-parse", "HEAD"]).trim().to_string();

    let head_app = format!("{VULN_XECUTE} set evil = \"do X^Y\"\n xecute evil\n");
    std::fs::write(repo.join("src/app.mac"), head_app).unwrap();
    git(repo, &["mv", "src/old-name.mac", "src/util.mac"]);
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "head"]);
    (dir, base_sha)
}

#[test]
fn diff_base_scans_base_ref_and_isolates_new() {
    let (dir, base_sha) = fixture_repo("scanbase");
    let (stdout, stderr, code) = crit(
        dir.path(),
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff-base", &base_sha,
            "--diff-mode", "new", "--diff-mode", "fixed",
            "--format", "json", "--fail-on", "off",
        ],
    );
    let findings = parse_findings(&stdout);

    let new: Vec<_> = findings.iter().filter(|f| f["state"] == "new").collect();
    assert_eq!(new.len(), 1, "only the added xecute is new; stderr: {stderr}");
    assert_eq!(new[0]["rule_id"], "os-dynamic-exec-xecute");
    assert_eq!(new[0]["file"], "src/app.mac");
    assert_eq!(
        new[0]["diff_relation"], "on_added_line",
        "the new finding sits on lines this change added"
    );

    // Rename tracking: util.mac's $ZF finding must NOT appear as fixed
    // (old path) — the -M remap matched it to the unchanged content.
    assert!(
        !findings.iter().any(|f| f["state"] == "absent"),
        "nothing was fixed; rename must not decay into fixed+new: {findings:?}"
    );
    assert_eq!(code, Some(0));
}

#[test]
fn renamed_unchanged_finding_stays_unchanged() {
    let (dir, base_sha) = fixture_repo("rename");
    let (stdout, _, _) = crit(
        dir.path(),
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff-base", &base_sha,
            "--format", "json", "--fail-on", "off",
        ],
    );
    let findings = parse_findings(&stdout);
    let zf: Vec<_> = findings
        .iter()
        .filter(|f| f["rule_id"] == "os-command-execution-zf")
        .collect();
    assert_eq!(zf.len(), 1, "{findings:?}");
    assert_eq!(zf[0]["file"], "src/util.mac");
    assert_eq!(zf[0]["state"], "unchanged", "rename must preserve identity");
    // A 100%-similarity rename emits no hunks: no *lines* changed, so the
    // finding's content is untouched by the change.
    assert_eq!(zf[0]["diff_relation"], "in_unchanged_file");
}

#[test]
fn diff_subcommand_gates_on_new_only() {
    let (dir, base_sha) = fixture_repo("sugar");
    // The only NEW finding is a warning-severity xecute → error gate passes...
    let (_, _, code) = crit(
        dir.path(),
        &["diff", "src", "--base", &base_sha, "--rules", &rules_dir(), "--fail-on", "error"],
    );
    assert_eq!(code, Some(0), "no new error-severity findings");
    // ...while a warning gate trips on it.
    let (_, _, code) = crit(
        dir.path(),
        &["diff", "src", "--base", &base_sha, "--rules", &rules_dir(), "--fail-on", "warning"],
    );
    assert_eq!(code, Some(1), "the new warning must gate at --fail-on warning");
}

#[test]
fn partition_separates_ruleset_from_code() {
    let (dir, base_sha) = fixture_repo("partition");
    let repo = dir.path();

    // Baseline produced at base with a REDUCED ruleset (only the .scm xecute
    // rule) — as if the org later upgraded to the full ruleset.
    let old_rules = repo.join("old-rules");
    std::fs::create_dir_all(&old_rules).unwrap();
    std::fs::copy(
        format!("{}/objectscript/dynamic-exec.scm", rules_dir()),
        old_rules.join("dynamic-exec.scm"),
    )
    .unwrap();
    let base_tree = tempdir("partition-basetree");
    git(repo, &["worktree", "add", "--detach", base_tree.path().to_str().unwrap(), &base_sha]);
    let (_, _, code) = crit(
        base_tree.path(),
        &[
            "scan", "src", "--rules", old_rules.to_str().unwrap(),
            "--format", "snapshot", "-o", repo.join("base.snapshot.json").to_str().unwrap(),
            "--fail-on", "off",
        ],
    );
    assert_eq!(code, Some(0));
    git(repo, &["worktree", "remove", "--force", base_tree.path().to_str().unwrap()]);

    // HEAD scan with the FULL ruleset against the old-ruleset baseline,
    // partitioned via the base source.
    let (stdout, stderr, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--baseline", "base.snapshot.json",
            "--diff-base", &base_sha,
            "--on-baseline-mismatch", "partition",
            "--diff-mode", "new",
            "--format", "json", "--fail-on-new", "--fail-on", "error",
        ],
    );
    assert!(stderr.contains("rescanning base"), "partition engaged: {stderr}");
    let findings = parse_findings(&stdout);

    // The genuinely new xecute: new_cause=code.
    let code_new: Vec<_> = findings.iter().filter(|f| f["new_cause"] == "code").collect();
    assert_eq!(code_new.len(), 1, "{findings:?}");
    assert_eq!(code_new[0]["state"], "new");

    // The $ZF error in (renamed, unchanged) util.mac: the old ruleset never
    // flagged it → new-due-to-ruleset, pre-existing code-wise.
    let ruleset_new: Vec<_> = findings
        .iter()
        .filter(|f| f["new_cause"] == "ruleset")
        .collect();
    assert_eq!(ruleset_new.len(), 1, "{findings:?}");
    assert_eq!(ruleset_new[0]["rule_id"], "os-command-execution-zf");
    assert_ne!(ruleset_new[0]["state"], "new", "pre-existing code must not read as new");

    // Gate: the ruleset-induced ERROR must not fail the new-code gate; the
    // only code-new finding is warning-severity.
    assert_eq!(
        code,
        Some(0),
        "ruleset-induced findings must not trip --fail-on-new; stderr: {stderr}"
    );

    // Same without --fail-on-new: ruleset-induced findings still never gate —
    // that invariant belongs to the partition itself, not to the flag.
    let (_, stderr2, code2) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--baseline", "base.snapshot.json",
            "--diff-base", &base_sha,
            "--on-baseline-mismatch", "partition",
            "--diff-mode", "new",
            "--format", "json", "--fail-on", "error",
        ],
    );
    assert_eq!(
        code2,
        Some(0),
        "ruleset-induced error must not gate even without --fail-on-new; {stderr2}"
    );
}

/// The base branch advancing past the PR's fork point must not leak into the
/// diff: "base" means the merge-base, not the branch tip.
#[test]
fn base_means_merge_base_not_tip() {
    let dir = tempdir("mergebase");
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/app.mac"), VULN_XECUTE).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "A: fork point (has the xecute vuln)"]);
    git(repo, &["branch", "feat"]);

    // main advances: someone FIXES the vuln on main after the fork.
    std::fs::write(repo.join("src/app.mac"), "Sample ; routine\n quit\n").unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "B: fix on main"]);

    // The PR branch (from A) adds an unrelated file; the old vuln is still there.
    git(repo, &["checkout", "-q", "feat"]);
    std::fs::write(repo.join("src/other.mac"), VULN_ZF).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "PR: add other.mac"]);

    let (stdout, stderr, _) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff-base", "main",
            "--format", "json", "--fail-on", "off",
        ],
    );
    let findings = parse_findings(&stdout);
    let new: Vec<_> = findings.iter().filter(|f| f["state"] == "new").collect();
    assert_eq!(new.len(), 1, "only the PR's own $ZF is new; stderr: {stderr}");
    assert_eq!(new[0]["file"], "src/other.mac");

    // The xecute vuln exists at the merge-base AND at HEAD: unchanged. Had the
    // base been main's TIP (where it was fixed), it would read as new.
    let xecute: Vec<_> = findings
        .iter()
        .filter(|f| f["rule_id"] == "os-dynamic-exec-xecute")
        .collect();
    assert_eq!(xecute.len(), 1, "{findings:?}");
    assert_eq!(
        xecute[0]["state"], "unchanged",
        "a fix on main after the fork must not make the PR's pre-existing vuln 'new'"
    );
}

/// `--diff <patch>` alone must engage the diff pipeline (attribution +
/// loud all-new), not silently no-op.
#[test]
fn diff_patch_flag_alone_is_not_a_noop() {
    let (dir, base_sha) = fixture_repo("patchflag");
    let repo = dir.path();
    let patch = git(repo, &["diff", "-M", "--unified=0", &base_sha, "HEAD"]);
    std::fs::write(repo.join("pr.patch"), patch).unwrap();

    let (stdout, stderr, _) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff", "pr.patch",
            "--format", "json", "--fail-on", "off",
        ],
    );
    assert!(
        stderr.contains("treating every finding as new"),
        "no baseline: must be loudly all-new, not silent: {stderr}"
    );
    let findings = parse_findings(&stdout);
    assert!(!findings.is_empty());
    let attributed = findings.iter().filter(|f| f["diff_relation"].is_string()).count();
    assert_eq!(
        attributed,
        findings.len(),
        "every finding must carry diff attribution from the patch: {findings:?}"
    );
    // The genuinely added xecute sits on added lines.
    assert!(
        findings
            .iter()
            .any(|f| f["diff_relation"] == "on_added_line"),
        "{findings:?}"
    );
}

/// A pre-content_key (v0.1) baseline is structurally incomparable and must be
/// rejected with the migration hint, not diffed into 100% noise.
#[test]
fn old_scheme_baseline_is_rejected() {
    let (dir, _) = fixture_repo("oldscheme");
    let repo = dir.path();
    let old = serde_json::json!({
        "schema": "crit.snapshot/v1",
        "engine_version": "0.1.0",
        "ruleset_id": "sha256:whatever",
        "grammar_versions": {},
        "findings": [{
            "fingerprint": "aaaa", "rule_id": "r", "severity": "error",
            "language": "objectscript_routine", "file": "src/app.mac",
            "start": {"line": 1, "column": 1}, "end": {"line": 1, "column": 2},
            "context_hash": "cc", "occurrence": 0
        }]
    });
    std::fs::write(repo.join("old.json"), old.to_string()).unwrap();
    let (_, stderr, code) = crit(
        repo,
        &["scan", "src", "--rules", &rules_dir(), "--baseline", "old.json", "--diff-mode", "new"],
    );
    assert_eq!(code, Some(2), "must be a hard error: {stderr}");
    assert!(
        stderr.contains("incompatible fingerprint scheme"),
        "must explain the migration path: {stderr}"
    );
}


/// A fingerprint listed in the baseline's `suppressions` disappears from
/// every report and from the gate, but stays in the emitted snapshot (full
/// set) with the suppression list carried forward.
#[test]
fn baseline_suppressions_hide_and_carry_forward() {
    let (dir, _) = fixture_repo("suppress");
    let repo = dir.path();

    // Produce a HEAD snapshot, then triage one error finding into it.
    let (_, _, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--format", "snapshot", "-o", "base.json", "--fail-on", "off",
        ],
    );
    assert_eq!(code, Some(0));
    let mut snap: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.join("base.json")).unwrap()).unwrap();
    let zf_fp = snap["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == "os-command-execution-zf")
        .expect("zf finding in snapshot")["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    // A second, dead fingerprint (its finding no longer exists) must expire
    // on carry-forward instead of riding every future baseline.
    snap["suppressions"] = serde_json::json!([zf_fp, "deadbeef-stale-fingerprint"]);
    std::fs::write(repo.join("base.json"), snap.to_string()).unwrap();

    // Re-scan against the triaged baseline: the suppressed error must not be
    // reported and must not gate, and the emitted snapshot keeps both the
    // finding (full set) and the suppression list.
    let (stdout, _, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--baseline", "base.json",
            "--emit-snapshot", "next.json",
            "--format", "json", "--fail-on", "error",
        ],
    );
    let findings = parse_findings(&stdout);
    assert!(
        !findings.iter().any(|f| f["fingerprint"] == zf_fp.as_str()),
        "suppressed finding must not be reported: {findings:?}"
    );
    assert_eq!(code, Some(0), "the suppressed error must not gate");

    let next: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.join("next.json")).unwrap()).unwrap();
    assert!(
        next["findings"].as_array().unwrap().iter().any(|f| f["fingerprint"] == zf_fp.as_str()),
        "the emitted snapshot stays complete"
    );
    assert_eq!(
        next["suppressions"],
        serde_json::json!([zf_fp]),
        "live suppression carried forward, dead one expired"
    );
}

/// --fingerprint-depth changes identity: snapshots record it and a mixed-depth
/// diff is flagged as a comparability mismatch instead of silently mis-diffing.
#[test]
fn fingerprint_depth_mismatch_is_flagged() {
    let (dir, _) = fixture_repo("fpdepth");
    let repo = dir.path();
    let (_, _, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--fingerprint-depth", "4",
            "--format", "snapshot", "-o", "d4.json", "--fail-on", "off",
        ],
    );
    assert_eq!(code, Some(0));
    let snap: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo.join("d4.json")).unwrap()).unwrap();
    assert_eq!(snap["fingerprint_depth"], 4);

    let (_, stderr, _) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--baseline", "d4.json", "--diff-mode", "new",
            "--on-baseline-mismatch", "warn",
            "--format", "json", "--fail-on", "off",
        ],
    );
    assert!(
        stderr.contains("fingerprint depth changed (4 → 3)"),
        "depth mismatch must be surfaced: {stderr}"
    );
}
