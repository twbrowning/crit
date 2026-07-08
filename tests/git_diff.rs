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

use std::path::{Path, PathBuf};
use std::process::Command;

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

fn rules_dir() -> String {
    format!("{}/rules", env!("CARGO_MANIFEST_DIR"))
}

fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn crit(repo: &Path, args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_crit"))
        .current_dir(repo)
        .args(args)
        .output()
        .expect("crit runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

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

fn parse_findings(json: &str) -> Vec<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_str(json).expect("valid JSON report");
    doc["findings"].as_array().expect("findings array").clone()
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
}

// --- tempdir helper (no external crates) ---

struct TempDir(PathBuf);
impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir(tag: &str) -> TempDir {
    let base = std::env::temp_dir().join(format!("crit-git-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create tempdir");
    TempDir(base)
}
