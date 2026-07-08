//! End-to-end tests for the cross-file rule class — including THE scenario
//! the whole diff-based-scanning design exists to keep correct: a change in
//! file A introduces a new finding in an otherwise untouched file B, and the
//! whole-tree snapshot diff surfaces it (where any diff-local scan would
//! stay silent).

#![cfg(feature = "bundled-objectscript")]

mod common;
use common::{crit, git, parse_findings, rules_dir, tempdir};
use std::path::Path;

const RULE_ID: &str = "os-crossfile-global-xecute";

/// File B: executes whatever is stored in ^TASKS("cmd"). Vulnerable only if
/// somebody, somewhere, writes that global.
const SINK: &str = "\
Runner ; file B
 xecute ^TASKS(\"cmd\")
 quit
";

/// File A, before: no global write.
const WRITER_CLEAN: &str = "\
Writer ; file A
 set local = \"nothing interesting\"
 quit
";

/// File A, after: writes the global that B executes.
const WRITER_TAINTED: &str = "\
Writer ; file A
 set local = \"nothing interesting\"
 set ^TASKS(\"cmd\") = input
 quit
";

fn crossfile_findings(json: &str) -> Vec<serde_json::Value> {
    parse_findings(json)
        .into_iter()
        .filter(|f| f["rule_id"] == RULE_ID)
        .collect()
}

/// The marquee A→B case: the PR touches ONLY file A (adding a global write),
/// yet the new finding surfaces in untouched file B — state `new`, attributed
/// `in_unchanged_file`, gating CI.
#[test]
fn change_in_a_surfaces_new_finding_in_untouched_b() {
    let dir = tempdir("xf-a2b");
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/a.mac"), WRITER_CLEAN).unwrap();
    std::fs::write(repo.join("src/b.mac"), SINK).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "base: B's xecute has no writer anywhere"]);
    let base_sha = git(repo, &["rev-parse", "HEAD"]).trim().to_string();

    // The PR: file A gains the global write. File B is byte-identical.
    std::fs::write(repo.join("src/a.mac"), WRITER_TAINTED).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "PR: A writes ^TASKS(\"cmd\")"]);

    let (stdout, stderr, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff-base", &base_sha,
            "--diff-mode", "new",
            "--format", "json", "--fail-on-new", "--fail-on", "error",
        ],
    );
    let xf = crossfile_findings(&stdout);
    assert_eq!(xf.len(), 1, "exactly one new cross-file finding; stderr: {stderr}");
    let f = &xf[0];
    assert_eq!(f["state"], "new", "{f}");
    assert_eq!(f["file"], "src/b.mac", "the finding lives in untouched B: {f}");
    assert_eq!(
        f["diff_relation"], "in_unchanged_file",
        "the loud A→B attribution: {f}"
    );
    assert!(
        f["message"].as_str().unwrap().contains("source: src/a.mac"),
        "message names the writer: {f}"
    );
    assert_eq!(code, Some(1), "a new error-severity finding gates CI");
}

/// The reverse direction: removing the writer in A fixes B's finding.
#[test]
fn removing_source_in_a_reads_as_fixed_in_b() {
    let dir = tempdir("xf-fix");
    let repo = dir.path();
    git(repo, &["init", "-q", "-b", "main"]);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/a.mac"), WRITER_TAINTED).unwrap();
    std::fs::write(repo.join("src/b.mac"), SINK).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "base: tainted"]);
    let base_sha = git(repo, &["rev-parse", "HEAD"]).trim().to_string();

    std::fs::write(repo.join("src/a.mac"), WRITER_CLEAN).unwrap();
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "PR: remove the writer"]);

    let (stdout, _, code) = crit(
        repo,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--diff-base", &base_sha,
            "--diff-mode", "new", "--diff-mode", "fixed",
            "--format", "json", "--fail-on-new", "--fail-on", "error",
        ],
    );
    let xf = crossfile_findings(&stdout);
    assert_eq!(xf.len(), 1, "{stdout}");
    assert_eq!(xf[0]["state"], "absent", "B's finding is fixed: {}", xf[0]);
    assert_eq!(code, Some(0), "nothing new — the gate passes");
}

/// Cross-file findings must never be served stale from the per-file cache:
/// with B warm in the cache, toggling the source in A must toggle B's
/// finding.
#[test]
fn cross_file_findings_are_never_cached() {
    let dir = tempdir("xf-cache");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.mac"), WRITER_CLEAN).unwrap();
    std::fs::write(root.join("src/b.mac"), SINK).unwrap();

    let scan = || {
        crit(
            root,
            &[
                "scan", "src", "--rules", &rules_dir(),
                "--cache-dir", "cache",
                "--format", "json", "--fail-on", "off", "-v",
            ],
        )
    };

    let (stdout, _, _) = scan();
    assert!(crossfile_findings(&stdout).is_empty(), "no writer yet: {stdout}");

    // Add the writer. B is untouched and will be a cache HIT — the cross-file
    // pass must still see the new source and fire in B.
    std::fs::write(root.join("src/a.mac"), WRITER_TAINTED).unwrap();
    let (stdout, stderr, _) = scan();
    assert!(
        stderr.contains("cache: 1 of 2"),
        "B is served from cache: {stderr}"
    );
    let xf = crossfile_findings(&stdout);
    assert_eq!(xf.len(), 1, "cached B still gains the finding: {stdout}");
    assert_eq!(xf[0]["file"], "src/b.mac");

    // Remove the writer again: everything is warm, the finding must vanish.
    std::fs::write(root.join("src/a.mac"), WRITER_CLEAN).unwrap();
    let (stdout, _, _) = scan();
    assert!(
        crossfile_findings(&stdout).is_empty(),
        "warm cache must not resurrect the cross-file finding: {stdout}"
    );
}

/// Editing only the cross-file rule must not invalidate per-file cache
/// entries (cross-file rules are outside the cache identity), but must still
/// change the cross-file result.
#[test]
fn cross_file_rule_edit_leaves_per_file_cache_warm() {
    let dir = tempdir("xf-ruleedit");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.mac"), WRITER_TAINTED).unwrap();
    std::fs::write(root.join("src/b.mac"), SINK).unwrap();
    // Local copy of the shipped rules so the cross-file rule can be edited.
    let rules = root.join("rules");
    copy_dir(Path::new(&format!("{}/objectscript", rules_dir())), &rules);

    let scan = || {
        crit(
            root,
            &[
                "scan", "src", "--rules", "rules",
                "--cache-dir", "cache",
                "--format", "json", "--fail-on", "off", "-v",
            ],
        )
    };
    scan();
    let (stdout, stderr, _) = scan();
    assert!(stderr.contains("cache: 2 of 2"), "{stderr}");
    assert_eq!(crossfile_findings(&stdout).len(), 1);

    // Edit ONLY the cross-file rule (bump its severity).
    let rule_path = rules.join("crossfile-global-exec.yml");
    let text = std::fs::read_to_string(&rule_path).unwrap();
    std::fs::write(&rule_path, text.replace("severity: error", "severity: warning")).unwrap();

    let (stdout, stderr, _) = scan();
    assert!(
        stderr.contains("cache: 2 of 2"),
        "per-file entries stay warm across a cross-file rule edit: {stderr}"
    );
    let xf = crossfile_findings(&stdout);
    assert_eq!(xf.len(), 1);
    assert_eq!(xf[0]["severity"], "warning", "the edit still takes effect: {stdout}");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}
