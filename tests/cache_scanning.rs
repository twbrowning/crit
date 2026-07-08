//! End-to-end tests for the content-addressed findings cache: identical
//! output warm vs cold, correct invalidation on content change, and clean
//! opt-out.

#![cfg(feature = "bundled-objectscript")]

use std::path::{Path, PathBuf};
use std::process::Command;

const VULN: &str = "\
Sample ; routine
 set code = \"set x=1\"
 xecute code
 quit
";

const CLEAN: &str = "\
Sample ; routine
 quit
";

fn rules_dir() -> String {
    format!("{}/rules", env!("CARGO_MANIFEST_DIR"))
}

fn crit(cwd: &Path, args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_crit"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("crit runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

fn scan_json(cwd: &Path) -> (String, String) {
    let (stdout, stderr, _) = crit(
        cwd,
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--cache-dir", "cache",
            "--format", "json", "--fail-on", "off", "-v",
        ],
    );
    (stdout, stderr)
}

fn setup(tag: &str) -> TempDir {
    let dir = tempdir(tag);
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/a.mac"), VULN).unwrap();
    std::fs::write(dir.path().join("src/b.mac"), CLEAN).unwrap();
    std::fs::write(dir.path().join("src/c.mac"), VULN).unwrap();
    dir
}

#[test]
fn warm_run_hits_cache_with_identical_output() {
    let dir = setup("warm");
    let (cold_out, cold_err) = scan_json(dir.path());
    assert!(
        cold_err.contains("cache: 0 of 3"),
        "cold run must miss everywhere: {cold_err}"
    );
    let (warm_out, warm_err) = scan_json(dir.path());
    assert!(
        warm_err.contains("cache: 3 of 3"),
        "warm run must hit everywhere: {warm_err}"
    );
    assert_eq!(cold_out, warm_out, "cached results must be byte-identical");
}

#[test]
fn content_change_invalidates_only_that_file() {
    let dir = setup("invalidate");
    let (_, _) = scan_json(dir.path());

    // b.mac gains the vulnerability; a.mac and c.mac are untouched.
    std::fs::write(dir.path().join("src/b.mac"), VULN).unwrap();
    let (stdout, stderr) = scan_json(dir.path());
    assert!(
        stderr.contains("cache: 2 of 3"),
        "only the changed file re-scans: {stderr}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let files: Vec<&str> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"] == "os-dynamic-exec-xecute")
        .filter_map(|f| f["file"].as_str())
        .collect();
    assert!(files.contains(&"src/b.mac"), "new content is found: {files:?}");
    assert!(files.contains(&"src/a.mac") && files.contains(&"src/c.mac"));
}

#[test]
fn corrupted_cache_entries_degrade_to_misses() {
    let dir = setup("corrupt");
    let (cold_out, _) = scan_json(dir.path());

    // Vandalize every cache entry.
    for entry in walk(dir.path().join("cache")) {
        if entry.extension().map(|e| e == "json").unwrap_or(false) {
            std::fs::write(&entry, "{definitely not json").unwrap();
        }
    }
    let (out, stderr) = scan_json(dir.path());
    assert!(
        stderr.contains("cache: 0 of 3"),
        "corrupt entries must be misses, not errors: {stderr}"
    );
    assert_eq!(cold_out, out, "results are unaffected by cache corruption");
}

#[test]
fn no_cache_disables_everything() {
    let dir = setup("nocache");
    let (_, stderr, code) = crit(
        dir.path(),
        &[
            "scan", "src", "--rules", &rules_dir(),
            "--no-cache", "--format", "json", "--fail-on", "off", "-v",
        ],
    );
    assert_eq!(code, Some(0));
    assert!(!stderr.contains("cache:"), "no cache stats when disabled: {stderr}");
    assert!(!dir.path().join(".crit").exists(), "no default cache dir created");
}

#[test]
fn cache_dir_is_git_self_ignoring() {
    let dir = setup("gitignore");
    scan_json(dir.path());
    let gitignore = dir.path().join("cache/.gitignore");
    assert_eq!(std::fs::read_to_string(gitignore).unwrap().trim(), "*");
}

// --- helpers ---

fn walk(root: PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

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
    let base = std::env::temp_dir().join(format!("crit-cachetest-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create tempdir");
    TempDir(base)
}
