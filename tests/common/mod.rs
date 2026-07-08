//! Scaffolding shared by the integration tests. `mod common;` in each test
//! crate pulls this in; not every test uses every helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repo's shipped example rules.
pub fn rules_dir() -> String {
    format!("{}/rules", env!("CARGO_MANIFEST_DIR"))
}

/// Run the built crit binary in `cwd`; returns (stdout, stderr, exit code).
pub fn crit(cwd: &Path, args: &[&str]) -> (String, String, Option<i32>) {
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

/// Self-cleaning temporary directory (no external crates).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Fresh per-(test, process) temp dir; `tag` keeps parallel tests apart.
pub fn tempdir(tag: &str) -> TempDir {
    let base = std::env::temp_dir().join(format!("crit-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create tempdir");
    TempDir(base)
}

/// Run git in `repo` with identity/signing pinned for hermetic tests;
/// asserts success and returns stdout.
pub fn git(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
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

/// The findings array from a `--format json` report.
pub fn parse_findings(json: &str) -> Vec<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_str(json).expect("valid JSON report");
    doc["findings"].as_array().expect("findings array").clone()
}
