//! Git integration: base-ref resolution, changed-file/hunk extraction, rename
//! tracking, and base-tree materialization.
//!
//! Everything here shells out to the `git` binary — crit needs no libgit2 and
//! never writes to the repository's history. The one mutating operation is
//! `git worktree add --detach` into a temporary directory (removed afterwards),
//! used to materialize the base tree for `partition`/`rescan-base` and for the
//! "no baseline available: scan the base ref itself" path.
//!
//! Diff/hunk information produced here is an *annotation and performance*
//! signal only ([`DiffSpec`] → `diff_relation`); correctness of "new since
//! BASE" is always the whole-tree finding-set difference.

use crate::snapshot::Vcs;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A discovered git repository.
pub struct GitContext {
    root: PathBuf,
}

impl GitContext {
    /// Discover the repository containing `start` (a file or directory).
    /// Returns `None` when `start` is not inside a git work tree or the `git`
    /// binary is unavailable.
    pub fn discover(start: &Path) -> Option<GitContext> {
        let dir = if start.is_dir() {
            start
        } else {
            start.parent().unwrap_or(Path::new("."))
        };
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let root = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        Some(GitContext { root })
    }

    /// The work-tree root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .context("running git")?;
        if !out.status.success() {
            bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Provenance of the current checkout, for the snapshot `vcs` block.
    pub fn head_vcs(&self) -> Option<Vcs> {
        let commit = self.git(&["rev-parse", "HEAD"]).ok()?.trim().to_string();
        // Detached HEAD has no symbolic ref; record "HEAD" rather than failing.
        let reference = self
            .git(&["symbolic-ref", "-q", "HEAD"])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "HEAD".to_string());
        Some(Vcs {
            system: "git".to_string(),
            commit,
            reference,
        })
    }

    /// Resolve `base` to the merge-base with HEAD (three-dot semantics): the
    /// commit a PR actually diverged from, not wherever the base branch has
    /// moved since.
    pub fn merge_base(&self, base: &str) -> Result<String> {
        Ok(self.git(&["merge-base", base, "HEAD"])?.trim().to_string())
    }

    /// The diff between the merge-base of `base` and HEAD, with rename
    /// detection (`-M`): repo-relative changed files, added-line ranges, and
    /// old→new rename mapping.
    pub fn diff_spec(&self, base: &str) -> Result<DiffSpec> {
        let merge_base = self.merge_base(base)?;
        let text = self.git(&["diff", "-M", "--unified=0", &merge_base, "HEAD"])?;
        parse_unified_diff(&text)
    }

    /// Materialize the tree at `refname` into a detached temporary worktree.
    /// The returned guard removes the worktree on drop.
    pub fn materialize(&self, refname: &str) -> Result<BaseTree> {
        let dest = std::env::temp_dir().join(format!(
            "crit-base-{}-{}",
            std::process::id(),
            refname.replace(['/', '\\', ':'], "_")
        ));
        if dest.exists() {
            std::fs::remove_dir_all(&dest).ok();
        }
        self.git(&[
            "worktree",
            "add",
            "--detach",
            "--force",
            dest.to_str().context("non-UTF-8 temp path")?,
            refname,
        ])
        .with_context(|| format!("materializing base tree at '{refname}'"))?;
        Ok(BaseTree {
            repo_root: self.root.clone(),
            path: dest,
        })
    }
}

/// A materialized base tree (temporary detached worktree), removed on drop.
pub struct BaseTree {
    repo_root: PathBuf,
    path: PathBuf,
}

impl BaseTree {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BaseTree {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .output();
        // Belt and braces if git itself is gone by now.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Diff spec: changed files, added-line ranges, renames
// ---------------------------------------------------------------------------

/// A finding's relationship to the change under review. Reviewer signal only —
/// it annotates, it never filters the max-security set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffRelation {
    /// The finding overlaps a line this change added or modified.
    OnAddedLine,
    /// The finding's file was touched by the change, but not its lines.
    InChangedFileUnchangedLine,
    /// The finding's file was not touched at all — the loud, interesting case
    /// for a *new* finding (a change elsewhere caused it).
    InUnchangedFile,
}

/// Per-file added-line ranges and rename mapping extracted from a unified diff
/// (git or supplied patch). Paths are as they appear in the diff, i.e.
/// repo-relative for git.
#[derive(Debug, Default, Clone)]
pub struct DiffSpec {
    /// new-path → added-line ranges (1-based, inclusive). A changed file with
    /// only deletions still appears, with an empty range list.
    changed: HashMap<String, Vec<(usize, usize)>>,
    /// old repo-relative path → new repo-relative path, for `-M` renames.
    renames: Vec<(String, String)>,
}

impl DiffSpec {
    /// Classify a finding by its (repo-relative) file and 1-based line span.
    pub fn relation(&self, file: &str, start_line: usize, end_line: usize) -> DiffRelation {
        match self.changed.get(&norm(file)) {
            None => DiffRelation::InUnchangedFile,
            Some(ranges) => {
                let hit = ranges
                    .iter()
                    .any(|&(lo, hi)| start_line <= hi && end_line >= lo);
                if hit {
                    DiffRelation::OnAddedLine
                } else {
                    DiffRelation::InChangedFileUnchangedLine
                }
            }
        }
    }

    /// old→new rename pairs, for remapping baseline file paths (and thus
    /// fingerprints) before differencing.
    pub fn renames(&self) -> &[(String, String)] {
        &self.renames
    }

    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }
}

fn norm(path: &str) -> String {
    path.replace('\\', "/")
}

/// Strip the conventional `a/` / `b/` prefix from a unified-diff path.
fn strip_ab(path: &str) -> &str {
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
}

/// Parse a unified diff (as produced by `git diff` or any compliant tool) into
/// a [`DiffSpec`]. Only headers are interpreted: `+++` for the post-image path,
/// `@@ -l,c +l,c @@` for added ranges, and git's `rename from`/`rename to`
/// extended headers.
pub fn parse_unified_diff(text: &str) -> Result<DiffSpec> {
    let mut spec = DiffSpec::default();
    let mut current: Option<String> = None;
    let mut rename_from: Option<String> = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("rename from ") {
            rename_from = Some(norm(rest.trim()));
        } else if let Some(rest) = line.strip_prefix("rename to ") {
            if let Some(from) = rename_from.take() {
                spec.renames.push((from, norm(rest.trim())));
            }
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            let raw = rest.split('\t').next().unwrap_or(rest).trim();
            if raw == "/dev/null" {
                current = None; // deletion: no post-image lines to attribute
            } else {
                let path = norm(strip_ab(raw));
                spec.changed.entry(path.clone()).or_default();
                current = Some(path);
            }
        } else if let Some(rest) = line.strip_prefix("@@") {
            // `@@ -l[,c] +l[,c] @@ ...`
            let Some(file) = &current else { continue };
            let plus = rest
                .split_whitespace()
                .find(|t| t.starts_with('+'))
                .context("malformed hunk header (no '+' segment)")?;
            let body = &plus[1..];
            let (start, count) = match body.split_once(',') {
                Some((s, c)) => (
                    s.parse::<usize>().context("hunk start")?,
                    c.parse::<usize>().context("hunk count")?,
                ),
                None => (body.parse::<usize>().context("hunk start")?, 1),
            };
            if count > 0 {
                spec.changed
                    .get_mut(file)
                    .expect("current file was inserted on '+++'")
                    .push((start, start + count - 1));
            }
        }
    }
    Ok(spec)
}

/// Make `path` relative to `root` for cross-scan identity: canonicalizes both
/// sides so `./src/x`, absolute paths, and symlinked roots all normalize the
/// same way. Returns `None` when `path` lies outside `root`.
pub fn relative_to(path: &Path, root: &Path) -> Option<PathBuf> {
    let canon_path = path.canonicalize().ok()?;
    let canon_root = root.canonicalize().ok()?;
    canon_path
        .strip_prefix(&canon_root)
        .ok()
        .map(|p| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH: &str = "\
diff --git a/src/kept.mac b/src/kept.mac
index 111..222 100644
--- a/src/kept.mac
+++ b/src/kept.mac
@@ -3,0 +4,2 @@ Sample
+ set evil = \"x\"
+ xecute evil
@@ -10 +12 @@ Sample
- old line
+ new line
diff --git a/src/old-name.mac b/src/new-name.mac
similarity index 95%
rename from src/old-name.mac
rename to src/new-name.mac
--- a/src/old-name.mac
+++ b/src/new-name.mac
@@ -1 +1 @@
-Old
+New
diff --git a/src/gone.mac b/src/gone.mac
deleted file mode 100644
--- a/src/gone.mac
+++ /dev/null
@@ -1,3 +0,0 @@
-a
-b
-c
";

    #[test]
    fn parses_added_ranges_and_relations() {
        let spec = parse_unified_diff(PATCH).unwrap();
        assert_eq!(spec.relation("src/kept.mac", 4, 5), DiffRelation::OnAddedLine);
        assert_eq!(spec.relation("src/kept.mac", 12, 12), DiffRelation::OnAddedLine);
        assert_eq!(
            spec.relation("src/kept.mac", 7, 7),
            DiffRelation::InChangedFileUnchangedLine
        );
        assert_eq!(
            spec.relation("src/untouched.mac", 1, 1),
            DiffRelation::InUnchangedFile
        );
    }

    #[test]
    fn parses_renames() {
        let spec = parse_unified_diff(PATCH).unwrap();
        assert_eq!(
            spec.renames(),
            &[("src/old-name.mac".to_string(), "src/new-name.mac".to_string())]
        );
    }

    #[test]
    fn deleted_files_do_not_attribute() {
        let spec = parse_unified_diff(PATCH).unwrap();
        // The deletion's post-image is /dev/null; the *old* path was never
        // registered as changed, so findings there read as unchanged-file.
        // (They cannot exist at HEAD anyway — the file is gone.)
        assert_eq!(spec.relation("src/gone.mac", 1, 1), DiffRelation::InUnchangedFile);
    }

    #[test]
    fn multiline_finding_overlapping_range_is_on_added_line() {
        let spec = parse_unified_diff(PATCH).unwrap();
        // Finding spans lines 2-4; added range is 4-5 → overlap.
        assert_eq!(spec.relation("src/kept.mac", 2, 4), DiffRelation::OnAddedLine);
    }
}
