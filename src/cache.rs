//! Content-addressed cache of per-file findings — the incremental-scan
//! machinery (design use case 2).
//!
//! A *file-local* rule's findings are a pure function of
//! `(identity path, file bytes, compiled ruleset, grammar version, language,
//! engine version)`, so they can be memoized under a key hashing exactly that
//! tuple. Anything that could change the result changes the key, which makes
//! staleness structurally impossible — there is no invalidation logic to get
//! wrong, only misses.
//!
//! Cross-file rules (rule `scope: cross-file`) are **never** cached: their
//! findings depend on other files' contents, so no per-file key can be
//! correct for them. They always run in the whole-tree pass.
//!
//! The cache is an accelerator only: corrupt, unreadable, or unwritable
//! entries degrade to a miss/no-op and can never fail or skew a scan.
//!
//! **Trust boundary:** entries are plain JSON read back as findings, and keys
//! are computable from public inputs — anyone who can write to the cache
//! directory can hide or inject findings. The directory is created
//! owner-only on Unix; do not point `--cache-dir` at a location writable by
//! parties you would not let edit the scan results themselves (e.g. a
//! shared, world-writable CI volume).

use crate::finding::Finding;
use crate::fingerprint;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default cache location, relative to the repo root (or cwd outside a repo).
pub const DEFAULT_DIR: &str = ".crit/cache";

pub struct Cache {
    dir: PathBuf,
    /// Identity of the rule set the cached findings were produced by — for
    /// per-file caching this must cover exactly the rules that run per file
    /// (in phase 4 terms: the file-local subset).
    ruleset_id: String,
    /// Identity of the fingerprint scheme in effect (composition version +
    /// tuning like ancestor depth / context lines); see
    /// [`crate::fingerprint::scheme_id`].
    scheme_id: String,
}

impl Cache {
    /// Open (creating if needed) a cache rooted at `dir`. The directory is
    /// made self-ignoring for git via a `.gitignore` containing `*`, and
    /// owner-only on Unix (see the module's trust-boundary note).
    pub fn open(dir: PathBuf, ruleset_id: String, scheme_id: String) -> std::io::Result<Cache> {
        create_dir_private(&dir)?;
        let ignore = dir.join(".gitignore");
        if !ignore.exists() {
            // Best-effort: a cache that can't self-ignore still works.
            let _ = std::fs::write(&ignore, "*\n");
        }
        Ok(Cache {
            dir,
            ruleset_id,
            scheme_id,
        })
    }

    /// The full opening policy in one place: `no_cache` disables, an explicit
    /// dir wins, otherwise the default location anchored at the repo root or
    /// the scanned tree — and any failure degrades to uncached scanning with
    /// a warning, never to an error (the cache is an accelerator only).
    pub fn open_default(
        no_cache: bool,
        explicit: Option<&Path>,
        repo_root: Option<&Path>,
        scan_anchor: Option<&Path>,
        ruleset_cache_id: String,
        scheme_id: String,
    ) -> Option<Cache> {
        if no_cache {
            return None;
        }
        let dir = resolve_dir(explicit, repo_root, scan_anchor);
        match Cache::open(dir, ruleset_cache_id, scheme_id) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("warning: cannot open findings cache ({e}); continuing without it");
                None
            }
        }
    }

    /// The cache key for one file. Everything the finding set depends on is
    /// hashed in; `identity_path` (not the on-disk path) so a HEAD scan and a
    /// materialized base-tree scan share entries for identical content.
    pub fn key(
        &self,
        identity_path: &str,
        content_hash: &str,
        language: &str,
        grammar_version: &str,
    ) -> String {
        fingerprint::sha256_parts(&[
            "crit.cache/v1",
            env!("CARGO_PKG_VERSION"),
            // The fingerprint scheme in effect (composition version + runtime
            // tuning) participates directly, so a depth change or constant
            // change invalidates entries even without a version bump.
            &self.scheme_id,
            &self.ruleset_id,
            identity_path,
            content_hash,
            language,
            grammar_version,
        ])
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        // Two-level fan-out keeps directories comfortably small.
        self.dir.join(&key[..2]).join(format!("{}.json", &key[2..]))
    }

    /// Look up a file's cached findings. Any read/parse problem is a miss.
    pub fn get(&self, key: &str) -> Option<Vec<Finding>> {
        let text = std::fs::read_to_string(self.entry_path(key)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Store a file's findings. Written atomically (temp file + rename) so a
    /// concurrent or killed scan can never leave a torn entry; failures are
    /// silently ignored (the cache is an accelerator, not a requirement).
    pub fn put(&self, key: &str, findings: &[Finding]) {
        static WRITER: AtomicU64 = AtomicU64::new(0);
        let path = self.entry_path(key);
        let Some(parent) = path.parent() else { return };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(json) = serde_json::to_string(findings) else { return };
        // pid + full key + a process-wide counter: unique even if intra-
        // process parallelism ever writes the same key twice concurrently.
        let tmp = parent.join(format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            WRITER.fetch_add(1, Ordering::Relaxed),
            &key[2..]
        ));
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Owner-only directory creation where the platform supports it.
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Resolve the effective cache directory: an explicit `--cache-dir`, else the
/// default under the repo root; outside a repo, anchored at the scanned tree
/// (never the process cwd, or caches would sprout wherever the user stands).
fn resolve_dir(
    explicit: Option<&Path>,
    repo_root: Option<&Path>,
    scan_anchor: Option<&Path>,
) -> PathBuf {
    if let Some(d) = explicit {
        return d.to_path_buf();
    }
    if let Some(r) = repo_root {
        return r.join(DEFAULT_DIR);
    }
    let anchor = scan_anchor
        .map(|p| if p.is_dir() { p } else { p.parent().unwrap_or(Path::new(".")) })
        .unwrap_or(Path::new("."));
    anchor.join(DEFAULT_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Position, Severity};

    fn finding() -> Finding {
        Finding {
            rule_id: "r".into(),
            message: "m".into(),
            severity: Severity::Error,
            language: "objectscript".into(),
            file: PathBuf::from("a.cls"),
            start: Position { line: 1, column: 1 },
            end: Position { line: 1, column: 2 },
            snippet: "x".into(),
            fingerprint: "fp".into(),
            content_key: "ck".into(),
            context_hash: "ch".into(),
            occurrence: 0,
            state: None,
            diff_relation: None,
            new_cause: None,
        }
    }

    fn temp_cache(tag: &str) -> Cache {
        let dir = std::env::temp_dir().join(format!("crit-cache-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Cache::open(dir, "sha256:rs".into(), "fp/v2:d3:c2".into()).unwrap()
    }

    #[test]
    fn roundtrip_and_atomicity() {
        let cache = temp_cache("rt");
        let key = cache.key("src/a.cls", "abc", "objectscript_udl", "15");
        assert!(cache.get(&key).is_none());
        cache.put(&key, &[finding()]);
        let hit = cache.get(&key).expect("hit after put");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].fingerprint, "fp");
    }

    #[test]
    fn key_varies_with_every_input() {
        let cache = temp_cache("keys");
        let base = cache.key("p", "c", "l", "g");
        assert_ne!(base, cache.key("p2", "c", "l", "g"), "path");
        assert_ne!(base, cache.key("p", "c2", "l", "g"), "content");
        assert_ne!(base, cache.key("p", "c", "l2", "g"), "language");
        assert_ne!(base, cache.key("p", "c", "l", "g2"), "grammar");
        let dir2 =
            std::env::temp_dir().join(format!("crit-cache-test-keys2-{}", std::process::id()));
        let other_rules =
            Cache::open(dir2.clone(), "sha256:other".into(), "fp/v2:d3:c2".into()).unwrap();
        assert_ne!(base, other_rules.key("p", "c", "l", "g"), "ruleset");
        let other_scheme = Cache::open(dir2, "sha256:rs".into(), "fp/v2:d4:c2".into()).unwrap();
        assert_ne!(base, other_scheme.key("p", "c", "l", "g"), "fingerprint scheme");
    }

    #[test]
    fn corrupt_entry_is_a_miss() {
        let cache = temp_cache("corrupt");
        let key = cache.key("p", "c", "l", "g");
        cache.put(&key, &[finding()]);
        std::fs::write(cache.entry_path(&key), "{not json").unwrap();
        assert!(cache.get(&key).is_none(), "corruption must degrade to a miss");
    }

    #[test]
    fn gitignore_is_planted() {
        let cache = temp_cache("ignore");
        let ignore = cache.dir.join(".gitignore");
        assert_eq!(std::fs::read_to_string(ignore).unwrap().trim(), "*");
    }
}
