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

use crate::finding::Finding;
use crate::fingerprint;
use std::path::{Path, PathBuf};

/// Default cache location, relative to the repo root (or cwd outside a repo).
pub const DEFAULT_DIR: &str = ".crit/cache";

pub struct Cache {
    dir: PathBuf,
    /// Identity of the rule set the cached findings were produced by — for
    /// per-file caching this must cover exactly the rules that run per file
    /// (in phase 4 terms: the file-local subset).
    ruleset_id: String,
}

impl Cache {
    /// Open (creating if needed) a cache rooted at `dir`. The directory is
    /// made self-ignoring for git via a `.gitignore` containing `*`.
    pub fn open(dir: PathBuf, ruleset_id: String) -> std::io::Result<Cache> {
        std::fs::create_dir_all(&dir)?;
        let ignore = dir.join(".gitignore");
        if !ignore.exists() {
            // Best-effort: a cache that can't self-ignore still works.
            let _ = std::fs::write(&ignore, "*\n");
        }
        Ok(Cache { dir, ruleset_id })
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
        let path = self.entry_path(key);
        let Some(parent) = path.parent() else { return };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(json) = serde_json::to_string(findings) else { return };
        let tmp = parent.join(format!(".tmp-{}-{}", std::process::id(), &key[2..10]));
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

/// Resolve the effective cache directory: an explicit `--cache-dir`, else the
/// default under the repo root (or cwd when not in a repo).
pub fn resolve_dir(explicit: Option<&Path>, repo_root: Option<&Path>) -> PathBuf {
    match explicit {
        Some(d) => d.to_path_buf(),
        None => repo_root
            .map(|r| r.join(DEFAULT_DIR))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR)),
    }
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
        Cache::open(dir, "sha256:rs".into()).unwrap()
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
        let other_rules = Cache::open(
            std::env::temp_dir().join(format!("crit-cache-test-keys2-{}", std::process::id())),
            "sha256:other".into(),
        )
        .unwrap();
        assert_ne!(base, other_rules.key("p", "c", "l", "g"), "ruleset");
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
