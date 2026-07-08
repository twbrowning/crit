//! The scanning engine: parse a file, run every applicable rule's query, and
//! turn matches into [`Finding`]s.

use crate::finding::{Finding, Position};
use crate::fingerprint;
use crate::language::LanguageRegistry;
use crate::rule::Rule;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor};

/// A rule whose query has been compiled for one specific language.
struct CompiledRule {
    rule_idx: usize,
    query: Query,
    /// Index of the capture marking the finding, if that capture name exists.
    match_capture_ix: Option<u32>,
}

/// Number of full source lines on each side of a match folded into its
/// `context_hash`.
const CONTEXT_LINES: usize = 2;

/// Summary returned by a multi-path scan.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// Language ids that were actually resolved during the scan. Feeds the
    /// snapshot's `grammar_versions` so comparability is judged only against
    /// grammars this scan relied on.
    pub languages_seen: BTreeSet<String>,
}

pub struct Scanner<'a> {
    registry: &'a LanguageRegistry,
    rules: &'a [Rule],
    /// Per-language compiled rule sets, built lazily on first use.
    compiled: RefCell<HashMap<String, std::rc::Rc<Vec<CompiledRule>>>>,
    /// Non-fatal diagnostics (e.g. a rule's query that didn't compile for a
    /// particular language).
    warnings: RefCell<Vec<String>>,
    /// When set, finding paths (and therefore fingerprints) are made relative
    /// to this root. This is what lets a base-tree scan in a temp worktree and
    /// a HEAD scan in the real checkout produce identical identities — and
    /// makes snapshots portable across machines.
    path_root: Option<std::path::PathBuf>,
}

impl<'a> Scanner<'a> {
    pub fn new(registry: &'a LanguageRegistry, rules: &'a [Rule]) -> Self {
        Self {
            registry,
            rules,
            compiled: RefCell::new(HashMap::new()),
            warnings: RefCell::new(Vec::new()),
            path_root: None,
        }
    }

    /// Relativize finding paths against `root` (see the field docs).
    pub fn with_path_root(mut self, root: std::path::PathBuf) -> Self {
        self.path_root = Some(root);
        self
    }

    pub fn take_warnings(&self) -> Vec<String> {
        std::mem::take(&mut self.warnings.borrow_mut())
    }

    /// Compile (once) the rules applicable to a language, skipping rules whose
    /// query is invalid for that grammar.
    fn compiled_for(&self, lang_id: &str) -> std::rc::Rc<Vec<CompiledRule>> {
        if let Some(c) = self.compiled.borrow().get(lang_id) {
            return c.clone();
        }
        let entry = self
            .registry
            .by_id(lang_id)
            .expect("language must be registered before scanning");
        let language = entry.language();
        let mut items = Vec::new();
        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !rule.applies_to(lang_id) {
                continue;
            }
            let source = match rule.query_source() {
                Ok(s) => s,
                Err(e) => {
                    self.warnings
                        .borrow_mut()
                        .push(format!("rule '{}': {e}", rule.id));
                    continue;
                }
            };
            match Query::new(language, &source) {
                Ok(query) => {
                    let match_capture_ix = query.capture_index_for_name(&rule.match_capture);
                    items.push(CompiledRule {
                        rule_idx,
                        query,
                        match_capture_ix,
                    });
                }
                Err(e) => {
                    // Most commonly: a node kind in the query doesn't exist in
                    // this grammar variant. Skip rather than abort the scan.
                    self.warnings.borrow_mut().push(format!(
                        "rule '{}' does not compile for language '{lang_id}': {e}",
                        rule.id
                    ));
                }
            }
        }
        let rc = std::rc::Rc::new(items);
        self.compiled
            .borrow_mut()
            .insert(lang_id.to_string(), rc.clone());
        rc
    }

    /// Scan a single file. Returns an empty vec (and bumps `files_skipped`) if
    /// no language can be resolved for it.
    pub fn scan_file(
        &self,
        path: &Path,
        explicit_language: Option<&str>,
        report: &mut ScanReport,
    ) -> Result<()> {
        let entry = match self.registry.resolve(explicit_language, path)? {
            Some(e) => e,
            None => {
                report.files_skipped += 1;
                return Ok(());
            }
        };
        let source = std::fs::read(path)
            .with_context(|| format!("reading source file {}", path.display()))?;

        // The identity path: repo-relative when a root is set, as-given
        // otherwise. Both the `file` field and the fingerprint use it.
        let id_path = self
            .path_root
            .as_deref()
            .and_then(|root| crate::git::relative_to(path, root))
            .unwrap_or_else(|| path.to_path_buf());

        let mut parser = Parser::new();
        parser
            .set_language(entry.language())
            .with_context(|| format!("setting language '{}'", entry.id))?;
        let tree = parser
            .parse(&source, None)
            .with_context(|| format!("parsing {}", path.display()))?;

        let compiled = self.compiled_for(&entry.id);
        let root = tree.root_node();
        let mut cursor = QueryCursor::new();
        let mut buf1: Vec<u8> = Vec::new();
        let mut buf2: Vec<u8> = Vec::new();
        let debug = std::env::var_os("CRIT_DEBUG").is_some();

        for cr in compiled.iter() {
            let rule = &self.rules[cr.rule_idx];
            let mut matches = cursor.matches(&cr.query, root, source.as_slice());
            while let Some(m) = matches.next() {
                // Evaluate #eq?/#match?/#not-* text predicates.
                let mut tp: &[u8] = source.as_slice();
                let sat = m.satisfies_text_predicates(&cr.query, &mut buf1, &mut buf2, &mut tp);
                if debug {
                    let caps: Vec<String> = m
                        .captures
                        .iter()
                        .map(|c| {
                            format!(
                                "{}={:?}",
                                cr.query.capture_names()[c.index as usize],
                                String::from_utf8_lossy(&source[c.node.byte_range()])
                            )
                        })
                        .collect();
                    eprintln!(
                        "[dbg] rule={} sat={} caps=[{}]",
                        rule.id,
                        sat,
                        caps.join(", ")
                    );
                }
                if !sat {
                    continue;
                }
                // Pick the node the finding points at.
                let node = cr
                    .match_capture_ix
                    .and_then(|ix| m.nodes_for_capture_index(ix).next())
                    .or_else(|| m.captures.first().map(|c| c.node));
                let node = match node {
                    Some(n) => n,
                    None => continue,
                };
                let start = node.start_position();
                let end = node.end_position();
                let snippet = source_line(&source, start.row);

                // Stable identity: independent of absolute line numbers so a
                // finding survives edits above it (see `crate::fingerprint`).
                let normalized = fingerprint::normalized_match_text(&source, node);
                let structural =
                    fingerprint::structural_path(node, fingerprint::DEFAULT_ANCESTOR_DEPTH);
                let content_key = fingerprint::content_key(&rule.id, &normalized, &structural);
                let fp = fingerprint::compose(&id_path.to_string_lossy(), &content_key);
                let context_hash = fingerprint::context_hash(&source, node, CONTEXT_LINES);

                report.findings.push(Finding {
                    rule_id: rule.id.clone(),
                    message: rule.message.clone(),
                    severity: rule.severity,
                    language: entry.id.clone(),
                    file: id_path.clone(),
                    start: Position {
                        line: start.row + 1,
                        column: start.column + 1,
                    },
                    end: Position {
                        line: end.row + 1,
                        column: end.column + 1,
                    },
                    snippet,
                    fingerprint: fp,
                    content_key,
                    context_hash,
                    occurrence: 0,
                    state: None,
                    diff_relation: None,
                    new_cause: None,
                });
            }
        }
        report.languages_seen.insert(entry.id.clone());
        report.files_scanned += 1;
        Ok(())
    }
}

/// Extract a single 0-based line of source for display, lossy-decoded.
fn source_line(source: &[u8], row: usize) -> String {
    String::from_utf8_lossy(source)
        .lines()
        .nth(row)
        .unwrap_or("")
        .to_string()
}
