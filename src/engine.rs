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

/// A cross-file rule's source/sink queries compiled for one language.
struct CompiledCrossRule {
    rule_idx: usize,
    source: Query,
    /// `@link` capture in the source query (join key).
    source_link_ix: u32,
    sink: Query,
    /// `@link` capture in the sink query (join key).
    sink_link_ix: u32,
    /// Capture marking the finding node in the sink query, if present.
    sink_match_ix: Option<u32>,
}

/// The capture name joining a cross-file rule's sources to its sinks.
const LINK_CAPTURE: &str = "link";

use crate::fingerprint::CONTEXT_LINES;

/// Summary returned by a multi-path scan.
#[derive(Debug, Default)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// Of `files_scanned`, how many were served from the findings cache
    /// without re-parsing.
    pub files_cached: usize,
    /// Language ids that were actually resolved during the scan. Feeds the
    /// snapshot's `grammar_versions` so comparability is judged only against
    /// grammars this scan relied on.
    pub languages_seen: BTreeSet<String>,
    /// Every (on-disk path, language id) the scan visited — including cache
    /// hits, which skip parsing. The cross-file pass re-walks exactly this
    /// set: its rules need every file's tree, cached or not.
    pub visited: BTreeSet<(std::path::PathBuf, String)>,
}

pub struct Scanner<'a> {
    registry: &'a LanguageRegistry,
    rules: &'a [Rule],
    /// Per-language compiled rule sets, built lazily on first use.
    compiled: RefCell<HashMap<String, std::rc::Rc<Vec<CompiledRule>>>>,
    /// Per-language compiled cross-file rules, built lazily on first use.
    cross_compiled: RefCell<HashMap<String, std::rc::Rc<Vec<CompiledCrossRule>>>>,
    /// Non-fatal diagnostics (e.g. a rule's query that didn't compile for a
    /// particular language).
    warnings: RefCell<Vec<String>>,
    /// When set, finding paths (and therefore fingerprints) are made relative
    /// to this root. This is what lets a base-tree scan in a temp worktree and
    /// a HEAD scan in the real checkout produce identical identities — and
    /// makes snapshots portable across machines.
    path_root: Option<std::path::PathBuf>,
    /// Content-addressed findings cache. `None` disables caching.
    cache: Option<&'a crate::cache::Cache>,
}

impl<'a> Scanner<'a> {
    pub fn new(registry: &'a LanguageRegistry, rules: &'a [Rule]) -> Self {
        Self {
            registry,
            rules,
            compiled: RefCell::new(HashMap::new()),
            cross_compiled: RefCell::new(HashMap::new()),
            warnings: RefCell::new(Vec::new()),
            path_root: None,
            cache: None,
        }
    }

    /// Relativize finding paths against `root` (see the field docs). The root
    /// is canonicalized once here so the per-file hot path doesn't redo it.
    pub fn with_path_root(mut self, root: std::path::PathBuf) -> Self {
        self.path_root = Some(root.canonicalize().unwrap_or(root));
        self
    }

    /// Serve unchanged files from (and populate) a findings cache.
    pub fn with_cache(mut self, cache: &'a crate::cache::Cache) -> Self {
        self.cache = Some(cache);
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
            // Cross-file rules never run per file (and never hit the cache);
            // they get their own whole-tree pass.
            if rule.is_cross_file() {
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

        let id_path = self.id_path_for(path);

        // Cache lookup: a file-local finding set is a pure function of the
        // hashed key inputs, so a hit skips parse + queries entirely. The
        // per-file bookkeeping below is shared by both paths — only
        // `files_cached` distinguishes them.
        let id_str = fingerprint::identity_path(&id_path);
        let cache_entry = self.cache.map(|c| {
            let content_hash = fingerprint::sha256_hex(&source);
            let key = c.key(&id_str, &content_hash, &entry.id, &entry.grammar_version());
            (c, key)
        });
        let cached = cache_entry.as_ref().and_then(|(c, k)| c.get(k));
        let was_cached = cached.is_some();
        let file_findings = match cached {
            Some(v) => v,
            None => {
                let fresh = self.run_file_queries(path, &source, entry, &id_path, &id_str)?;
                if let Some((c, k)) = &cache_entry {
                    c.put(k, &fresh);
                }
                fresh
            }
        };
        report.findings.extend(file_findings);
        report.languages_seen.insert(entry.id.clone());
        report.visited.insert((path.to_path_buf(), entry.id.clone()));
        report.files_scanned += 1;
        if was_cached {
            report.files_cached += 1;
        }
        Ok(())
    }

    /// The identity path for a scanned file: repo-relative when a root is
    /// set, as-given otherwise. Both the `file` field and the fingerprint
    /// use it.
    fn id_path_for(&self, path: &Path) -> std::path::PathBuf {
        match self.path_root.as_deref() {
            Some(root) => match crate::git::relative_to_canonical(path, root) {
                Some(rel) => rel,
                None => {
                    // A file that escapes the root (symlink target, race)
                    // keeps its as-given path — its identity then cannot
                    // match a base-tree scan's, so say so rather than let a
                    // permanent new+fixed pair appear silently.
                    self.warnings.borrow_mut().push(format!(
                        "{} lies outside the scan root {}; its findings keep a \
                         non-portable path and may not diff cleanly",
                        path.display(),
                        root.display()
                    ));
                    path.to_path_buf()
                }
            },
            None => path.to_path_buf(),
        }
    }

    /// Parse one file and run every applicable compiled rule query over it,
    /// returning the file's finding set (the unit the cache stores).
    fn run_file_queries(
        &self,
        path: &Path,
        source: &[u8],
        entry: &crate::language::LanguageEntry,
        id_path: &Path,
        id_str: &str,
    ) -> Result<Vec<Finding>> {
        let mut parser = Parser::new();
        parser
            .set_language(entry.language())
            .with_context(|| format!("setting language '{}'", entry.id))?;
        let tree = parser
            .parse(source, None)
            .with_context(|| format!("parsing {}", path.display()))?;

        let compiled = self.compiled_for(&entry.id);
        let mut file_findings: Vec<Finding> = Vec::new();
        let root = tree.root_node();
        let mut cursor = QueryCursor::new();
        let mut buf1: Vec<u8> = Vec::new();
        let mut buf2: Vec<u8> = Vec::new();
        let debug = std::env::var_os("CRIT_DEBUG").is_some();

        for cr in compiled.iter() {
            let rule = &self.rules[cr.rule_idx];
            let mut matches = cursor.matches(&cr.query, root, source);
            while let Some(m) = matches.next() {
                // Evaluate #eq?/#match?/#not-* text predicates.
                let mut tp: &[u8] = source;
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
                let snippet = source_line(source, start.row);

                // Stable identity: independent of absolute line numbers so a
                // finding survives edits above it (see `crate::fingerprint`).
                let normalized = fingerprint::normalized_match_text(source, node);
                let structural =
                    fingerprint::structural_path(node, fingerprint::DEFAULT_ANCESTOR_DEPTH);
                let content_key = fingerprint::content_key(&rule.id, &normalized, &structural);
                let fp = fingerprint::compose(id_str, &content_key);
                let context_hash = fingerprint::context_hash(source, node, CONTEXT_LINES);

                file_findings.push(Finding {
                    rule_id: rule.id.clone(),
                    message: rule.message.clone(),
                    severity: rule.severity,
                    language: entry.id.clone(),
                    file: id_path.to_path_buf(),
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
        Ok(file_findings)
    }

    /// Compile (once) the cross-file rules applicable to a language.
    fn cross_compiled_for(&self, lang_id: &str) -> std::rc::Rc<Vec<CompiledCrossRule>> {
        if let Some(c) = self.cross_compiled.borrow().get(lang_id) {
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
            let crate::rule::Matcher::CrossFile { source, sink } = &rule.matcher else {
                continue;
            };
            let compiled = (|| -> Result<CompiledCrossRule, String> {
                let source_q = Query::new(language, source).map_err(|e| format!("source: {e}"))?;
                let sink_q = Query::new(language, sink).map_err(|e| format!("sink: {e}"))?;
                let source_link_ix = source_q
                    .capture_index_for_name(LINK_CAPTURE)
                    .ok_or_else(|| format!("source query has no @{LINK_CAPTURE} capture"))?;
                let sink_link_ix = sink_q
                    .capture_index_for_name(LINK_CAPTURE)
                    .ok_or_else(|| format!("sink query has no @{LINK_CAPTURE} capture"))?;
                let sink_match_ix = sink_q.capture_index_for_name(&rule.match_capture);
                Ok(CompiledCrossRule {
                    rule_idx,
                    source: source_q,
                    source_link_ix,
                    sink: sink_q,
                    sink_link_ix,
                    sink_match_ix,
                })
            })();
            match compiled {
                Ok(c) => items.push(c),
                Err(e) => self.warnings.borrow_mut().push(format!(
                    "cross-file rule '{}' does not compile for language '{lang_id}': {e}",
                    rule.id
                )),
            }
        }
        let rc = std::rc::Rc::new(items);
        self.cross_compiled
            .borrow_mut()
            .insert(lang_id.to_string(), rc.clone());
        rc
    }

    /// The whole-tree pass for cross-file rules: re-walk every visited file
    /// (cache hits included — their trees were never parsed this run),
    /// collect `@link`-keyed sources and sinks per rule, join, and emit a
    /// finding at every sink whose link some source also captures.
    ///
    /// These findings are NEVER cached: they are a function of the whole
    /// tree, so no per-file key can be correct for them. Identity works like
    /// any other finding (fingerprint at the sink), which is what makes the
    /// A→B diff story work: adding a source in file A creates a *new*
    /// finding in untouched file B, and the whole-tree snapshot diff
    /// surfaces it.
    pub fn cross_file_pass(&self, report: &mut ScanReport) -> Result<()> {
        if !self.rules.iter().any(|r| r.is_cross_file()) {
            return Ok(());
        }

        // (rule_idx, link text) → earliest source location, for the message.
        let mut sources: std::collections::BTreeMap<(usize, String), (String, usize)> =
            std::collections::BTreeMap::new();
        // Sink candidates: finding prototype + its join key.
        let mut sinks: Vec<(usize, String, Finding)> = Vec::new();

        for (path, lang_id) in report.visited.clone() {
            let compiled = self.cross_compiled_for(&lang_id);
            if compiled.is_empty() {
                continue;
            }
            let entry = self
                .registry
                .by_id(&lang_id)
                .expect("visited language must be registered");
            let source_bytes = std::fs::read(&path)
                .with_context(|| format!("reading source file {}", path.display()))?;
            let mut parser = Parser::new();
            parser
                .set_language(entry.language())
                .with_context(|| format!("setting language '{}'", entry.id))?;
            let tree = parser
                .parse(&source_bytes, None)
                .with_context(|| format!("parsing {}", path.display()))?;
            let root = tree.root_node();
            let id_path = self.id_path_for(&path);
            let id_str = fingerprint::identity_path(&id_path);

            let mut cursor = QueryCursor::new();
            let mut buf1: Vec<u8> = Vec::new();
            let mut buf2: Vec<u8> = Vec::new();
            for cr in compiled.iter() {
                let rule = &self.rules[cr.rule_idx];

                // Sources: record each link key's earliest location.
                let mut matches = cursor.matches(&cr.source, root, source_bytes.as_slice());
                while let Some(m) = matches.next() {
                    let mut tp: &[u8] = source_bytes.as_slice();
                    if !m.satisfies_text_predicates(&cr.source, &mut buf1, &mut buf2, &mut tp) {
                        continue;
                    }
                    for node in m.nodes_for_capture_index(cr.source_link_ix) {
                        let link = fingerprint::normalized_match_text(&source_bytes, node);
                        let loc = (id_str.clone(), node.start_position().row + 1);
                        sources
                            .entry((cr.rule_idx, link))
                            .and_modify(|cur| {
                                if loc < *cur {
                                    *cur = loc.clone();
                                }
                            })
                            .or_insert(loc);
                    }
                }

                // Sinks: build finding prototypes keyed by their link text.
                let mut matches = cursor.matches(&cr.sink, root, source_bytes.as_slice());
                while let Some(m) = matches.next() {
                    let mut tp: &[u8] = source_bytes.as_slice();
                    if !m.satisfies_text_predicates(&cr.sink, &mut buf1, &mut buf2, &mut tp) {
                        continue;
                    }
                    let Some(link_node) = m.nodes_for_capture_index(cr.sink_link_ix).next()
                    else {
                        continue;
                    };
                    let link = fingerprint::normalized_match_text(&source_bytes, link_node);
                    let node = cr
                        .sink_match_ix
                        .and_then(|ix| m.nodes_for_capture_index(ix).next())
                        .unwrap_or(link_node);

                    let start = node.start_position();
                    let end = node.end_position();
                    let normalized = fingerprint::normalized_match_text(&source_bytes, node);
                    let structural =
                        fingerprint::structural_path(node, fingerprint::DEFAULT_ANCESTOR_DEPTH);
                    let content_key =
                        fingerprint::content_key(&rule.id, &normalized, &structural);
                    sinks.push((
                        cr.rule_idx,
                        link,
                        Finding {
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
                            snippet: source_line(&source_bytes, start.row),
                            fingerprint: fingerprint::compose(&id_str, &content_key),
                            content_key,
                            context_hash: fingerprint::context_hash(
                                &source_bytes,
                                node,
                                CONTEXT_LINES,
                            ),
                            occurrence: 0,
                            state: None,
                            diff_relation: None,
                            new_cause: None,
                        },
                    ));
                }
            }
        }

        // Join: a sink fires when any source shares its link key. The source
        // location is appended to the message (deterministically: earliest
        // location wins) but never to the identity — a source merely moving
        // must not churn the sink's fingerprint.
        for (rule_idx, link, mut finding) in sinks {
            if let Some((src_file, src_line)) = sources.get(&(rule_idx, link.clone())) {
                finding.message =
                    format!("{} (source: {src_file}:{src_line})", finding.message);
                report.findings.push(finding);
            }
        }
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
