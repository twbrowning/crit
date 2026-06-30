//! Rule model and loading.
//!
//! A rule supplies its match logic in one of two forms:
//!   * `query:` — a raw tree-sitter query (also how `.scm` rule files work), or
//!   * `pattern:` — the structured format from [`crate::compile`].
//!
//! The capture named `match` (configurable) marks the node a finding points at.

use crate::compile::{self, Pattern};
use crate::finding::Severity;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;
use walkdir::WalkDir;

/// Where a rule's tree-sitter query comes from.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Raw tree-sitter query text (from `query:` or a `.scm` file).
    Query(String),
    /// Structured pattern compiled to a query on demand (per language).
    Pattern(Pattern),
}

/// A loaded, validated rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    /// Language ids/groups this rule applies to. Empty = any language.
    /// A bare group like `objectscript` matches every `objectscript_*` variant.
    pub languages: Vec<String>,
    pub matcher: Matcher,
    /// Capture name marking the finding location.
    pub match_capture: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub cwe: Option<String>,
}

impl Rule {
    /// Does this rule apply to a file parsed with language `lang_id`?
    pub fn applies_to(&self, lang_id: &str) -> bool {
        if self.languages.is_empty() {
            return true;
        }
        self.languages.iter().any(|e| {
            e == "*" || e == lang_id || lang_id.starts_with(&format!("{e}_"))
        })
    }

    /// Produce the tree-sitter query text for this rule.
    pub fn query_source(&self) -> Result<String, String> {
        match &self.matcher {
            Matcher::Query(q) => Ok(q.clone()),
            Matcher::Pattern(p) => compile::compile(p, &self.match_capture),
        }
    }
}

// ---------------------------------------------------------------------------
// YAML deserialization
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    id: String,
    message: String,
    #[serde(default)]
    severity: Option<Severity>,
    #[serde(default)]
    languages: Vec<String>,
    /// Singular convenience alias for a one-language rule.
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    pattern: Option<Pattern>,
    #[serde(default)]
    capture: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    cwe: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleFile {
    Many { rules: Vec<RuleSpec> },
    List(Vec<RuleSpec>),
    One(RuleSpec),
}

impl RuleSpec {
    fn into_rule(self) -> Result<Rule> {
        let mut languages = self.languages;
        if let Some(l) = self.language {
            languages.push(l);
        }
        let matcher = match (self.query, self.pattern) {
            (Some(_), Some(_)) => {
                bail!("rule '{}' sets both `query` and `pattern`; use exactly one", self.id)
            }
            (Some(q), None) => Matcher::Query(q),
            (None, Some(p)) => Matcher::Pattern(p),
            (None, None) => {
                bail!("rule '{}' must set either `query` or `pattern`", self.id)
            }
        };
        Ok(Rule {
            id: self.id,
            message: self.message,
            severity: self.severity.unwrap_or(Severity::Warning),
            languages,
            matcher,
            match_capture: self.capture.unwrap_or_else(|| "match".to_string()),
            name: self.name,
            description: self.description,
            references: self.references,
            cwe: self.cwe,
        })
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load rules from a YAML document (single rule, a list, or `{rules: [...]}`).
pub fn parse_yaml(text: &str) -> Result<Vec<Rule>> {
    let file: RuleFile = serde_yaml::from_str(text).context("parsing YAML rule document")?;
    let specs = match file {
        RuleFile::Many { rules } => rules,
        RuleFile::List(rules) => rules,
        RuleFile::One(rule) => vec![rule],
    };
    specs.into_iter().map(RuleSpec::into_rule).collect()
}

/// Parse a raw `.scm` rule file. The leading `; key: value` comment lines form
/// the metadata header; the remainder is the tree-sitter query.
pub fn parse_scm(text: &str) -> Result<Rule> {
    let mut id = None;
    let mut message = None;
    let mut severity = None;
    let mut languages: Vec<String> = Vec::new();
    let mut capture = None;
    let mut name = None;
    let mut description = None;
    let mut cwe = None;
    let mut references: Vec<String> = Vec::new();

    let mut body_start = 0usize;
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            body_start = i + 1;
            continue;
        }
        // Header lines look like: `; key: value`
        if let Some(rest) = trimmed.strip_prefix(';') {
            if let Some((key, value)) = rest.split_once(':') {
                let key = key.trim().to_ascii_lowercase();
                let value = value.trim().to_string();
                match key.as_str() {
                    "id" => id = Some(value),
                    "message" => message = Some(value),
                    "severity" => {
                        severity = Some(
                            serde_yaml::from_str::<Severity>(&value)
                                .with_context(|| format!("invalid severity '{value}'"))?,
                        )
                    }
                    "language" | "languages" => languages
                        .extend(value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
                    "capture" => capture = Some(value),
                    "name" => name = Some(value),
                    "description" => description = Some(value),
                    "cwe" => cwe = Some(value),
                    "reference" | "references" => references
                        .extend(value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
                    _ => {}
                }
                body_start = i + 1;
                continue;
            }
            // A `;` comment that isn't a header pair — treat as start of body.
        }
        body_start = i;
        break;
    }

    let query = lines[body_start..].join("\n").trim().to_string();
    if query.is_empty() {
        bail!("`.scm` rule has no query body");
    }
    let id = id.context("`.scm` rule is missing an `; id:` header")?;
    Ok(Rule {
        message: message.unwrap_or_else(|| id.clone()),
        id,
        severity: severity.unwrap_or(Severity::Warning),
        languages,
        matcher: Matcher::Query(query),
        match_capture: capture.unwrap_or_else(|| "match".to_string()),
        name,
        description,
        references,
        cwe,
    })
}

/// Load all rules under the given paths. Each path may be a single rule file
/// (`.yml`/`.yaml`/`.scm`) or a directory tree to walk.
pub fn load_paths(paths: &[std::path::PathBuf]) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    load_one(entry.path(), &mut rules)?;
                }
            }
        } else {
            load_one(path, &mut rules)?;
        }
    }
    // Stable order for deterministic output.
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    detect_duplicate_ids(&rules)?;
    Ok(rules)
}

fn load_one(path: &Path, out: &mut Vec<Rule>) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading rule file {}", path.display()))?;
    match ext.as_deref() {
        Some("yml") | Some("yaml") => {
            let loaded = parse_yaml(&text)
                .with_context(|| format!("in rule file {}", path.display()))?;
            out.extend(loaded);
        }
        Some("scm") => {
            let rule = parse_scm(&text)
                .with_context(|| format!("in rule file {}", path.display()))?;
            out.push(rule);
        }
        _ => {} // ignore non-rule files in a directory walk
    }
    Ok(())
}

fn detect_duplicate_ids(rules: &[Rule]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for r in rules {
        if !seen.insert(&r.id) {
            bail!("duplicate rule id '{}'", r.id);
        }
    }
    Ok(())
}
