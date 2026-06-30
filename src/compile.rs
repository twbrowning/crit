//! Compiler from the structured `pattern:` rule format to a tree-sitter query
//! string. This is the "structured rule format that transpiles to a tree-sitter
//! query" half of the rule system; the other half is raw `.scm`/`query:` text.
//!
//! Supported pattern surface (a useful subset of tree-sitter query power,
//! chosen to keep rules readable):
//!
//! ```yaml
//! pattern:
//!   node: parameter              # required: the node kind to match
//!   capture: match               # optional: capture name (root defaults to "match")
//!   text: { regex: "(?i)pw" }    # optional: constrain this node's source text
//!   children:                    # optional: DIRECT named-child sub-patterns
//!     - node: parameter_name
//!       field: name              # optional: require it under this field
//!       children:
//!         - node: identifier
//!           text: { regex: "..." }
//! ```
//!
//! `children` are *direct* named children — tree-sitter queries have no
//! descendant combinator, so each level of nesting maps to one level of the
//! syntax tree. `text` accepts `regex`, `eq`, `not_regex`, `not_eq`, compiled to
//! the `#match?` / `#eq?` / `#not-match?` / `#not-eq?` tree-sitter predicates.

use serde::Deserialize;

/// A structured pattern node.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    /// The node kind to match (required).
    pub node: String,
    /// When used as a sub-pattern, require it under this field name.
    #[serde(default)]
    pub field: Option<String>,
    /// Constrain the matched node's source text.
    #[serde(default)]
    pub text: Option<TextMatch>,
    /// Capture name. The root pattern defaults to `match` if unset.
    #[serde(default)]
    pub capture: Option<String>,
    /// Direct named-child sub-patterns (in order).
    #[serde(default)]
    pub children: Vec<Pattern>,
}

/// A text constraint on a node, compiled to a tree-sitter text predicate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextMatch {
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub eq: Option<String>,
    #[serde(default)]
    pub not_regex: Option<String>,
    #[serde(default)]
    pub not_eq: Option<String>,
}

/// Compile a structured pattern into a tree-sitter query string. `root_capture`
/// is the capture name used to mark the finding location (default `match`).
pub fn compile(pattern: &Pattern, root_capture: &str) -> Result<String, String> {
    let mut counter = 0usize;
    let mut predicates: Vec<String> = Vec::new();
    let body = compile_node(pattern, Some(root_capture), &mut counter, &mut predicates)?;
    if predicates.is_empty() {
        return Ok(body);
    }
    // Predicates must be grouped with their pattern inside an outer paren,
    // otherwise tree-sitter parses each `(#...)` as a separate (empty) pattern.
    let mut out = String::from("(");
    out.push_str(&body);
    for p in predicates {
        out.push('\n');
        out.push_str(&p);
    }
    out.push(')');
    Ok(out)
}

fn compile_node(
    p: &Pattern,
    root_capture: Option<&str>,
    counter: &mut usize,
    predicates: &mut Vec<String>,
) -> Result<String, String> {
    if p.node.trim().is_empty() {
        return Err("pattern node kind must not be empty".into());
    }

    let mut s = format!("({}", p.node);
    for child in &p.children {
        let child_sexp = compile_node(child, None, counter, predicates)?;
        s.push(' ');
        if let Some(field) = &child.field {
            s.push_str(field);
            s.push_str(": ");
        }
        s.push_str(&child_sexp);
    }
    s.push(')');

    // Decide whether this node needs a capture (for the root, or to anchor a
    // text predicate, or because the rule author named one).
    let capture = match (root_capture, &p.capture, &p.text) {
        (Some(c), _, _) => Some(c.to_string()),
        (None, Some(c), _) => Some(c.clone()),
        (None, None, Some(_)) => {
            *counter += 1;
            Some(format!("_c{counter}"))
        }
        (None, None, None) => None,
    };

    if let Some(cap) = &capture {
        s.push_str(" @");
        s.push_str(cap);
    }

    if let Some(text) = &p.text {
        let cap = capture
            .as_ref()
            .expect("text constraint always assigns a capture");
        emit_text_predicates(cap, text, predicates)?;
    }

    Ok(s)
}

fn emit_text_predicates(
    capture: &str,
    text: &TextMatch,
    predicates: &mut Vec<String>,
) -> Result<(), String> {
    let mut any = false;
    if let Some(re) = &text.regex {
        predicates.push(format!("(#match? @{capture} \"{}\")", escape(re)));
        any = true;
    }
    if let Some(re) = &text.not_regex {
        predicates.push(format!("(#not-match? @{capture} \"{}\")", escape(re)));
        any = true;
    }
    if let Some(lit) = &text.eq {
        predicates.push(format!("(#eq? @{capture} \"{}\")", escape(lit)));
        any = true;
    }
    if let Some(lit) = &text.not_eq {
        predicates.push(format!("(#not-eq? @{capture} \"{}\")", escape(lit)));
        any = true;
    }
    if !any {
        return Err("text constraint must set at least one of regex/eq/not_regex/not_eq".into());
    }
    Ok(())
}

/// Escape a string for inclusion inside a tree-sitter query `"..."` literal.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(yaml: &str) -> Pattern {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn compiles_simple_node() {
        let p = pat("node: command_xecute");
        assert_eq!(compile(&p, "match").unwrap(), "(command_xecute) @match");
    }

    #[test]
    fn compiles_text_predicate_on_root_wrapped() {
        let p = pat("node: system_defined_function\ntext: { regex: \"(?i)\\\\$zf\" }");
        let q = compile(&p, "match").unwrap();
        assert_eq!(
            q,
            "((system_defined_function) @match\n(#match? @match \"(?i)\\\\$zf\"))"
        );
    }

    #[test]
    fn compiles_nested_children_with_field_and_predicates() {
        let p = pat(
            "node: set_argument\n\
             children:\n\
             - node: objectscript_identifier\n  field: name\n  text: { regex: \"(?i)pwd\" }\n\
             - node: string_literal",
        );
        let q = compile(&p, "match").unwrap();
        assert_eq!(
            q,
            "((set_argument name: (objectscript_identifier) @_c1 (string_literal)) @match\n\
             (#match? @_c1 \"(?i)pwd\"))"
        );
    }

    #[test]
    fn empty_node_is_error() {
        let p = pat("node: \"\"");
        assert!(compile(&p, "match").is_err());
    }
}
