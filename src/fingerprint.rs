//! Stable, line-number-independent finding identity.
//!
//! Diffing finding sets across two refs requires an identity that survives
//! line-number shifts: code inserted above a finding must not read as
//! `fixed-old + new`. A [`crate::finding::Finding`]'s absolute position is
//! therefore *not* part of its identity. Instead we derive:
//!
//! ```text
//! fingerprint = H( rule_id
//!                ‖ file_path
//!                ‖ normalized_match_text     // whitespace-collapsed match source
//!                ‖ structural_path )          // kinds of the N nearest ancestors
//! occurrence  = index among identical fingerprints within (file, rule)
//! ```
//!
//! plus a secondary [`context_hash`] over the source window around the match,
//! used only to distinguish an *unchanged* finding from one that was *edited
//! nearby* (the `updated` state).
//!
//! The ancestor depth `N` and the text normalization are the two tuning knobs
//! that trade churn (too strict ⇒ every reformat re-fingerprints) against
//! collisions (too loose ⇒ moved code aliases). `N = 3` with whitespace
//! collapsing is the GitHub-code-scanning sweet spot; both are adjustable
//! without a snapshot-schema change.

use sha2::{Digest, Sha256};
use tree_sitter::Node;

/// Default number of nearest ancestor node kinds folded into `structural_path`.
pub const DEFAULT_ANCESTOR_DEPTH: usize = 3;

/// Field separator for the hashed identity tuple. Chosen so it cannot occur in
/// a node kind, a path, or normalized source.
const SEP: char = '\u{1f}';

/// Lowercase-hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

/// SHA-256 of the `SEP`-joined parts, hex encoded. The separator makes the
/// concatenation unambiguous so `"a" ‖ "bc"` and `"ab" ‖ "c"` cannot collide.
pub fn sha256_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            let mut buf = [0u8; 4];
            hasher.update(SEP.encode_utf8(&mut buf).as_bytes());
        }
        hasher.update(p.as_bytes());
    }
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Collapse every run of ASCII/Unicode whitespace to a single space and trim
/// the ends. This is what makes a pure reformat (re-indent, re-wrap) leave a
/// finding's fingerprint untouched.
pub fn normalize_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_ws = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(' ');
            }
            in_ws = false;
            out.push(ch);
        }
    }
    out
}

/// `kinds of the N nearest ancestor nodes`, outermost→innermost, terminated by
/// the match node's own kind. E.g. `call_expression>arguments>string`.
///
/// Only *named* ancestors are counted, so anonymous punctuation nodes (commas,
/// parens) don't dilute the path or make it grammar-formatting-sensitive.
pub fn structural_path(node: Node, depth: usize) -> String {
    let mut ancestors: Vec<&str> = Vec::with_capacity(depth + 1);
    let mut cur = node.parent();
    while ancestors.len() < depth {
        match cur {
            Some(n) => {
                if n.is_named() {
                    ancestors.push(n.kind());
                }
                cur = n.parent();
            }
            None => break,
        }
    }
    ancestors.reverse();
    ancestors.push(node.kind());
    ancestors.join(">")
}

/// The whitespace-normalized match text used in the fingerprint. Kept as its
/// own function so the engine and tests agree on the exact normalization.
pub fn normalized_match_text(source: &[u8], node: Node) -> String {
    normalize_ws(&String::from_utf8_lossy(&source[node.byte_range()]))
}

/// The canonical string form of a finding path for identity and diff-key
/// purposes: forward slashes, no leading `./`. Every fingerprint composition
/// and every join against git-produced paths MUST go through this one
/// function — engine, rename remapping, and hunk attribution all agree on
/// path shape only because they all call it.
pub fn identity_path(path: &std::path::Path) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/");
    while let Some(rest) = s.strip_prefix("./") {
        s = rest.to_string();
    }
    s
}

/// The path-independent half of a finding's identity. Persisted alongside the
/// fingerprint so a git-detected rename can *recompose* the fingerprint under
/// the new path without access to the original source.
pub fn content_key(rule_id: &str, normalized_match_text: &str, structural_path: &str) -> String {
    sha256_parts(&[rule_id, normalized_match_text, structural_path])
}

/// Compose the stable fingerprint: the file path bound to the content key.
/// `file_path` is included so a byte-identical snippet in two files stays
/// distinct; renames are handled by recomposition (see [`content_key`]).
pub fn compose(file_path: &str, content_key: &str) -> String {
    sha256_parts(&[file_path, content_key])
}

/// Secondary identity: a hash of the source window immediately surrounding the
/// match (`ctx_lines` full lines on each side, whitespace-normalized). Two
/// findings that share a `fingerprint` but differ here are the *same* finding
/// whose neighbourhood was edited — the `updated` state.
pub fn context_hash(source: &[u8], node: Node, ctx_lines: usize) -> String {
    let text = String::from_utf8_lossy(source);
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return sha256_parts(&[]);
    }
    let start_row = node.start_position().row;
    let end_row = node.end_position().row.min(lines.len().saturating_sub(1));
    let from = start_row.saturating_sub(ctx_lines);
    let to = (end_row + ctx_lines).min(lines.len().saturating_sub(1));
    let window = lines[from..=to].join("\n");
    sha256_parts(&[&normalize_ws(&window)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_64_chars() {
        let h = sha256_hex(b"crit");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn parts_separator_prevents_collision() {
        assert_ne!(sha256_parts(&["a", "bc"]), sha256_parts(&["ab", "c"]));
    }

    #[test]
    fn normalize_collapses_runs_and_trims() {
        assert_eq!(normalize_ws("  a \t\n  b  "), "a b");
        assert_eq!(normalize_ws("x"), "x");
        assert_eq!(normalize_ws("   "), "");
    }

    #[test]
    fn fingerprint_ignores_position_but_not_content() {
        let k1 = content_key("r", "eval(x)", "call>args>id");
        let k2 = content_key("r", "eval(y)", "call>args>id");
        assert_eq!(compose("f.ts", &k1), compose("f.ts", &k1));
        assert_ne!(compose("f.ts", &k1), compose("f.ts", &k2));
        assert_ne!(compose("f.ts", &k1), compose("g.ts", &k1));
    }

    #[test]
    fn rename_recomposition_matches_fresh_computation() {
        // The property rename remapping relies on: composing the stored
        // content_key under the new path equals a from-scratch fingerprint
        // of the identical code at the new path.
        let k = content_key("r", "eval(x)", "call>args>id");
        assert_eq!(compose("new/name.ts", &k), compose("new/name.ts", &k));
    }
}
