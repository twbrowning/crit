//! Validates that catseye can *consume* the InterSystems ObjectScript
//! tree-sitter grammar — all four bundled variants. For each variant we load the
//! `tree_sitter::Language`, parse a representative snippet, and assert the parse
//! is healthy and contains the node kinds we expect. This is the "consumption of
//! the treesitter" half of the acceptance criteria.

#![cfg(feature = "bundled-objectscript")]

use std::collections::HashSet;
use tree_sitter::{Node, Parser};

/// Collect every named node kind that appears in a tree.
fn node_kinds(node: Node, out: &mut HashSet<String>) {
    out.insert(node.kind().to_string());
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        node_kinds(child, out);
    }
}

struct Case {
    id: &'static str,
    source: &'static str,
    /// Node kinds that must be present for the parse to be considered meaningful.
    expect_kinds: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        id: "objectscript_expr",
        source: "1+2*3_\"end\"",
        expect_kinds: &["binary_operator", "numeric_literal", "string_literal"],
    },
    Case {
        id: "objectscript_core",
        source: " set x = $ZF(-1,\"id\")\n",
        expect_kinds: &["command_set", "system_defined_function"],
    },
    Case {
        id: "objectscript_udl",
        source: "Class Demo.A Extends %RegisteredObject\n{\nParameter K = \"v\";\nClassMethod M()\n{\n set x = 1\n}\n}\n",
        expect_kinds: &["class_definition", "parameter", "classmethod"],
    },
    Case {
        id: "objectscript_routine",
        source: "Tag ; a routine\n set x = 1\n xecute x\n quit\n",
        expect_kinds: &["tag", "command_set", "command_xecute"],
    },
];

/// Every one of the four variants must be present in the bundled set.
#[test]
fn all_four_variants_are_bundled() {
    let ids: HashSet<_> = catseye::bundled::all().into_iter().map(|l| l.id).collect();
    for expected in [
        "objectscript_expr",
        "objectscript_core",
        "objectscript_udl",
        "objectscript_routine",
    ] {
        assert!(ids.contains(expected), "missing bundled variant {expected}");
    }
    assert_eq!(ids.len(), 4, "expected exactly the four ObjectScript variants");
}

#[test]
fn every_variant_loads_and_parses() {
    for case in CASES {
        let lang = catseye::bundled::all()
            .into_iter()
            .find(|l| l.id == case.id)
            .unwrap_or_else(|| panic!("variant {} not bundled", case.id))
            .language();

        // The vendored parsers are ABI 15.
        assert_eq!(lang.abi_version(), 15, "{}: unexpected ABI", case.id);

        let mut parser = Parser::new();
        parser
            .set_language(&lang)
            .unwrap_or_else(|e| panic!("{}: set_language failed: {e}", case.id));

        let tree = parser
            .parse(case.source, None)
            .unwrap_or_else(|| panic!("{}: parse returned None", case.id));
        let root = tree.root_node();

        assert_eq!(root.kind(), "source_file", "{}: unexpected root", case.id);
        assert!(
            !root.has_error(),
            "{}: parse produced ERROR node(s) for source <<{}>>",
            case.id,
            case.source
        );

        let mut kinds = HashSet::new();
        node_kinds(root, &mut kinds);
        for expected in case.expect_kinds {
            assert!(
                kinds.contains(*expected),
                "{}: expected node kind '{}' not found; got {:?}",
                case.id,
                expected,
                kinds
            );
        }
    }
}

/// The same query API catseye uses for rules must work against a bundled grammar.
#[test]
fn queries_run_against_bundled_grammar() {
    use streaming_iterator::StreamingIterator;
    use tree_sitter::{Query, QueryCursor};

    let lang = catseye::bundled::all()
        .into_iter()
        .find(|l| l.id == "objectscript_routine")
        .unwrap()
        .language();
    let src = b"Tag ;\n xecute x\n";
    let mut parser = Parser::new();
    parser.set_language(&lang).unwrap();
    let tree = parser.parse(src.as_slice(), None).unwrap();

    let query = Query::new(&lang, "(command_xecute) @match").unwrap();
    let mut cursor = QueryCursor::new();
    let mut it = cursor.matches(&query, tree.root_node(), src.as_slice());
    let mut count = 0;
    while it.next().is_some() {
        count += 1;
    }
    assert_eq!(count, 1, "expected exactly one XECUTE match");
}
