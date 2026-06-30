//! Build script: statically compile the vendored InterSystems ObjectScript
//! tree-sitter grammars (all four variants) when the `bundled-objectscript`
//! feature is enabled.
//!
//! The generated `parser.c` files are enormous (tens of MB each), so every
//! translation unit is compiled at `-O0` with warnings off — optimization level
//! does not affect parser correctness and `-O2` on a 1M-line switch statement is
//! pathologically slow and memory-hungry. Each grammar becomes its own static
//! library; the Rust side links to the exported `tree_sitter_*` symbols.

use std::path::Path;

/// (directory under vendor/objectscript, has_external_scanner)
const OBJECTSCRIPT_VARIANTS: &[(&str, bool)] = &[
    ("expr", false),
    ("core", true),
    ("udl", true),
    ("objectscript_routine", true),
];

fn main() {
    if std::env::var("CARGO_FEATURE_BUNDLED_OBJECTSCRIPT").is_err() {
        // Bundled grammars disabled — nothing to compile. The binary will only
        // be able to load grammars dynamically.
        return;
    }

    let vendor = Path::new("vendor/objectscript");

    for (variant, has_scanner) in OBJECTSCRIPT_VARIANTS {
        let src = vendor.join(variant).join("src");
        let parser_c = src.join("parser.c");
        let scanner_c = src.join("scanner.c");

        let mut build = cc::Build::new();
        build
            .include(&src)
            .opt_level(0)
            .warnings(false)
            .extra_warnings(false)
            // Silence the deluge of unused-parameter/value warnings from
            // generated code without affecting the build outcome.
            .flag_if_supported("-w")
            .file(&parser_c);

        if *has_scanner {
            build.file(&scanner_c);
            println!("cargo:rerun-if-changed={}", scanner_c.display());
        }

        build.compile(&format!("objectscript_{variant}"));

        println!("cargo:rerun-if-changed={}", parser_c.display());
    }

    println!("cargo:rerun-if-changed=vendor/objectscript/common/scanner.h");
    println!("cargo:rerun-if-changed=build.rs");
}
