//! catseye CLI.

use anyhow::{Context, Result};
use catseye::engine::{ScanReport, Scanner};
use catseye::finding::Severity;
use catseye::language::LanguageRegistry;
use catseye::report::{self, Format};
use catseye::rule::{self, Rule};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// A tree-sitter-based, language-agnostic source security scanner.
#[derive(Parser)]
#[command(name = "catseye", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Path to a TOML config registering dynamically-loaded grammars.
    #[arg(long, global = true, value_name = "FILE")]
    languages_config: Option<PathBuf>,

    /// Ignore the grammars compiled into this binary.
    #[arg(long, global = true)]
    no_bundled: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Scan source files/directories for rule violations.
    Scan(ScanArgs),
    /// List all available languages (bundled + dynamically loaded).
    ListLanguages,
    /// List the rules loaded from the given rule paths.
    ListRules(RulesArgs),
    /// Parse a file and print its tree-sitter s-expression (debugging rules).
    DumpAst(DumpArgs),
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    /// Rule files or directories (`.yml`/`.yaml`/`.scm`). Repeatable.
    #[arg(short, long, value_name = "PATH", default_value = "rules")]
    rules: Vec<PathBuf>,

    /// Force a language id for every input (skip extension detection).
    #[arg(short, long, value_name = "ID")]
    language: Option<String>,

    /// Output format.
    #[arg(short, long, default_value = "human")]
    format: Format,

    /// Write the report here instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Exit non-zero when a finding at or above this severity is present
    /// (error|warning|info|note|off).
    #[arg(long, default_value = "error")]
    fail_on: String,

    /// Print non-fatal warnings (e.g. rules skipped for a grammar) to stderr.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(clap::Args)]
struct RulesArgs {
    /// Rule files or directories.
    #[arg(short, long, value_name = "PATH", default_value = "rules")]
    rules: Vec<PathBuf>,
}

#[derive(clap::Args)]
struct DumpArgs {
    /// File to parse. Reads stdin if omitted.
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    /// Language id (required when reading stdin or for unmapped extensions).
    #[arg(short, long, value_name = "ID")]
    language: Option<String>,
}

fn build_registry(cli: &Cli) -> Result<LanguageRegistry> {
    let mut registry = if cli.no_bundled {
        LanguageRegistry::new()
    } else {
        LanguageRegistry::with_bundled()
    };
    if let Some(cfg) = &cli.languages_config {
        registry.load_dynamic_config(cfg)?;
    }
    Ok(registry)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let registry = build_registry(&cli)?;

    match &cli.command {
        Command::ListLanguages => {
            list_languages(&registry);
            Ok(ExitCode::SUCCESS)
        }
        Command::ListRules(args) => {
            let rules = rule::load_paths(&args.rules)?;
            list_rules(&rules);
            Ok(ExitCode::SUCCESS)
        }
        Command::DumpAst(args) => {
            dump_ast(&registry, args)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan(args) => scan(&registry, args),
    }
}

fn scan(registry: &LanguageRegistry, args: &ScanArgs) -> Result<ExitCode> {
    let fail_on = Severity::parse_threshold(&args.fail_on)
        .with_context(|| format!("invalid --fail-on value '{}'", args.fail_on))?;

    let rules = rule::load_paths(&args.rules)?;
    if rules.is_empty() {
        eprintln!("warning: no rules loaded from {:?}", args.rules);
    }

    let scanner = Scanner::new(registry, &rules);
    let mut report = ScanReport::default();
    for path in &args.paths {
        scan_path(&scanner, path, args.language.as_deref(), &mut report)?;
    }

    if args.verbose {
        for w in scanner.take_warnings() {
            eprintln!("warning: {w}");
        }
    }

    // Sort findings by file, then position, for stable output.
    report.findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.start.line.cmp(&b.start.line))
            .then(a.start.column.cmp(&b.start.column))
            .then(a.end.line.cmp(&b.end.line))
            .then(a.end.column.cmp(&b.end.column))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    // De-duplicate identical findings (the same rule can match a node via
    // several internal combinations, e.g. multiple concatenation operators).
    report.findings.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.file == b.file
            && a.start.line == b.start.line
            && a.start.column == b.start.column
            && a.end.line == b.end.line
            && a.end.column == b.end.column
    });

    let rendered = match args.format {
        Format::Human => {
            report::render_human(&report.findings, report.files_scanned, report.files_skipped)
        }
        Format::Sarif => report::render_sarif(&report.findings, &rules),
        Format::Json => {
            report::render_json(&report.findings, report.files_scanned, report.files_skipped)
        }
    };

    if let Some(out) = &args.output {
        std::fs::write(out, rendered).with_context(|| format!("writing {}", out.display()))?;
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(rendered.as_bytes())?;
    }

    // Decide exit code from the fail-on threshold.
    if let Some(threshold) = fail_on {
        let tripped = report.findings.iter().any(|f| f.severity <= threshold);
        if tripped {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Recurse into directories, scanning each file.
fn scan_path(
    scanner: &Scanner,
    path: &std::path::Path,
    language: Option<&str>,
    report: &mut ScanReport,
) -> Result<()> {
    if path.is_dir() {
        for entry in walkdir::WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                scanner.scan_file(entry.path(), language, report)?;
            }
        }
    } else {
        scanner.scan_file(path, language, report)?;
    }
    Ok(())
}

fn list_languages(registry: &LanguageRegistry) {
    if registry.is_empty() {
        println!("No languages available. (Built with --no-default-features and no --languages-config?)");
        return;
    }
    println!("{:<24} {:<8} {:<22} {}", "ID", "SOURCE", "EXTENSIONS", "DESCRIPTION");
    for e in registry.entries() {
        let exts = if e.extensions.is_empty() {
            "-".to_string()
        } else {
            e.extensions
                .iter()
                .map(|x| format!(".{x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        println!(
            "{:<24} {:<8} {:<22} {}",
            e.id,
            if e.bundled { "bundled" } else { "dynamic" },
            exts,
            e.description
        );
    }
}

fn list_rules(rules: &[Rule]) {
    if rules.is_empty() {
        println!("No rules loaded.");
        return;
    }
    println!("{:<40} {:<9} {:<28} {}", "ID", "SEVERITY", "LANGUAGES", "FORMAT");
    for r in rules {
        let langs = if r.languages.is_empty() {
            "*".to_string()
        } else {
            r.languages.join(",")
        };
        let format = match r.matcher {
            rule::Matcher::Query(_) => "query",
            rule::Matcher::Pattern(_) => "pattern",
        };
        println!(
            "{:<40} {:<9} {:<28} {}",
            r.id,
            r.severity.as_str(),
            langs,
            format
        );
    }
    println!("\n{} rule(s).", rules.len());
}

fn dump_ast(registry: &LanguageRegistry, args: &DumpArgs) -> Result<()> {
    use std::io::Read;
    let (source, path_for_resolve): (Vec<u8>, PathBuf) = match &args.file {
        Some(p) => (
            std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
            p.clone(),
        ),
        None => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            (buf, PathBuf::from("stdin"))
        }
    };

    let entry = registry
        .resolve(args.language.as_deref(), &path_for_resolve)?
        .context("could not determine language; pass --language")?;

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(entry.language())?;
    let tree = parser.parse(&source, None).context("parse failed")?;

    let mut out = String::new();
    write_sexp(tree.root_node(), &source, 0, &mut out);
    print!("{out}");
    if tree.root_node().has_error() {
        eprintln!("note: tree contains ERROR node(s)");
    }
    Ok(())
}

fn write_sexp(node: tree_sitter::Node, src: &[u8], depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    let leaf_text = if node.named_child_count() == 0 {
        let t = &src[node.byte_range()];
        format!("  {:?}", String::from_utf8_lossy(t))
    } else {
        String::new()
    };
    out.push_str(&format!("{indent}({}{})\n", node.kind(), leaf_text));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        write_sexp(child, src, depth + 1, out);
    }
}
