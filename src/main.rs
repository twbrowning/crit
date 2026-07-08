//! catseye CLI.

use anyhow::{bail, Context, Result};
use catseye::diff::{DiffMode, DiffOutcome};
use catseye::engine::{ScanReport, Scanner};
use catseye::finding::Severity;
use catseye::language::LanguageRegistry;
use catseye::report::{self, Format};
use catseye::rule::{self, Rule};
use catseye::snapshot::{self, Snapshot};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// Policy for when a baseline snapshot's ruleset/engine/grammar identity differs
/// from the current scan's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MismatchPolicy {
    Fail,
    Warn,
    Partition,
    RescanBase,
}

impl std::str::FromStr for MismatchPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "fail" => Ok(MismatchPolicy::Fail),
            "warn" => Ok(MismatchPolicy::Warn),
            "partition" => Ok(MismatchPolicy::Partition),
            "rescan-base" | "rescan_base" => Ok(MismatchPolicy::RescanBase),
            other => Err(format!(
                "unknown --on-baseline-mismatch '{other}' (expected fail|warn|partition|rescan-base)"
            )),
        }
    }
}

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

    /// Prior snapshot to diff against (the baseline). Enables differential
    /// reporting; produce one with `--emit-snapshot` or `--format snapshot`.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// What to report, relative to the baseline: all|new|fixed|updated.
    /// Repeatable; the report is the union. `new` is the PR gate; `all`
    /// (the default) is the whole-tree behaviour.
    #[arg(long = "diff-mode", value_name = "MODE")]
    diff_mode: Vec<String>,

    /// Always write the complete HEAD snapshot here (seeds the next baseline),
    /// regardless of `--diff-mode`/`--format`.
    #[arg(long, value_name = "FILE")]
    emit_snapshot: Option<PathBuf>,

    /// What to do when the baseline's ruleset/engine/grammar identity differs
    /// from this scan: fail|warn|partition|rescan-base.
    #[arg(long, default_value = "warn")]
    on_baseline_mismatch: MismatchPolicy,

    /// With a baseline, gate the exit code on *new* findings only (nightly
    /// full-backlog jobs leave this off).
    #[arg(long)]
    fail_on_new: bool,

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

    // Canonicalize: sort (a documented, load-bearing ordering), dedup, and
    // assign fingerprint occurrence indices.
    catseye::finding::finalize(&mut report.findings);

    // Identity of this scan, for snapshots and comparability.
    let ruleset_id = snapshot::ruleset_id(&rules);
    let grammar_versions = snapshot::grammar_versions(registry, &report.languages_seen);

    // The complete HEAD snapshot — always the full set, never a diff subset.
    let head_snapshot = Snapshot::from_findings(
        &report.findings,
        ruleset_id.clone(),
        grammar_versions.clone(),
        None,
    );
    if let Some(path) = &args.emit_snapshot {
        std::fs::write(path, head_snapshot.to_json())
            .with_context(|| format!("writing snapshot {}", path.display()))?;
    }

    // Resolve requested diff modes (default: the whole-tree `all` behaviour).
    let modes = parse_diff_modes(&args.diff_mode)?;
    let wants_diff = args.baseline.is_some()
        || args.fail_on_new
        || modes.iter().any(|m| *m != DiffMode::All);

    let outcome = if wants_diff {
        Some(run_diff(args, &report, &ruleset_id, &grammar_versions)?)
    } else {
        None
    };

    let rendered = render(args, &report, &rules, &head_snapshot, outcome.as_ref(), &modes);

    if let Some(out) = &args.output {
        std::fs::write(out, rendered).with_context(|| format!("writing {}", out.display()))?;
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(rendered.as_bytes())?;
    }

    // Decide exit code from the fail-on threshold. When diffing, the gate
    // tracks the *reported* set (so `--diff-mode new` fails only on new), and
    // `--fail-on-new` narrows it to new findings regardless of the report.
    // Fixed (`absent`) findings are never present at HEAD, so they never gate.
    if let Some(threshold) = fail_on {
        let tripped = match &outcome {
            Some(o) => o
                .reported(&modes)
                .iter()
                .filter(|f| f.state.map(|s| s.present_at_head()).unwrap_or(true))
                .filter(|f| {
                    !args.fail_on_new || f.state == Some(catseye::finding::FindingState::New)
                })
                .any(|f| f.severity <= threshold),
            None => report.findings.iter().any(|f| f.severity <= threshold),
        };
        if tripped {
            return Ok(ExitCode::from(1));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Parse `--diff-mode` values; an empty list defaults to `all` (today's
/// whole-tree behaviour).
fn parse_diff_modes(raw: &[String]) -> Result<Vec<DiffMode>> {
    if raw.is_empty() {
        return Ok(vec![DiffMode::All]);
    }
    raw.iter()
        .map(|s| s.parse::<DiffMode>().map_err(|e| anyhow::anyhow!(e)))
        .collect()
}

/// Load the baseline (or synthesise the "everything is new" case), applying the
/// baseline-mismatch policy, and produce the annotated diff outcome.
fn run_diff(
    args: &ScanArgs,
    report: &ScanReport,
    ruleset_id: &str,
    grammar_versions: &std::collections::BTreeMap<String, String>,
) -> Result<DiffOutcome> {
    let baseline_path = match &args.baseline {
        Some(p) => p,
        None => {
            // Diff requested with no baseline: never silently report zero.
            eprintln!(
                "warning: --diff-mode/--fail-on-new set without --baseline; \
                 treating every finding as new"
            );
            return Ok(DiffOutcome::all_new(report.findings.clone()));
        }
    };

    let baseline = Snapshot::load(baseline_path)?;
    let mismatches = baseline.comparability(ruleset_id, grammar_versions);
    if !mismatches.is_empty() {
        let summary = mismatches
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        match args.on_baseline_mismatch {
            MismatchPolicy::Fail => {
                bail!(
                    "baseline mismatch ({summary}); refusing to diff \
                     (--on-baseline-mismatch fail)"
                );
            }
            MismatchPolicy::Warn => {
                eprintln!(
                    "warning: baseline mismatch ({summary}); diffing anyway — \
                     'new' findings may include ruleset/grammar-induced ones"
                );
            }
            MismatchPolicy::Partition | MismatchPolicy::RescanBase => {
                // Honest partitioning needs the base *source* to re-derive the
                // base finding set with the current ruleset — that is the git
                // integration phase. Until then, degrade to `warn`.
                eprintln!(
                    "warning: baseline mismatch ({summary}); \
                     '{}' needs the base source (git integration, a later phase) — \
                     falling back to 'warn' and diffing anyway",
                    match args.on_baseline_mismatch {
                        MismatchPolicy::Partition => "partition",
                        _ => "rescan-base",
                    }
                );
            }
        }
    }

    Ok(DiffOutcome::diff(report.findings.clone(), &baseline))
}

/// Render the report in the requested format, differential when diffing.
fn render(
    args: &ScanArgs,
    report: &ScanReport,
    rules: &[Rule],
    head_snapshot: &Snapshot,
    outcome: Option<&DiffOutcome>,
    modes: &[DiffMode],
) -> String {
    // The snapshot format is always the full HEAD set, never a diff subset.
    if args.format == Format::Snapshot {
        return head_snapshot.to_json();
    }

    match outcome {
        Some(o) => {
            let reported = o.reported(modes);
            match args.format {
                Format::Human => report::render_human_diff(
                    &reported,
                    o.counts(),
                    report.files_scanned,
                    report.files_skipped,
                ),
                Format::Sarif => report::render_sarif(&reported, rules),
                Format::Json => {
                    report::render_json(&reported, report.files_scanned, report.files_skipped)
                }
                Format::Snapshot => unreachable!("handled above"),
            }
        }
        None => match args.format {
            Format::Human => {
                report::render_human(&report.findings, report.files_scanned, report.files_skipped)
            }
            Format::Sarif => report::render_sarif(&report.findings, rules),
            Format::Json => {
                report::render_json(&report.findings, report.files_scanned, report.files_skipped)
            }
            Format::Snapshot => unreachable!("handled above"),
        },
    }
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
