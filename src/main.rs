//! crit CLI.

use anyhow::{bail, Context, Result};
use crit::diff::{DiffMode, DiffOutcome};
use crit::engine::{ScanReport, Scanner};
use crit::finding::Severity;
use crit::git::{self, GitContext};
use crit::language::LanguageRegistry;
use crit::report::{self, Format};
use crit::rule::{self, Rule};
use crit::snapshot::{self, Snapshot};
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
#[command(name = "crit", version, about, long_about = None)]
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
    /// Differential scan against a git base ref (sugar over `scan`):
    /// resolve base → obtain/derive base snapshot → full HEAD scan →
    /// set-difference → differential report → exit 1 on new ≥ --fail-on.
    Diff(DiffArgs),
    /// List all available languages (bundled + dynamically loaded).
    ListLanguages,
    /// List the rules loaded from the given rule paths.
    ListRules(RulesArgs),
    /// Parse a file and print its tree-sitter s-expression (debugging rules).
    DumpAst(DumpArgs),
}

/// Options shared verbatim by `scan` and `diff`. One definition: a flag added
/// here reaches both subcommands (and the desugaring) automatically.
#[derive(clap::Args)]
struct CommonArgs {
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

    /// Always write the complete HEAD snapshot here (seeds the next baseline),
    /// regardless of what the report includes.
    #[arg(long, value_name = "FILE")]
    emit_snapshot: Option<PathBuf>,

    /// Findings-cache directory (content-addressed; unchanged files are not
    /// re-parsed). Defaults to `.crit/cache` under the repo root.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    /// Disable the findings cache entirely.
    #[arg(long, conflicts_with = "cache_dir")]
    no_cache: bool,

    /// Fingerprint tuning: how many ancestor node kinds the structural path
    /// includes. Higher = stricter identity (fewer collisions, more churn on
    /// refactors). Changing it changes finding identity; snapshots record it.
    #[arg(long, value_name = "N", default_value_t = crit::fingerprint::DEFAULT_ANCESTOR_DEPTH)]
    fingerprint_depth: usize,

    /// Print non-fatal warnings (e.g. rules skipped for a grammar) to stderr.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,

    #[command(flatten)]
    common: CommonArgs,

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

    /// What to do when the baseline's ruleset/engine/grammar identity differs
    /// from this scan: fail|warn|partition|rescan-base. `partition` and
    /// `rescan-base` re-derive the base finding set with the current ruleset
    /// (needs `--diff-base` and git; otherwise they degrade to `warn`).
    #[arg(long, default_value = "partition")]
    on_baseline_mismatch: MismatchPolicy,

    /// With a baseline, gate the exit code on *new* findings only (nightly
    /// full-backlog jobs leave this off).
    #[arg(long)]
    fail_on_new: bool,

    /// Git ref the change is against (e.g. origin/main). Enables diff
    /// attribution and rename tracking; with no `--baseline`, crit scans the
    /// base ref itself to derive one (costs one extra full scan).
    #[arg(long, value_name = "REF")]
    diff_base: Option<String>,

    /// Unified diff supplying changed files/hunks without invoking git
    /// (a patch file, or `-` for stdin). Attribution only — it cannot
    /// materialize the base source.
    #[arg(long, value_name = "FILE", conflicts_with = "diff_base")]
    diff: Option<String>,
}

#[derive(clap::Args)]
struct DiffArgs {
    /// Files or directories to scan (defaults to the whole tree).
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

    /// Git ref the change is against (e.g. origin/main).
    #[arg(long, value_name = "REF")]
    base: String,

    #[command(flatten)]
    common: CommonArgs,

    /// Where the base snapshot comes from: `scan` (rescan the base ref),
    /// `file:<path>` (must exist), or `cache:<path>` (use if present, else
    /// fall back to scanning the base ref — the CI-restored-artifact flow).
    #[arg(long, value_name = "SPEC", default_value = "scan")]
    baseline_source: String,

    /// What to report: all|new|fixed|updated. Repeatable; default `new`.
    #[arg(long = "report", value_name = "MODE")]
    report: Vec<String>,

    /// Exit non-zero when a *new* finding at or above this severity exists.
    #[arg(long, default_value = "error")]
    fail_on: String,
}

impl DiffArgs {
    /// Desugar into the `scan` primitive's arguments.
    fn into_scan_args(self) -> Result<ScanArgs> {
        let baseline = match self.baseline_source.as_str() {
            "scan" => None,
            s => match s.split_once(':') {
                Some(("file", p)) => {
                    let p = PathBuf::from(p);
                    if !p.exists() {
                        bail!("--baseline-source file:{} does not exist", p.display());
                    }
                    Some(p)
                }
                Some(("cache", p)) => {
                    let p = PathBuf::from(p);
                    if p.exists() {
                        Some(p)
                    } else {
                        eprintln!(
                            "note: cached baseline {} not present; deriving one by \
                             scanning '{}' instead",
                            p.display(),
                            self.base
                        );
                        None
                    }
                }
                _ => bail!(
                    "invalid --baseline-source '{s}' (expected scan | file:<path> | cache:<path>)"
                ),
            },
        };
        let report = if self.report.is_empty() {
            vec!["new".to_string()]
        } else {
            self.report
        };
        Ok(ScanArgs {
            paths: self.paths,
            common: self.common,
            fail_on: self.fail_on,
            baseline,
            diff_mode: report,
            on_baseline_mismatch: MismatchPolicy::Partition,
            fail_on_new: true,
            diff_base: Some(self.base),
            diff: None,
        })
    }
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

    match cli.command {
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
            dump_ast(&registry, &args)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan(args) => scan(&registry, &args),
        // `diff` is sugar: resolve base → obtain/derive base snapshot →
        // incremental full HEAD scan → set-difference → differential report.
        Command::Diff(args) => scan(&registry, &args.into_scan_args()?),
    }
}

fn scan(registry: &LanguageRegistry, args: &ScanArgs) -> Result<ExitCode> {
    let fail_on = Severity::parse_threshold(&args.fail_on)
        .with_context(|| format!("invalid --fail-on value '{}'", args.fail_on))?;

    let rules = rule::load_paths(&args.common.rules)?;
    if rules.is_empty() {
        eprintln!("warning: no rules loaded from {:?}", args.common.rules);
    }

    // Git context (if any): repo-relative finding paths make fingerprints
    // portable across machines and identical between a HEAD scan and a
    // materialized base-tree scan. Discovered from the scanned paths only —
    // falling back to the cwd's repo would attach the *wrong* repository to
    // out-of-repo scans (bogus vcs provenance, bogus --diff-base).
    let git_ctx = args.paths.first().and_then(|p| GitContext::discover(p));

    // Ruleset identity — needed up front: it is both the snapshot identity
    // and a cache-key component.
    let ruleset_id = snapshot::ruleset_id(&rules);

    // Findings cache: on by default (content-addressed keys make staleness
    // structurally impossible), disabled by --no-cache. Keyed by the *cache*
    // ruleset identity, which also covers text copied into findings, and by
    // the fingerprint scheme in effect (composition version + tuning).
    let scheme_id = crit::fingerprint::scheme_id(
        args.common.fingerprint_depth,
        crit::fingerprint::CONTEXT_LINES,
    );
    let cache = crit::cache::Cache::open_default(
        args.common.no_cache,
        args.common.cache_dir.as_deref(),
        git_ctx.as_ref().map(|c| c.root()),
        args.paths.first().map(|p| p.as_path()),
        snapshot::ruleset_cache_id(&rules),
        scheme_id,
    );

    let mut scanner =
        Scanner::new(registry, &rules).with_fingerprint_depth(args.common.fingerprint_depth);
    if let Some(ctx) = &git_ctx {
        scanner = scanner.with_path_root(ctx.root().to_path_buf());
    }
    if let Some(c) = &cache {
        scanner = scanner.with_cache(c);
    }
    let mut report = ScanReport::default();
    for path in &args.paths {
        scan_path(&scanner, path, args.common.language.as_deref(), &mut report)?;
    }
    // Whole-tree pass for cross-file rules (no-op without any).
    scanner.cross_file_pass(&mut report)?;

    if args.common.verbose {
        for w in scanner.take_warnings() {
            eprintln!("warning: {w}");
        }
        if cache.is_some() {
            eprintln!(
                "cache: {} of {} scanned file(s) served from cache{}",
                report.files_cached,
                report.files_scanned,
                if report.files_cached > 0 {
                    " (cached files skip parse/query diagnostics)"
                } else {
                    ""
                }
            );
        }
    }

    // Canonicalize: sort (a documented, load-bearing ordering), dedup, and
    // assign fingerprint occurrence indices.
    crit::finding::finalize(&mut report.findings);

    // Identity of this scan, for snapshots and comparability.
    let grammar_versions = snapshot::grammar_versions(registry, &report.languages_seen);

    // The complete HEAD snapshot — always the full set, never a diff subset.
    // vcs provenance costs two git subprocesses, so resolve it only when the
    // snapshot is actually serialized. Written to disk *after* diffing so a
    // consumed baseline's suppressions can be carried forward.
    let wants_snapshot = args.common.emit_snapshot.is_some() || args.common.format == Format::Snapshot;
    let mut head_snapshot = Snapshot::from_findings(
        &report.findings,
        ruleset_id.clone(),
        grammar_versions.clone(),
        if wants_snapshot {
            git_ctx.as_ref().and_then(|c| c.head_vcs())
        } else {
            None
        },
    );
    head_snapshot.fingerprint_depth = args.common.fingerprint_depth;

    // Resolve requested diff modes (default: the whole-tree `all` behaviour).
    let modes = parse_diff_modes(&args.diff_mode)?;
    let wants_diff = args.baseline.is_some()
        || args.fail_on_new
        || args.diff_base.is_some()
        || args.diff.is_some()
        || modes.iter().any(|m| *m != DiffMode::All);

    let outcome = if wants_diff {
        let env = DiffEnv {
            args,
            registry,
            rules: &rules,
            git_ctx: git_ctx.as_ref(),
            cache: cache.as_ref(),
            ruleset_id: &ruleset_id,
            grammar_versions: &grammar_versions,
        };
        // The snapshot has been built; the findings can be moved out rather
        // than cloned through the diff pipeline.
        let head = std::mem::take(&mut report.findings);
        Some(run_diff(&env, head)?)
    } else {
        None
    };

    // Carry the consumed baseline's triaged fingerprints forward, then emit.
    if let Some(o) = &outcome {
        let mut carried: Vec<String> = o.suppressed.iter().cloned().collect();
        carried.sort();
        head_snapshot.suppressions = carried;
        if args.common.verbose && !o.suppressed.is_empty() {
            let n = o
                .annotated
                .iter()
                .filter(|f| o.suppressed.contains(&f.fingerprint))
                .count();
            eprintln!(
                "suppressions: {n} finding(s) hidden by the baseline's {} triaged fingerprint(s)",
                o.suppressed.len()
            );
        }
    }
    if let Some(path) = &args.common.emit_snapshot {
        std::fs::write(path, head_snapshot.to_json())
            .with_context(|| format!("writing snapshot {}", path.display()))?;
    }

    let rendered = render(args, &report, &rules, &head_snapshot, outcome.as_ref(), &modes);

    if let Some(out) = &args.common.output {
        std::fs::write(out, rendered).with_context(|| format!("writing {}", out.display()))?;
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(rendered.as_bytes())?;
    }

    // Decide exit code from the fail-on threshold. When diffing, the gate
    // tracks the *reported* set (so `--diff-mode new` fails only on new), and
    // `--fail-on-new` narrows it to new findings regardless of the report.
    // Fixed (`absent`) findings are never present at HEAD, and ruleset-induced
    // findings are pre-existing code surfaced by a rules bump — neither may
    // ever fail an innocent change.
    if let Some(threshold) = fail_on {
        let tripped = match &outcome {
            Some(o) => o
                .reported(&modes)
                .iter()
                .filter(|f| f.state.map(|s| s.present_at_head()).unwrap_or(true))
                .filter(|f| f.new_cause != Some(crit::finding::NewCause::Ruleset))
                .filter(|f| {
                    !args.fail_on_new || f.state == Some(crit::finding::FindingState::New)
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

/// Everything the differential pipeline needs besides the findings
/// themselves; one bundle instead of seven threaded parameters.
struct DiffEnv<'a> {
    args: &'a ScanArgs,
    registry: &'a LanguageRegistry,
    rules: &'a [Rule],
    git_ctx: Option<&'a GitContext>,
    cache: Option<&'a crit::cache::Cache>,
    ruleset_id: &'a str,
    grammar_versions: &'a std::collections::BTreeMap<String, String>,
}

/// Resolve the baseline (supplied file, base-ref rescan, or the loud
/// "everything is new" fallback), apply the mismatch policy, diff, and
/// attribute findings against the change's hunks. Takes ownership of the
/// HEAD findings — no clones on the diff path.
fn run_diff(env: &DiffEnv, head: Vec<crit::finding::Finding>) -> Result<DiffOutcome> {
    let args = env.args;
    // Hunk/rename information for attribution (and baseline path remapping).
    // Attribution is an annotation, never correctness: when a baseline
    // artifact is available the diff can proceed without it (e.g. merge-base
    // fails in a shallow CI clone), so degrade rather than abort.
    let spec = match diff_spec(args, env.git_ctx) {
        Ok(s) => s,
        Err(e) if args.baseline.is_some() => {
            eprintln!(
                "warning: cannot compute diff attribution ({e:#}); \
                 continuing without hunk/rename information"
            );
            None
        }
        Err(e) => return Err(e),
    };

    let mut outcome = match &args.baseline {
        Some(baseline_path) => {
            let mut baseline = Snapshot::load(baseline_path)?;
            if let Some(spec) = &spec {
                baseline.remap_renames(spec.renames());
            }
            let mismatches = baseline.comparability(
                env.ruleset_id,
                env.grammar_versions,
                env.args.common.fingerprint_depth,
            );
            if mismatches.is_empty() {
                DiffOutcome::diff(head, &baseline)
            } else {
                mismatched_diff(env, head, &baseline, &mismatches, spec.as_ref())?
            }
        }
        None => match &args.diff_base {
            // No baseline artifact, but a base ref: scan the base tree itself.
            // Same ruleset by construction, so no mismatch is possible.
            Some(base_ref) => {
                let base_now = resolve_base_now(env, base_ref, spec.as_ref())?;
                DiffOutcome::diff(head, &base_now)
            }
            None => {
                // Diff requested with no baseline: never silently report zero.
                eprintln!(
                    "warning: --diff-mode/--fail-on-new set without --baseline or \
                     --diff-base; treating every finding as new"
                );
                DiffOutcome::all_new(head)
            }
        },
    };

    if let Some(spec) = &spec {
        outcome.attribute(spec);
    }
    Ok(outcome)
}

/// Handle a baseline whose ruleset/engine/grammar identity differs from the
/// current scan, per `--on-baseline-mismatch`.
fn mismatched_diff(
    env: &DiffEnv,
    head: Vec<crit::finding::Finding>,
    baseline: &Snapshot,
    mismatches: &[snapshot::Mismatch],
    spec: Option<&git::DiffSpec>,
) -> Result<DiffOutcome> {
    let args = env.args;
    let summary = mismatches
        .iter()
        .map(|m| m.to_string())
        .collect::<Vec<_>>()
        .join("; ");

    let warn = |reason: &str| {
        eprintln!(
            "warning: baseline mismatch ({summary}); {reason} — diffing anyway; \
             'new' findings may include ruleset/grammar-induced ones"
        );
    };

    let is_partition = args.on_baseline_mismatch == MismatchPolicy::Partition;
    match args.on_baseline_mismatch {
        MismatchPolicy::Fail => bail!(
            "baseline mismatch ({summary}); refusing to diff \
             (--on-baseline-mismatch fail)"
        ),
        MismatchPolicy::Warn => {
            warn("policy is 'warn'");
            Ok(DiffOutcome::diff(head, baseline))
        }
        MismatchPolicy::Partition | MismatchPolicy::RescanBase => {
            let policy = if is_partition { "partition" } else { "rescan-base" };
            // Both need the base *source* to re-derive the base finding set
            // with the current ruleset.
            let Some(base_ref) = &args.diff_base else {
                warn(&format!(
                    "'{policy}' needs the base source (pass --diff-base inside a git repo)"
                ));
                return Ok(DiffOutcome::diff(head, baseline));
            };
            eprintln!(
                "note: baseline mismatch ({summary}); '{policy}': rescanning base \
                 '{base_ref}' with the current ruleset"
            );
            let base_now = resolve_base_now(env, base_ref, spec)?;
            if is_partition {
                // Honest split: states vs base_now (code-relative), findings
                // the old rules missed labelled new-due-to-ruleset.
                Ok(DiffOutcome::diff_partitioned(head, baseline, &base_now))
            } else {
                // rescan-base: the re-derived base replaces the stale one, but
                // the supplied baseline's triaged suppressions still apply.
                let mut outcome = DiffOutcome::diff(head, &base_now);
                outcome
                    .suppressed
                    .extend(baseline.suppressions.iter().cloned());
                Ok(outcome)
            }
        }
    }
}

/// Derive the base finding set with the *current* ruleset: materialize the
/// merge-base of `base_ref` (the same commit the hunk spec is computed
/// against — never the moved-on branch tip), scan it, and apply rename
/// remapping so its paths line up with HEAD's.
fn resolve_base_now(
    env: &DiffEnv,
    base_ref: &str,
    spec: Option<&git::DiffSpec>,
) -> Result<Snapshot> {
    let ctx = env
        .git_ctx
        .context("--diff-base requires the scanned paths to be inside a git repository")?;
    let merge_base = ctx.merge_base(base_ref)?;
    let mut base_now = scan_base_tree(env, ctx, &merge_base)?;
    if let Some(spec) = spec {
        base_now.remap_renames(spec.renames());
    }
    Ok(base_now)
}

/// Obtain hunk/rename information: from a supplied unified diff (`--diff`),
/// or from git (`--diff-base`, merge-base semantics).
fn diff_spec(args: &ScanArgs, git_ctx: Option<&GitContext>) -> Result<Option<git::DiffSpec>> {
    if let Some(patch) = &args.diff {
        let text = if patch == "-" {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(patch)
                .with_context(|| format!("reading diff file {patch}"))?
        };
        return Ok(Some(git::parse_unified_diff(&text)?));
    }
    if let Some(base) = &args.diff_base {
        let ctx = git_ctx.context(
            "--diff-base requires the scanned paths to be inside a git repository",
        )?;
        return Ok(Some(ctx.diff_spec(base)?));
    }
    Ok(None)
}

/// Materialize `base_ref` in a temporary worktree and run the same scan over
/// it (same rules, same language forcing, same relative paths), producing the
/// base snapshot. Paths are relativized to the *worktree* root so fingerprints
/// line up with the HEAD scan's repo-relative ones.
fn scan_base_tree(env: &DiffEnv, ctx: &GitContext, base_commit: &str) -> Result<Snapshot> {
    let tree = ctx.materialize(base_commit)?;
    let mut scanner = Scanner::new(env.registry, env.rules)
        .with_path_root(tree.path().to_path_buf())
        .with_fingerprint_depth(env.args.common.fingerprint_depth);
    // The base scan shares the HEAD scan's cache: identity paths are
    // worktree-relative on both sides, so unchanged files hit the entries the
    // HEAD scan just wrote (and vice versa) — whole-tree completeness at
    // roughly the cost of the changed subset.
    if let Some(c) = env.cache {
        scanner = scanner.with_cache(c);
    }

    let mut report = ScanReport::default();
    for path in &env.args.paths {
        // Map each scanned path into the base tree via its repo-relative form.
        let Some(rel) = git::relative_to(path, ctx.root()) else {
            eprintln!(
                "warning: {} is outside the git repository; skipping it in the base scan",
                path.display()
            );
            continue;
        };
        let base_path = tree.path().join(&rel);
        if !base_path.exists() {
            continue; // path introduced since base — nothing to scan there
        }
        scan_path(&scanner, &base_path, env.args.common.language.as_deref(), &mut report)?;
    }
    // A→B correctness cuts both ways: the BASE finding set must include
    // cross-file findings too, or removing a source would not read as fixed.
    scanner.cross_file_pass(&mut report)?;
    crit::finding::finalize(&mut report.findings);

    let mut snap = Snapshot::from_findings(
        &report.findings,
        env.ruleset_id.to_string(),
        snapshot::grammar_versions(env.registry, &report.languages_seen),
        None,
    );
    snap.fingerprint_depth = env.args.common.fingerprint_depth;
    Ok(snap)
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
    if args.common.format == Format::Snapshot {
        return head_snapshot.to_json();
    }

    match outcome {
        Some(o) => {
            let reported = o.reported(modes);
            match args.common.format {
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
        None => match args.common.format {
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
            rule::Matcher::CrossFile { .. } => "cross-file",
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
