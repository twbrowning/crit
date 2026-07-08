# crit

A tree-sitter-based, language-agnostic source **security scanner**. crit
parses code with a tree-sitter grammar and reports security issues described as
**rules** — either raw tree-sitter queries or a structured YAML format that
transpiles to a tree-sitter query.

It ships with first-class support for **InterSystems ObjectScript**, with all
four language variants compiled in:

| Variant (`--language` id) | Files                         | Notes                              |
|---------------------------|-------------------------------|------------------------------------|
| `objectscript_expr`       | —                             | Expression grammar (family base)   |
| `objectscript_core`       | —                             | Core statement/line grammar        |
| `objectscript_udl`        | `.cls`                        | Class Definition / UDL             |
| `objectscript_routine`    | `.mac` `.int` `.inc` `.rtn`   | Routine grammar                    |

> The vendored grammar is the generated parser source for
> `intersystems/tree-sitter-objectscript` v1.9.5 (MIT, tree-sitter ABI 15). See
> [`vendor/objectscript/PROVENANCE.md`](vendor/objectscript/PROVENANCE.md).

## Why "consumes a tree-sitter"

crit does not hard-code any language. It resolves a `tree_sitter::Language`
two ways:

1. **Bundled** — grammars statically compiled into the binary (the four
   ObjectScript variants, via `build.rs`). On by default; disable with
   `--no-default-features`.
2. **Dynamic** — any grammar compiled to a shared library (`.so`/`.dylib`/`.dll`)
   and registered in a TOML config, loaded at runtime with `dlopen`. This makes
   the tool work for *any* language without recompiling crit.

## Build & install

```sh
cargo build --release
# binary at target/release/crit
```

A C compiler is required (the vendored ObjectScript parsers are compiled by
`build.rs`). They are large generated files compiled at `-O0`, so the first
build takes ~30s.

## Usage

```sh
# Scan a tree using the example rules; language auto-detected by extension.
crit scan src/ --rules rules/

# Force a language (e.g. for stdin-like or unmapped files).
crit scan Foo.cls --language objectscript_udl --rules rules/

# CI-friendly SARIF for GitHub code scanning.
crit scan src/ --rules rules/ --format sarif --output results.sarif

# Inspect the parse tree while authoring rules.
crit dump-ast Foo.cls
echo ' xecute x' | crit dump-ast --language objectscript_routine

# Discover what's available.
crit list-languages
crit list-rules --rules rules/
```

Exit codes: `0` clean (or below threshold), `1` a finding at/above `--fail-on`
(default `error`; use `off` to disable), `2` an error.

Output formats: `human` (default, colorized), `sarif` (SARIF 2.1.0), `json`,
`snapshot` (the `crit.snapshot/v1` artifact — see below).

## Differential ("what changed") scanning

crit can surface only the issues a change *introduces*, rather than the whole
backlog — the PR-review use case. Correctness is defined at the level of
**findings**, never lines:

> `new(PR) = findings(HEAD) − findings(BASE)`, compared by a stable, line-number-
> independent **fingerprint**, over the *complete* tree at each ref.

Because the whole tree is evaluated at HEAD, a change in file A that causes a new
finding in an otherwise-unchanged file B is still caught — diff locality is never
traded for completeness.

### The snapshot artifact

The one stateful concept is a **snapshot**: the complete, fingerprinted finding
set of one scan, plus the provenance (`ruleset_id`, `engine_version`,
`grammar_versions`) needed to know whether two snapshots are comparable. crit
*emits* it and *consumes* it as a baseline — it never commits anything itself, so
a PR run never edits PR contents.

```sh
# Zero setup, inside a git repo — scan the base ref itself for the baseline:
crit diff src/ --base origin/main --rules rules/ --format sarif -o results.sarif

# Or with a CI-cached baseline artifact (no extra base scan, no repo writes):
crit scan src/ --rules rules/ --emit-snapshot base.snapshot.json     # on main
crit scan src/ --rules rules/ \
        --baseline base.snapshot.json --diff-base origin/main \
        --diff-mode new --fail-on-new --fail-on error                   # on the PR
```

### Flags (all additive; the default is today's whole-tree behaviour)

| Flag | Meaning |
|------|---------|
| `--baseline <FILE>` | Prior snapshot to diff against. |
| `--diff-base <REF>` | Git ref the change is against. Enables diff attribution + rename tracking; with no `--baseline`, crit scans the base ref itself (one extra full scan, zero setup). |
| `--diff <FILE\|->` | Unified diff for attribution without git (VCS-agnostic escape hatch). |
| `--diff-mode <all\|new\|fixed\|updated>` | What to report (repeatable; the union). `new` is the PR gate; `all` is the default. |
| `--emit-snapshot <FILE>` | Always writes the **complete** HEAD finding set (seeds the next baseline), even under `--diff-mode new`. |
| `--fail-on-new` | Gate the exit code on *new* findings only (nightly `--diff-mode all` jobs leave it off and fail on the full backlog). |
| `--on-baseline-mismatch <fail\|warn\|partition\|rescan-base>` | What to do when the baseline's ruleset/engine/grammar identity differs from this scan. Default `partition`. |

The `crit diff` subcommand is sugar over these primitives: resolve base →
obtain/derive the base snapshot (`--baseline-source scan|file:<p>|cache:<p>`) →
full HEAD scan → set-difference → differential report → exit 1 on new ≥
`--fail-on`.

Each finding carries a **state** (`new` / `unchanged` / `updated` / `absent`),
and — when `--diff-base`/`--diff` supplies hunks — a **`diff_relation`**
(`on_added_line` / `in_changed_file_unchanged_line` / `in_unchanged_file`). The
relation is a reviewer signal only, never a filter: a *new* finding
`in_unchanged_file` is the loud case where a change in file A introduced an
issue in untouched file B.

* **human** groups findings into *New in this change* / *Newly flagged by a
  rules change* / *Pre-existing* / *Fixed*, with attribution on each;
* **SARIF** populates `result.baselineState` and `partialFingerprints`, so GitHub
  code scanning shows "new in this PR" natively — no git or artifact plumbing;
* **JSON** adds `fingerprint`, `content_key`, `context_hash`, `occurrence`,
  `state`, `diff_relation`, and `new_cause` per hit.

File renames are tracked via `git diff -M`: each finding stores a
path-independent `content_key`, so a renamed-but-unchanged finding's
fingerprint is *recomposed* under the new path instead of decaying into
fixed-old + new.

### Comparability

"New since BASE" can mean the *code* changed **or** the *rules/grammar/engine*
changed (an upgraded rule legitimately flags old code). The snapshot records
`ruleset_id`, `engine_version`, and `grammar_versions`; on a mismatch,
`--on-baseline-mismatch` decides. `fail` and `warn` need no base source.
`partition` (the default) and `rescan-base` re-derive the base finding set with
the *current* rules by rescanning the base tree (needs `--diff-base` inside a
git repo; otherwise they degrade to `warn` with a note):

* **partition** reports the honest split — `new_cause: code` findings are truly
  introduced by the change and gate CI; `new_cause: ruleset` findings are
  pre-existing code newly flagged by a rules bump, reported separately and
  never failing an innocent PR.
* **rescan-base** simply replaces the stale baseline with the re-derived one.

## Writing rules

A rule supplies its match logic in **one** of two forms. The capture named
`@match` (configurable via `capture:`) marks the node a finding points at.

### 1. Raw tree-sitter query (`query:` or a `.scm` file)

```yaml
id: os-command-execution-zf
message: $ZF(-1)/$ZF(-100) execute OS commands.
severity: error            # error | warning | info | note
languages: [objectscript]  # variant ids or the `objectscript` group; empty = any
cwe: CWE-78
query: |
  ((system_defined_function) @match
   (#match? @match "(?i)^\\$zf\\s*\\(\\s*-\\s*(1|100)\\b"))
```

> **Predicate gotcha:** wrap a pattern *and* its `(#...)` predicates in an outer
> paren — `(( ... ) @match (#match? ...))` — otherwise tree-sitter parses each
> predicate as a separate pattern and it silently never filters.

A `.scm` file carries its metadata in a leading comment header:

```scheme
; id: os-dynamic-exec-xecute
; message: XECUTE runs its argument as ObjectScript code.
; severity: warning
; languages: objectscript
(command_xecute) @match
```

### 2. Structured `pattern:` (transpiled to a query)

```yaml
id: os-hardcoded-credential-parameter
message: Hardcoded credential in a class Parameter.
severity: error
languages: [objectscript_udl]
pattern:
  node: parameter            # node kind to match
  children:                  # DIRECT named children (one nesting level each)
    - node: parameter_name
      children:
        - node: identifier
          text: { regex: "(?i)(password|secret|token|apikey)" }
    - node: default_argument_value
      children:
        - node: typename
          text: { regex: "^\"" }   # value is a string literal
```

`text` accepts `regex` / `eq` / `not_regex` / `not_eq`, compiled to
`#match?` / `#eq?` / `#not-match?` / `#not-eq?`. Because tree-sitter queries have
no descendant combinator, `children` are *direct* children — one level of YAML
nesting per level of the syntax tree. Use `crit dump-ast` to see the shape.

A YAML file may hold a single rule, a top-level list, or `{ rules: [ ... ] }`.

## Bundled ObjectScript rules

[`rules/objectscript/`](rules/objectscript) ships example security rules
covering both authoring formats:

| Rule id                              | Severity | Issue                                       | Format    |
|--------------------------------------|----------|---------------------------------------------|-----------|
| `os-command-execution-zf`            | error    | OS command exec via `$ZF(-1)`/`$ZF(-100)`   | query     |
| `os-sql-dynamic-concat`              | error    | SQL built by string concatenation           | query     |
| `os-sql-tainted-exec`                | warning  | `%SQL.Statement` executed from a variable    | query     |
| `os-hardcoded-credential-set`        | error    | Secret-named var assigned a string literal   | query     |
| `os-hardcoded-credential-parameter`  | error    | Secret-named class `Parameter` with literal  | pattern   |
| `os-dynamic-exec-xecute`             | warning  | `XECUTE` (dynamic code execution)            | `.scm`    |
| `os-indirection-review`              | info     | Indirection (`@`) dynamic evaluation         | pattern   |

## Scanning another language (dynamic grammars)

```sh
# Build a grammar into a shared library once:
gcc -shared -fPIC -O2 -I src -o libtree-sitter-json.so src/parser.c

# Register it and scan — same engine, same rule formats:
crit --languages-config examples/languages.toml \
        scan config.json --rules examples/json-rules/
```

See [`examples/languages.toml`](examples/languages.toml) and
[`examples/json-rules/`](examples/json-rules).

## Testing

```sh
cargo test
```

The suite validates:

* **Grammar consumption** ([`tests/grammar_consumption.rs`](tests/grammar_consumption.rs))
  — all four ObjectScript variants load (ABI 15), parse representative code with
  no `ERROR` nodes, and expose the expected node kinds; the query API runs
  against a bundled grammar.
* **Rule matching** ([`tests/rule_matching.rs`](tests/rule_matching.rs)) — the
  shipped rules fire on vulnerable fixtures and stay silent on clean ones, across
  both authoring formats, with severities and predicate filtering verified.
* **Diff scanning** ([`tests/diff_scanning.rs`](tests/diff_scanning.rs)) —
  fingerprints survive line-number shifts, snapshots round-trip through disk, and
  new/unchanged/updated/fixed classification drives the PR gate.
* **Pattern compiler** and **fingerprint/snapshot/diff** (unit tests in
  `src/compile.rs`, `src/fingerprint.rs`, `src/snapshot.rs`, `src/diff.rs`).

## Layout

```
build.rs                     # compiles the vendored grammars
vendor/objectscript/         # generated parser sources (MIT) + provenance
src/
  bundled.rs                 # statically-compiled grammars
  language.rs                # registry: bundled + dynamic (.so) loading
  rule.rs                    # rule model + YAML/.scm loaders
  compile.rs                 # structured pattern -> tree-sitter query
  engine.rs                  # parse + run queries + collect findings
  fingerprint.rs             # stable, position-independent finding identity
  snapshot.rs                # crit.snapshot/v1 emit/consume + comparability
  diff.rs                    # differential ("what changed") analysis
  report/                    # human, SARIF, JSON, snapshot output
rules/objectscript/          # example security rules
tests/                       # consumption + rule-matching tests + fixtures
examples/                    # dynamic-language config + JSON rule
```

## License

crit is MIT-licensed. The vendored ObjectScript grammar is MIT © InterSystems
Corporation (see [`vendor/objectscript/LICENSE`](vendor/objectscript/LICENSE)).
