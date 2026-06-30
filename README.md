# catseye

A tree-sitter-based, language-agnostic source **security scanner**. catseye
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

catseye does not hard-code any language. It resolves a `tree_sitter::Language`
two ways:

1. **Bundled** — grammars statically compiled into the binary (the four
   ObjectScript variants, via `build.rs`). On by default; disable with
   `--no-default-features`.
2. **Dynamic** — any grammar compiled to a shared library (`.so`/`.dylib`/`.dll`)
   and registered in a TOML config, loaded at runtime with `dlopen`. This makes
   the tool work for *any* language without recompiling catseye.

## Build & install

```sh
cargo build --release
# binary at target/release/catseye
```

A C compiler is required (the vendored ObjectScript parsers are compiled by
`build.rs`). They are large generated files compiled at `-O0`, so the first
build takes ~30s.

## Usage

```sh
# Scan a tree using the example rules; language auto-detected by extension.
catseye scan src/ --rules rules/

# Force a language (e.g. for stdin-like or unmapped files).
catseye scan Foo.cls --language objectscript_udl --rules rules/

# CI-friendly SARIF for GitHub code scanning.
catseye scan src/ --rules rules/ --format sarif --output results.sarif

# Inspect the parse tree while authoring rules.
catseye dump-ast Foo.cls
echo ' xecute x' | catseye dump-ast --language objectscript_routine

# Discover what's available.
catseye list-languages
catseye list-rules --rules rules/
```

Exit codes: `0` clean (or below threshold), `1` a finding at/above `--fail-on`
(default `error`; use `off` to disable), `2` an error.

Output formats: `human` (default, colorized), `sarif` (SARIF 2.1.0), `json`.

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
nesting per level of the syntax tree. Use `catseye dump-ast` to see the shape.

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
catseye --languages-config examples/languages.toml \
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
* **Pattern compiler** (unit tests in `src/compile.rs`).

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
  report/                    # human, SARIF, JSON output
rules/objectscript/          # example security rules
tests/                       # consumption + rule-matching tests + fixtures
examples/                    # dynamic-language config + JSON rule
```

## License

catseye is MIT-licensed. The vendored ObjectScript grammar is MIT © InterSystems
Corporation (see [`vendor/objectscript/LICENSE`](vendor/objectscript/LICENSE)).
