# Vendored grammar: InterSystems ObjectScript (tree-sitter)

These are the **generated** tree-sitter parser sources for InterSystems
ObjectScript, vendored so that `catseye` can compile the bundled grammars
reproducibly without network access at build time.

| Field         | Value                                                       |
|---------------|-------------------------------------------------------------|
| Upstream      | `intersystems/tree-sitter-objectscript`                     |
| Source artifact | npm package `tree-sitter-objectscript` (the npm tarball ships the generated `parser.c` for every grammar; the crates.io/PyPI artifacts ship only a subset) |
| Version       | `1.9.5`                                                      |
| tree-sitter ABI (`LANGUAGE_VERSION`) | `15`                                  |
| License       | MIT — see `LICENSE` (© InterSystems Corporation)            |

## The four language variants

InterSystems ObjectScript is modelled by upstream as a layered family of
grammars. `catseye` vendors and statically compiles all four:

| Variant id (catseye)     | Exported C symbol                    | Purpose / typical files                          | External scanner |
|--------------------------|--------------------------------------|--------------------------------------------------|------------------|
| `objectscript_expr`      | `tree_sitter_objectscript_expr`      | Expression grammar (the base of the family)      | no               |
| `objectscript_core`      | `tree_sitter_objectscript_core`      | One or more lines/statements of ObjectScript     | yes              |
| `objectscript_udl`       | `tree_sitter_objectscript_udl`       | Class Definition / UDL — `.cls` files            | yes              |
| `objectscript_routine`   | `tree_sitter_objectscript_routine`   | Routine files — `.mac`, `.int`, `.inc`, `.rtn`   | yes              |

`udl` and `core` extend `expr`; `udl`/`routine` build on `core`. Upstream also
publishes an `objectscript` "playground" wrapper grammar — not vendored here as
it is not one of the four canonical variants, but it can be loaded dynamically
(see the dynamic-language config) if desired.

## What was copied

For each variant directory: `src/parser.c`, `src/scanner.c` (where present),
`src/node-types.json`, and `src/tree_sitter/*.h`. The shared external-scanner
header lives in `common/scanner.h` and is included by each `scanner.c` as
`../../common/scanner.h`.

Nothing was modified. To refresh, re-download the npm tarball for the desired
version and re-copy these files.
