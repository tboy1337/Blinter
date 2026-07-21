# Blinter Language Specification (SSOT)

This directory is the single source of truth for Blinter's batch language model,
rule metadata, conformance corpus, and ANTLR grammar.

## Layout

| Path | Purpose |
|------|---------|
| `grammar/` | ANTLR 4 lexer/parser (`.g4`) |
| `data/rules.yaml` | Rule catalog (codes, severity, messages) |
| `data/commands.yaml` | Built-in commands, deprecations, security patterns |
| `data/expansion.yaml` | `%` / `!` / `%~` expansion rules |
| `schema/` | JSON Schema for YAML validation |
| `corpus/` | Committed `.cmd` fixtures + `expect.json` oracles |
| `audit/` | Reference matrix, cmd.exe help captures, audit baselines |

## Authoring a corpus case

Create `spec/corpus/<category>/<case-id>/`:

```
input.cmd      # Batch source under test
expect.json    # Expected diagnostics
```

Example `expect.json`:

```json
{
  "description": "Mismatched double quotes (E009)",
  "rules": ["E009"],
  "lines": { "2": ["E009"] },
  "must_not": [],
  "config": {},
  "tags": ["syntax", "quotes"]
}
```

Optional `expect.json` fields for cmd.exe oracle (`cmd_oracle.py`):

| Field | Purpose |
|-------|---------|
| `"oracle": "skip"` | Always skip execution (static-only fixture) |
| `"oracle": "run"` | Bypass content heuristics and always run |
| `"oracle_timeout_s": 10` | Per-case timeout override (seconds) |

Skip policy tiers (in order): `oracle=skip` → `oracle=run` (bypass heuristics) → [`corpus/meta/oracle-skip.yaml`](corpus/meta/oracle-skip.yaml) denylist → content heuristics in `cmd_oracle.py` → run.

## Code generation

```bash
py scripts/spec/generate_rules.py      # rules.yaml -> src/blinter/rules/registry.py
py scripts/spec/generate_parser.py     # grammar -> src/blinter/generated/
py scripts/spec/generate_expansion.py  # expansion.yaml -> expansion_data.py
py scripts/spec/generate_commands.py   # commands.yaml -> patterns.py (SSOT tables)
py scripts/spec/generate_docs.py       # rules.yaml -> docs rule catalog sections
py scripts/spec/generate_grammar_rules.py  # rules.yaml grammar_nodes -> grammar_rules.py
py scripts/spec/validate_spec.py       # Validate all YAML against schemas
py scripts/spec/validate_corpus.py     # Validate corpus fixtures
py scripts/spec/audit_ssot.py          # SSOT drift and coverage audit
py scripts/spec/seed_corpus_cases.py   # Seed additional corpus fixtures
py scripts/spec/cmd_oracle.py          # Windows cmd.exe smoke oracle (safe subset only)
py scripts/spec/cmd_oracle.py --dry-run  # list runnable/skipped cases without executing
```

Use `--check` on generators to verify committed artifacts are up to date (CI).

## SSOT audit

```bash
py scripts/spec/audit_ssot.py              # human-readable report
py scripts/spec/audit_ssot.py --strict     # fail on error-level drift (CI)
```

The audit enforces full rule corpus coverage, E-rule 100% coverage, `reference-matrix.yaml` integrity, grammar_nodes drift checks, and SSOT drift between YAML and generated Python artifacts.

See `spec/audit/reference-matrix.yaml` and `spec/audit/cmd-help/` for batch language references. See `docs/Batch-Language-Reference.md` for the authoritative source list.

## Parser limitations

The ANTLR grammar models **static structure** for linting (quotes, blocks, expansions).
It does not execute batch or replicate full cmd.exe expansion phases. See `spec/grammar/`
for supported constructs per phase.
