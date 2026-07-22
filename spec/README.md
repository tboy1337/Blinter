# Blinter Linter Specification

Blinter owns **linter** artifacts: rule catalog, security/style command policy, and the
202-case conformance corpus. The **batch language** SSOT lives in the pinned
[`batch-spec`](https://github.com/tboy1337/batch-spec) submodule at `vendor/batch-spec`.

## Submodule setup

```bash
git clone --recurse-submodules https://github.com/tboy1337/Blinter.git
# or after a plain clone:
git submodule update --init --recursive
```

The pinned release is recorded in [`batch-spec.lock`](batch-spec.lock) (currently `v0.2.1`).

## Layout

| Path | Purpose |
|------|---------|
| `data/rules.yaml` | Rule catalog (codes, severity, messages) |
| `data/commands-linter.yaml` | Linter policy: dangerous commands, casing, security patterns |
| `schema/` | JSON Schema for linter YAML validation |
| `corpus/` | Committed `.cmd` fixtures + `expect.json` oracles |
| `audit/` | Reference matrix and audit baselines |
| `batch-spec.lock` | Pinned batch-spec repo ref |

Language artifacts (grammar, expansion rules, command catalog, cmd-help captures, parse
conformance corpus) are in `vendor/batch-spec/`. See that repo's README for layout and
versioning.

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
py scripts/spec/generate_parser.py     # vendor/batch-spec/grammar -> src/blinter/generated/
py scripts/spec/generate_expansion.py  # vendor/batch-spec/data/expansion.yaml -> expansion_data.py
py scripts/spec/generate_commands.py   # merge language + linter YAML -> patterns.py
py scripts/spec/generate_docs.py       # rules.yaml -> docs rule catalog sections
py scripts/spec/generate_grammar_rules.py  # rules.yaml grammar_nodes -> grammar_rules.py
py scripts/spec/validate_spec.py       # Validate linter YAML + batch-spec language YAML
py scripts/spec/validate_corpus.py     # Validate corpus fixtures
py scripts/conformance/lint_corpus.py  # Linter corpus conformance (wraps validate_corpus.py)
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

The audit enforces full rule corpus coverage, E-rule 100% coverage, `reference-matrix.yaml`
integrity, grammar_nodes drift checks, and SSOT drift between YAML and generated Python
artifacts.

See `spec/audit/reference-matrix.yaml` and `vendor/batch-spec/audit/cmd-help/` for batch
language references. See `docs/Batch-Language-Reference.md` for the authoritative source list.

## Parser limitations

The ANTLR grammar in `vendor/batch-spec/grammar/` models **static structure** for linting
(quotes, blocks, expansions). It does not execute batch or replicate full cmd.exe expansion
phases. Runtime linting uses a fast syntax path; ANTLR remains available for tests and oracle
parity.
