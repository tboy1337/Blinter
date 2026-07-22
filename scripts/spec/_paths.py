"""Shared paths for spec tooling."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BATCH_SPEC_DIR = REPO_ROOT / "vendor" / "batch-spec"
SPEC_DIR = REPO_ROOT / "spec"
GRAMMAR_DIR = BATCH_SPEC_DIR / "grammar"
DATA_DIR = SPEC_DIR / "data"
BATCH_SPEC_DATA_DIR = BATCH_SPEC_DIR / "data"
SCHEMA_DIR = SPEC_DIR / "schema"
BATCH_SPEC_SCHEMA_DIR = BATCH_SPEC_DIR / "schema"
CORPUS_DIR = SPEC_DIR / "corpus"
RULES_YAML = DATA_DIR / "rules.yaml"
COMMANDS_LINTER_YAML = DATA_DIR / "commands-linter.yaml"
COMMANDS_LANGUAGE_YAML = BATCH_SPEC_DATA_DIR / "commands.yaml"
EXPANSION_YAML = BATCH_SPEC_DATA_DIR / "expansion.yaml"
BATCH_SPEC_LOCK = SPEC_DIR / "batch-spec.lock"
REGISTRY_PY = REPO_ROOT / "src" / "blinter" / "rules" / "registry.py"
GENERATED_DIR = REPO_ROOT / "src" / "blinter" / "generated"
REQUIREMENTS_MD = REPO_ROOT / "docs" / "Batch-File-Linter-Requirements.md"
AUDIT_DIR = SPEC_DIR / "audit"
BATCH_SPEC_AUDIT_DIR = BATCH_SPEC_DIR / "audit"
REFERENCE_MATRIX_YAML = AUDIT_DIR / "reference-matrix.yaml"
CHECKERS_DIR = REPO_ROOT / "src" / "blinter" / "checkers"
PARSING_DIR = REPO_ROOT / "src" / "blinter" / "parsing"
VISITORS_DIR = REPO_ROOT / "src" / "blinter" / "parsing" / "visitors"
RULE_IMPL_DIR = VISITORS_DIR / "rule_impl"
RULES_HELPERS_PY = REPO_ROOT / "src" / "blinter" / "rules" / "helpers.py"
EXPANSION_DATA_PY = REPO_ROOT / "src" / "blinter" / "rules" / "expansion_data.py"
PATTERNS_PY = REPO_ROOT / "src" / "blinter" / "patterns.py"
CORPUS_INDEX_YAML = CORPUS_DIR / "meta" / "corpus-index.yaml"

# Backward-compatible alias for scripts that still import COMMANDS_YAML
COMMANDS_YAML = COMMANDS_LINTER_YAML
