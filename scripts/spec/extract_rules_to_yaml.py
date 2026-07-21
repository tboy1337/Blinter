#!/usr/bin/env python3
"""One-time helper: export blinter.rules.registry RULES to spec/data/rules.yaml."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from _paths import REPO_ROOT, RULES_YAML  # noqa: E402

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from blinter.models import RuleSeverity  # noqa: E402
from blinter.rules.registry import RULES  # noqa: E402


def _rule_to_dict(rule: object) -> dict[str, object]:
    from blinter.models import Rule

    if not isinstance(rule, Rule):
        raise TypeError(f"Expected Rule, got {type(rule)}")
    return {
        "code": rule.code,
        "name": rule.name,
        "severity": rule.severity.name,
        "explanation": rule.explanation,
        "recommendation": rule.recommendation,
        "checker": "ast",
    }


def main() -> None:
    """Write rules.yaml from the current Python registry."""
    rules_list = [_rule_to_dict(rule) for rule in RULES.values()]
    rules_list.sort(key=lambda item: str(item["code"]))
    payload = {
        "version": 1,
        "rules": rules_list,
    }
    RULES_YAML.parent.mkdir(parents=True, exist_ok=True)
    RULES_YAML.write_text(
        yaml.dump(payload, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    print(f"Wrote {len(rules_list)} rules to {RULES_YAML}")


if __name__ == "__main__":
    main()
