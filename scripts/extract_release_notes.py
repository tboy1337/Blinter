#!/usr/bin/env python3
"""Print the latest release-notes section from CHANGELOG.md to stdout."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
_SECTION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\].*$", re.MULTILINE)


def extract_latest_section(changelog_path: Path = _CHANGELOG) -> str:
    """Return markdown for the most recent version block in the changelog."""
    text = changelog_path.read_text(encoding="utf-8")
    matches = list(_SECTION_RE.finditer(text))
    if not matches:
        raise SystemExit(f"No version sections found in {changelog_path}")

    start = matches[0].start()
    end = matches[1].start() if len(matches) > 1 else len(text)
    section = text[start:end].strip()
    if not section:
        raise SystemExit("Latest changelog section is empty")
    return section


def main() -> None:
    sys.stdout.write(extract_latest_section())


if __name__ == "__main__":
    main()
