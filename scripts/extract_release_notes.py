#!/usr/bin/env python3
"""Print the latest release-notes section from CHANGELOG.md to stdout."""

from __future__ import annotations

from pathlib import Path
import re
import sys

_CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
_SECTION_RE = re.compile(r"^## \[[^\]]+\].*$", re.MULTILINE)


def _heading_version(heading: str) -> str:
    """Return the bracketed version label from a changelog heading line."""
    start = heading.find("[")
    end = heading.find("]", start + 1)
    if start < 0 or end < 0:
        return ""
    return heading[start + 1 : end]


def extract_latest_section(changelog_path: Path = _CHANGELOG) -> str:
    """Return markdown for the most recent versioned changelog section.

    ``## [Unreleased]`` headings are skipped so GitHub Releases publish the
    latest tagged version notes rather than in-progress work.
    """
    text = changelog_path.read_text(encoding="utf-8")
    matches = list(_SECTION_RE.finditer(text))
    versioned = [
        match
        for match in matches
        if _heading_version(text[match.start() : match.end()]).casefold()
        != "unreleased"
    ]
    if not versioned:
        raise SystemExit(f"No version sections found in {changelog_path}")

    start = versioned[0].start()
    following = [match for match in matches if match.start() > start]
    end = following[0].start() if following else len(text)
    section = text[start:end].strip()
    if not section:
        raise SystemExit("Latest changelog section is empty")
    return section


def main() -> None:
    sys.stdout.write(extract_latest_section())


if __name__ == "__main__":
    main()
