"""Package version resolution."""

from importlib.metadata import PackageNotFoundError, version
import logging
from pathlib import Path
import sys
from typing import cast

__author__ = "tboy1337"

__license__ = "AGPL-3.0-or-later"

_PACKAGE_NAME = "Blinter"

logger = logging.getLogger(__name__)


def _compiled_marker() -> object | None:
    """Return Nuitka's injected __compiled__ object when this module is compiled."""
    namespace = cast(dict[str, object], globals())
    compiled_raw = namespace.get("__compiled__")
    if compiled_raw is None:
        return None
    return compiled_raw


def _is_compiled() -> bool:
    """Return True inside a Nuitka binary (or a PyInstaller-compatible frozen exe)."""
    if _compiled_marker() is not None:
        return True
    frozen_raw: object = getattr(sys, "frozen", False)
    return frozen_raw is True


def _compiled_containing_dir() -> Path | None:
    """Return Nuitka's containing_dir when this module was compiled."""
    compiled = _compiled_marker()
    if compiled is None:
        return None
    containing_raw: object = getattr(compiled, "containing_dir", None)
    if containing_raw is None:
        return None
    return Path(str(containing_raw))


def _compiled_pyproject_candidates(package_dir: Path) -> tuple[Path, ...]:
    """Return pyproject.toml locations used inside a Nuitka onefile extract."""
    candidates: list[Path] = [
        package_dir / "pyproject.toml",
        package_dir.parent / "pyproject.toml",
    ]
    containing_dir = _compiled_containing_dir()
    if containing_dir is not None:
        candidates.append(containing_dir / "pyproject.toml")
    return tuple(candidates)


def _pyproject_path() -> Path:
    """Return pyproject.toml for source trees or Nuitka frozen bundles."""
    module_file = Path(__file__).resolve()
    package_dir = module_file.parent
    if _is_compiled():
        for candidate in _compiled_pyproject_candidates(package_dir):
            if candidate.is_file():
                logger.debug("Resolved bundled pyproject.toml at %s", candidate)
                return candidate
        fallback = package_dir / "pyproject.toml"
        logger.debug("No bundled pyproject.toml found; using %s", fallback)
        return fallback
    source_path = package_dir.parent.parent / "pyproject.toml"
    logger.debug("Resolved source pyproject.toml at %s", source_path)
    return source_path


def _fallback_version() -> str:
    """Read version from pyproject.toml when the package is not installed."""
    pyproject = _pyproject_path()
    if not pyproject.is_file():
        return "unknown"
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("version = "):
            return stripped.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def get_version() -> str:
    """Return the package version, preferring pyproject.toml when developing from source."""
    if _pyproject_path().is_file():
        pyproject_version = _fallback_version()
        if pyproject_version != "unknown":
            return pyproject_version
    try:
        return version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return _fallback_version()


__version__ = get_version()
