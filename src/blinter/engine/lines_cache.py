"""Thread-safe helpers for shared per-run batch file line caches."""

from pathlib import Path
import threading
from typing import Dict, List, Optional

_LINES_CACHE_LOCK = threading.Lock()


def get_cached_lines(
    lines_cache: Optional[Dict[Path, List[str]]],
    path: Path,
) -> Optional[List[str]]:
    """Return cached lines for path when lines_cache is set (thread-safe read)."""
    if lines_cache is None:
        return None
    resolved = path.resolve()
    with _LINES_CACHE_LOCK:
        cached = lines_cache.get(resolved)
        if cached is None:
            return None
        return list(cached)


def store_cached_lines(
    lines_cache: Dict[Path, List[str]],
    path: Path,
    lines: List[str],
) -> None:
    """Store lines for path in the shared cache (thread-safe write)."""
    resolved = path.resolve()
    with _LINES_CACHE_LOCK:
        lines_cache[resolved] = list(lines)
