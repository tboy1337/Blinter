#!/usr/bin/env python3
"""Benchmark Blinter lint performance on synthetic or real batch files."""

from __future__ import annotations

import argparse
import cProfile
import pstats
import statistics
import sys
import tempfile
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from blinter import lint_batch_file  # noqa: E402


def _generate_synthetic_file(line_count: int = 2838) -> Path:
    """Generate a realistic multi-section batch file for benchmarking."""
    lines = ["@echo off", "setlocal enabledelayedexpansion"]
    for index in range(line_count - 4):
        section = index % 7
        if section == 0:
            lines.append(f"set VAR{index}=C:\\temp\\value{index}.txt")
        elif section == 1:
            lines.append(f"if exist C:\\data\\file{index}.log echo found {index}")
        elif section == 2:
            lines.append(f"for %%a in (1 2 3) do echo %%a {index}")
        elif section == 3:
            lines.append(f"call :sub{index % 50} arg{index}")
        elif section == 4:
            lines.append(f"set /a TOTAL=TOTAL+{index % 10}")
        elif section == 5:
            lines.append(f"echo Processing item {index} && echo done {index}")
        else:
            lines.append(f"echo line {index} >nul")
    lines.extend(["endlocal", "exit /b 0"])

    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".bat",
        delete=False,
        encoding="utf-8",
    )
    temp_file.write("\n".join(lines))
    temp_file.close()
    return Path(temp_file.name)


def _run_timed_lint(file_path: Path) -> float:
    start = time.perf_counter()
    lint_batch_file(str(file_path))
    return time.perf_counter() - start


def _print_profile(file_path: Path, top_n: int) -> None:
    profiler = cProfile.Profile()

    def _profiled_lint() -> None:
        lint_batch_file(str(file_path))

    profiler.runcall(_profiled_lint)
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    stats.print_stats(top_n)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Blinter lint performance.")
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a .bat/.cmd file (default: generate synthetic file)",
    )
    parser.add_argument(
        "--lines",
        type=int,
        default=2838,
        help="Line count for synthetic file when no path is given (default: 2838)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of timed runs (default: 3)",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Run cProfile and print top functions by cumulative time",
    )
    parser.add_argument(
        "--profile-top",
        type=int,
        default=20,
        help="Number of profile rows to print (default: 20)",
    )
    args = parser.parse_args()

    generated = False
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"File not found: {file_path}", file=sys.stderr)
            return 1
    else:
        file_path = _generate_synthetic_file(args.lines)
        generated = True
        print(f"Generated synthetic file: {file_path} ({args.lines} lines)")

    try:
        durations = [_run_timed_lint(file_path) for _ in range(args.runs)]
        median = statistics.median(durations)
        print(f"File: {file_path}")
        print(f"Runs: {args.runs}")
        print("Timings (seconds): " + ", ".join(f"{value:.3f}" for value in durations))
        print(f"Median: {median:.3f}s")

        if args.profile:
            print()
            _print_profile(file_path, args.profile_top)
    finally:
        if generated:
            file_path.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
