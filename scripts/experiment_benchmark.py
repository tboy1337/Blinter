#!/usr/bin/env python3
"""Interleaved A/B benchmark for SST performance experiment."""

from __future__ import annotations

import argparse
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

MAIN_ROOT = Path(__file__).resolve().parent.parent.parent / "Blinter"
SST_ROOT = Path(__file__).resolve().parent.parent.parent / "Blinter-sst-wt"
EXPERIMENT_ROOT = Path(__file__).resolve().parent.parent


def _generate_synthetic_file(line_count: int = 2838) -> Path:
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


def _discover_corpus_files(corpus_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in corpus_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
    )


def _lint_once(repo_root: Path, target: Path | list[Path]) -> float:
    src_root = str((repo_root / "src").resolve())
    script = f"""
import sys
import time
sys.path.insert(0, {src_root!r})
from blinter import lint_batch_file

targets = [p.strip() for p in sys.argv[1:] if p.strip()]
start = time.perf_counter()
for target in targets:
    lint_batch_file(target)
elapsed = time.perf_counter() - start
print(elapsed)
"""
    args = [sys.executable, "-c", script]
    if isinstance(target, list):
        args.extend(str(path) for path in target)
    else:
        args.append(str(target))
    result = subprocess.run(
        args,
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return float(result.stdout.strip().splitlines()[-1])


def _run_interleaved(
    *,
    main_root: Path,
    sst_root: Path,
    target: Path | list[Path],
    runs: int,
    label: str,
) -> dict[str, object]:
    main_times: list[float] = []
    sst_times: list[float] = []
    for run_index in range(runs):
        for branch, bucket, root in (
            ("main", main_times, main_root),
            ("sst", sst_times, sst_root),
        ):
            elapsed = _lint_once(root, target)
            bucket.append(elapsed)
            print(
                f"{label} run {run_index + 1}/{runs} {branch}: {elapsed:.3f}s",
                flush=True,
            )
    measured_main = main_times[1:] if len(main_times) > 1 else main_times
    measured_sst = sst_times[1:] if len(sst_times) > 1 else sst_times
    main_median = statistics.median(measured_main)
    sst_median = statistics.median(measured_sst)
    ratio = sst_median / main_median if main_median else float("inf")
    return {
        "label": label,
        "main_times": main_times,
        "sst_times": sst_times,
        "main_median": main_median,
        "sst_median": sst_median,
        "main_min": min(measured_main),
        "sst_min": min(measured_sst),
        "ratio": ratio,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Interleaved SST experiment benchmark")
    parser.add_argument("--runs", type=int, default=11)
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=MAIN_ROOT / "batch-script-examples",
    )
    parser.add_argument(
        "--main-root",
        type=Path,
        default=MAIN_ROOT,
    )
    parser.add_argument(
        "--sst-root",
        type=Path,
        default=SST_ROOT,
    )
    args = parser.parse_args()

    synthetic = _generate_synthetic_file()
    try:
        synthetic_result = _run_interleaved(
            main_root=args.main_root,
            sst_root=args.sst_root,
            target=synthetic,
            runs=args.runs,
            label="synthetic",
        )
        corpus_files = _discover_corpus_files(args.corpus_dir)
        if not corpus_files:
            raise SystemExit(f"No corpus files found in {args.corpus_dir}")
        corpus_result = _run_interleaved(
            main_root=args.main_root,
            sst_root=args.sst_root,
            target=corpus_files,
            runs=args.runs,
            label=f"corpus({len(corpus_files)} files)",
        )
    finally:
        synthetic.unlink(missing_ok=True)

    for result in (synthetic_result, corpus_result):
        print()
        print(f"=== {result['label']} ===")
        print(f"main median (runs 2-{args.runs}): {result['main_median']:.3f}s")
        print(f"sst  median (runs 2-{args.runs}): {result['sst_median']:.3f}s")
        print(f"main min: {result['main_min']:.3f}s")
        print(f"sst  min: {result['sst_min']:.3f}s")
        print(f"ratio (sst/main): {result['ratio']:.3f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
