#!/usr/bin/env python3
"""Run safe corpus fixtures through cmd.exe for behavioral smoke checks (Windows).

Part of the verification pipeline (see scripts/verify.py). Only fixtures that pass
strict static safety checks are executed. Destructive, interactive, or unbounded
corpus cases are listed in spec/corpus/meta/oracle-skip.yaml.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Literal

import yaml

_REPO = Path(__file__).resolve().parent.parent.parent
_CORPUS = _REPO / "spec" / "corpus"
_ORACLE_SKIP_YAML = _CORPUS / "meta" / "oracle-skip.yaml"
_DEFAULT_TIMEOUT_S = 3.0
# Smoke oracle: any exit code is acceptable if cmd.exe finishes (fixtures are often
# intentional error cases). Only timeouts count as failures.


def _corpus_inputs() -> list[Path]:
    """Return corpus primary inputs (input.cmd, or input.bat when no .cmd)."""
    inputs: list[Path] = []
    seen_dirs: set[Path] = set()
    for input_path in sorted(_CORPUS.glob("**/input.cmd")):
        inputs.append(input_path)
        seen_dirs.add(input_path.parent)
    for input_path in sorted(_CORPUS.glob("**/input.bat")):
        if input_path.parent in seen_dirs:
            continue
        inputs.append(input_path)
    return inputs


def _load_skip_ids() -> dict[str, str]:
    if not _ORACLE_SKIP_YAML.is_file():
        return {}
    data = yaml.safe_load(_ORACLE_SKIP_YAML.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    skip: dict[str, str] = {}
    for entry in data.get("cases", []):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("id", "")).strip().replace("\\", "/")
        reason = str(entry.get("reason", "listed in oracle-skip.yaml"))
        if case_id:
            skip[case_id] = reason
    return skip


def _expect_oracle_settings(
    case_dir: Path,
) -> tuple[Literal["run", "skip"] | None, float | None]:
    """Return (oracle mode override, per-case timeout override)."""
    expect_path = case_dir / "expect.json"
    if not expect_path.is_file():
        return None, None
    try:
        expect = json.loads(expect_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None, None
    mode = expect.get("oracle")
    oracle_mode: Literal["run", "skip"] | None = None
    if mode in {"run", "skip"}:
        oracle_mode = mode
    timeout_raw = expect.get("oracle_timeout_s")
    timeout_s: float | None = None
    if isinstance(timeout_raw, (int, float)) and float(timeout_raw) > 0:
        timeout_s = float(timeout_raw)
    return oracle_mode, timeout_s


def _call_unsafe_reason(text: str, case_dir: Path) -> str | None:
    """Flag CALL targets that may invoke external or uncontrolled scripts."""
    if not re.search(r"\bcall\b", text, re.IGNORECASE):
        return None
    for match in re.finditer(r"\bcall\s+(\S+)", text, re.IGNORECASE):
        target = str(match.group(1)).strip('"')
        if target.startswith(":"):
            continue
        if "%" in target or "!" in target:
            return "call with dynamic target"
        if re.search(r"[\\/]", target):
            return "call to path script"
        if re.search(r"\.[a-z]{1,4}$", target, re.IGNORECASE):
            if (case_dir / target).is_file():
                continue
            if target.lower().endswith((".com", ".exe", ".bat", ".cmd")):
                continue
            return "call may invoke external scripts"
        continue
    return None


def _content_unsafe_reason(text: str, case_dir: Path) -> str | None:
    """Return a reason when fixture content must not be executed."""
    lowered = text.lower()

    if re.search(r"\bstart\b", text, re.IGNORECASE):
        return "start command may spawn child processes/windows"

    if re.search(r"%~f0|%0\b", text, re.IGNORECASE):
        return "self-referential script path"

    if re.search(r"\bchoice\b", text, re.IGNORECASE):
        return "interactive choice"

    if re.search(r"\bpause\b", text, re.IGNORECASE):
        return "interactive pause"

    if re.search(r"\bping\b", text, re.IGNORECASE):
        count_match = re.search(r"ping\s+[^\n]*-n\s+(\d+)", text, re.IGNORECASE)
        if count_match:
            if int(count_match.group(1)) <= 3:
                pass
            else:
                return f"long ping delay (-n {count_match.group(1)})"
        else:
            return "unbounded ping"

    timeout_match = re.search(r"timeout\s+/t\s+(\d+)", text, re.IGNORECASE)
    if timeout_match and int(timeout_match.group(1)) > 2:
        return f"long timeout ({timeout_match.group(1)}s)"

    call_reason = _call_unsafe_reason(text, case_dir)
    if call_reason:
        return call_reason

    if re.search(r"\bpowershell\b", text, re.IGNORECASE):
        return "powershell"

    if re.search(r"\bcmd\s+/c\b", text, re.IGNORECASE):
        return "nested cmd"

    if re.search(r"\bnet\b", text, re.IGNORECASE):
        if re.search(r"\bnet\s+user\b", text, re.IGNORECASE) and re.search(
            r"/add", text, re.IGNORECASE
        ):
            return "net user /add"
        if re.search(r"\bnet\s+use\b", text, re.IGNORECASE):
            return "net use"

    if re.search(r"\btaskkill\b", text, re.IGNORECASE):
        return "taskkill"

    if re.search(r"\bdel\b", text, re.IGNORECASE):
        if re.search(r"\bdel\s+[^\n]*[*?]", text, re.IGNORECASE):
            return "del with wildcards"
        if re.search(r"\bdel\s+/[qs]", text, re.IGNORECASE):
            return "del with /q or /s"

    if re.search(r"\brmdir\b", text, re.IGNORECASE):
        return "rmdir"

    if re.search(r"\breg\b", text, re.IGNORECASE):
        if re.search(r"\breg\s+delete\b", text, re.IGNORECASE):
            return "reg delete"

    if re.search(r"\bwmic\b", text, re.IGNORECASE):
        if re.search(r"\bwmic\b[^\n]*\b(delete|call|create)\b", text, re.IGNORECASE):
            return "wmic mutating command"

    if re.search(r"\bshutdown\b", text, re.IGNORECASE):
        return "shutdown"

    if re.search(r":\s*(loop|retry)\b", text, re.IGNORECASE) and re.search(
        r"goto\s+(loop|retry)", text, re.IGNORECASE
    ):
        return "backward goto loop"

    if ":retry_loop" in lowered and "goto retry_loop" in lowered:
        return "infinite retry loop"

    return None


def _skip_reason(
    input_path: Path, case_id: str, skip_ids: dict[str, str]
) -> str | None:
    oracle_mode, _ = _expect_oracle_settings(input_path.parent)
    if oracle_mode == "skip":
        return "expect.json oracle=skip"

    if oracle_mode == "run":
        return None

    if case_id in skip_ids:
        return skip_ids[case_id]

    text = input_path.read_text(encoding="utf-8", errors="replace")
    unsafe = _content_unsafe_reason(text, input_path.parent)
    if unsafe:
        return unsafe

    return None


def _case_timeout_s(input_path: Path, default_timeout_s: float) -> float:
    _, override = _expect_oracle_settings(input_path.parent)
    if override is not None:
        return override
    return default_timeout_s


def _subprocess_kwargs() -> dict[str, object]:
    """Avoid flashing a console window for each cmd.exe invocation on Windows."""
    if sys.platform != "win32":
        return {}
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if create_no_window:
        return {"creationflags": create_no_window}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {"startupinfo": startupinfo}


def _kill_process_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill", "/F", "/T", "/PID", str(pid)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        **_subprocess_kwargs(),
    )


def _run_case(input_path: Path, timeout_s: float) -> int | Literal["TIMEOUT"]:
    kwargs = _subprocess_kwargs()
    proc = subprocess.Popen(
        ["cmd", "/c", input_path.name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(input_path.parent),
        **kwargs,
    )
    try:
        return proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc.pid)
        proc.kill()
        return "TIMEOUT"


def main() -> None:
    parser = argparse.ArgumentParser(description="cmd.exe oracle for corpus fixtures")
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max runnable cases (0 = all safe cases)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT_S,
        help=f"Per-case timeout in seconds (default {_DEFAULT_TIMEOUT_S})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List runnable and skipped cases without executing cmd.exe",
    )
    args = parser.parse_args()
    if sys.platform != "win32":
        print("cmd.exe oracle is Windows-only; skipping")
        return

    skip_ids = _load_skip_ids()
    runnable: list[Path] = []
    skipped: list[tuple[str, str]] = []
    for input_path in _corpus_inputs():
        case_id = "/".join(input_path.parent.relative_to(_CORPUS).parts)
        reason = _skip_reason(input_path, case_id, skip_ids)
        if reason:
            skipped.append((case_id, reason))
            continue
        runnable.append(input_path)

    if args.limit:
        runnable = runnable[: args.limit]

    print(
        f"cmd_oracle: {len(runnable)} runnable, {len(skipped)} skipped "
        f"(timeout={args.timeout}s)",
        flush=True,
    )

    if args.dry_run:
        for case_id, reason in skipped:
            print(f"SKIP {case_id} ({reason})", flush=True)
        for input_path in runnable:
            case_id = "/".join(input_path.parent.relative_to(_CORPUS).parts)
            print(f"RUN {case_id}", flush=True)
        return

    failures = 0
    for input_path in runnable:
        case_id = "/".join(input_path.parent.relative_to(_CORPUS).parts)
        timeout_s = _case_timeout_s(input_path, args.timeout)
        code = _run_case(input_path, timeout_s)
        if code == "TIMEOUT":
            failures += 1
            print(f"FAIL {case_id} exit=TIMEOUT", flush=True)
            continue
        print(f"OK {case_id} exit={code}", flush=True)

    print(f"cmd_oracle: skipped {len(skipped)} unsafe/static-only cases", flush=True)
    if failures:
        raise SystemExit(f"{failures} cmd.exe oracle failures")


if __name__ == "__main__":
    main()
