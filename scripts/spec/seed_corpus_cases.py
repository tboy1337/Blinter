#!/usr/bin/env python3
"""Seed spec/corpus syntax and integration cases for SSOT audit coverage."""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_CORPUS = _REPO / "spec" / "corpus"

_CASES: dict[str, tuple[str, str, list[str]]] = {
    # id -> (category, input.cmd content, tags)
    "syntax/e001-nested-parens": (
        "syntax",
        "@echo off\nIF (1==1 (\necho bad\n)\n",
        ["syntax", "quotes"],
    ),
    "syntax/e002-missing-label": (
        "syntax",
        "@echo off\ngoto missing_label\n",
        ["syntax", "control-flow"],
    ),
    "syntax/e003-if-format": (
        "syntax",
        "@echo off\nIF%1==1 echo bad\n",
        ["syntax"],
    ),
    "syntax/e004-if-exist-mix": (
        "syntax",
        "@echo off\nIF EXIST file.txt == yes echo bad\n",
        ["syntax"],
    ),
    "syntax/e005-invalid-path": (
        "syntax",
        "@echo off\ncopy C:\\test<>\\file.txt dest\n",
        ["syntax"],
    ),
    "syntax/e007-empty-var-check": (
        "syntax",
        "@echo off\nIF %UNSET%== echo bad\n",
        ["syntax", "expansion"],
    ),
    "syntax/e010-for-missing-do": (
        "syntax",
        "@echo off\nFOR %%i IN (a b) echo %%i\n",
        ["syntax"],
    ),
    "syntax/e012-missing-call": (
        "syntax",
        "@echo off\n:sub\necho hi\nexit /b 0\n:main\nsub\n",
        ["syntax", "control-flow"],
    ),
    "syntax/e014-call-missing-colon": (
        "syntax",
        "@echo off\nCALL sub\n:sub\nexit /b 0\n",
        ["syntax"],
    ),
    "syntax/e015-goto-eof-missing-colon": (
        "syntax",
        "@echo off\ngoto EOF\n",
        ["syntax"],
    ),
    "syntax/e016-errorlevel-syntax": (
        "syntax",
        "@echo off\nIF %ERRORLEVEL% 1 echo bad\n",
        ["syntax"],
    ),
    "syntax/e018-unix-endings": (
        "syntax",
        "@echo off\necho test\n",
        ["syntax"],
    ),
    "syntax/e019-tilde-wrong-param": (
        "syntax",
        "@echo off\necho %~nUNDEFINED%\n",
        ["syntax", "expansion"],
    ),
    "syntax/e020-for-var-single-percent": (
        "syntax",
        "@echo off\nFOR %i IN (a) DO echo %i\n",
        ["syntax"],
    ),
    "syntax/e021-string-substring-invalid": (
        "syntax",
        "@echo off\nset x=hello\necho %x:~a,b%\n",
        ["syntax", "expansion"],
    ),
    "syntax/e021-string-substring-valid": (
        "syntax",
        "@echo off\nset x=hello\necho %x:~0,2%\n",
        ["syntax", "expansion"],
    ),
    "syntax/e022-set-a-invalid": (
        "syntax",
        "@echo off\nset /a x=1+++\n",
        ["syntax"],
    ),
    "syntax/e023-set-a-unquoted": (
        "syntax",
        "@echo off\nset /a x=5^2\n",
        ["syntax"],
    ),
    "syntax/e024-invalid-modifier-combo": (
        "syntax",
        "@echo off\necho %~q1%\n",
        ["syntax", "expansion"],
    ),
    "syntax/e025-tilde-wrong-context": (
        "syntax",
        "@echo off\necho %~dPATH%\n",
        ["syntax", "expansion"],
    ),
    "syntax/e027-unc-cd": (
        "syntax",
        "@echo off\ncd \\\\server\\share\n",
        ["syntax"],
    ),
    "syntax/e028-complex-quotes": (
        "syntax",
        '@echo off\necho "unclosed\n',
        ["syntax", "quotes"],
    ),
    "syntax/e034-removed-command": (
        "syntax",
        "@echo off\ndiskcomp a: b:\n",
        ["syntax"],
    ),
    "syntax/for-in-parens-valid": (
        "syntax",
        "@echo off\nFOR %%i IN (a b) DO echo %%i\n",
        ["syntax"],
    ),
    "syntax/if-errorlevel-ge": (
        "syntax",
        "@echo off\nIF ERRORLEVEL 1 echo failed\n",
        ["syntax"],
    ),
    "syntax/if-defined-var": (
        "syntax",
        "@echo off\nIF DEFINED MYVAR echo set\n",
        ["syntax"],
    ),
    "syntax/if-else-block": (
        "syntax",
        "@echo off\nIF 1==1 (echo yes) ELSE (echo no)\n",
        ["syntax", "control-flow"],
    ),
    "syntax/percent-tilde-dp0-valid": (
        "syntax",
        "@echo off\necho %~dp0\n",
        ["syntax", "expansion"],
    ),
    "syntax/w017-errorlevel-semantic": (
        "syntax",
        "@echo off\nIF %ERRORLEVEL% NEQ 1 echo note\n",
        ["syntax"],
    ),
    "syntax/w021-if-unquoted": (
        "syntax",
        "@echo off\nset v=hello world\nIF %v%==test echo bad\n",
        ["syntax"],
    ),
    "syntax/w024-deprecated-wmic": (
        "syntax",
        "@echo off\nwmic os get caption\n",
        ["syntax"],
    ),
    "integration/setlocal-delayed-expansion": (
        "integration",
        "@echo off\nsetlocal EnableDelayedExpansion\necho !count!\n",
        ["integration", "performance"],
    ),
    "integration/call-subroutine-e012": (
        "integration",
        "@echo off\nCALL :sub\nexit /b 0\n:sub\necho ok\nexit /b 0\n",
        ["integration", "control-flow"],
    ),
    "integration/w028-bat-errorlevel": (
        "integration",
        "@echo off\nset PATH=C:\\\n",
        ["integration"],
    ),
    "integration/w005-unquoted-var": (
        "integration",
        "@echo off\nset MSG=hello world\necho %MSG%\n",
        ["integration"],
    ),
    "integration/w013-duplicate-label": (
        "integration",
        "@echo off\n:dup\necho one\n:dup\necho two\n",
        ["integration", "control-flow"],
    ),
    "integration/p008-delayed-not-enabled": (
        "integration",
        "@echo off\necho !notenabled!\n",
        ["integration", "performance"],
    ),
    "integration/sec003-dangerous-del": (
        "integration",
        "@echo off\ndel /q *.*\n",
        ["integration"],
    ),
    "integration/s003-command-casing": (
        "integration",
        "@echo off\nECHO hello\nSET x=1\n",
        ["integration", "style"],
    ),
}


def main() -> None:
    for case_id, (category, content, _tags) in _CASES.items():
        case_dir = _CORPUS / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        input_path = case_dir / "input.cmd"
        if case_id == "syntax/e018-unix-endings":
            input_path.write_bytes(content.encode("utf-8").replace(b"\r\n", b"\n"))
        else:
            input_path.write_text(content, encoding="utf-8", newline="\r\n")
        print(f"Seeded {case_id} category={category}")


if __name__ == "__main__":
    main()
