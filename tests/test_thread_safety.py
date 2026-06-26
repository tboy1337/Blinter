"""Tests for thread safety and concurrent operations."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import tempfile
import threading
from typing import Dict, List

import pytest

from blinter import (
    BlinterConfig,
    LintIssue,
    lint_batch_file,
    read_file_with_encoding,
)
from blinter.engine.lines_cache import get_cached_lines, store_cached_lines


class TestLinesCache:
    """Tests for shared line cache defensive copying."""

    def test_lines_cache_returns_defensive_copy(self, tmp_path: Path) -> None:
        """Mutating a returned cache entry must not corrupt stored lines."""
        batch_file = tmp_path / "sample.bat"
        batch_file.write_text("@ECHO OFF\necho test\n", encoding="utf-8")
        cache: Dict[Path, List[str]] = {}
        original_lines = ["@ECHO OFF\n", "echo test\n"]

        store_cached_lines(cache, batch_file, original_lines)
        cached = get_cached_lines(cache, batch_file)
        assert cached is not None
        cached.append("mutated\n")

        cached_again = get_cached_lines(cache, batch_file)
        assert cached_again is not None
        assert len(cached_again) == 2
        assert "mutated\n" not in cached_again

    def test_store_cached_lines_copies_input(self, tmp_path: Path) -> None:
        """Mutating the source list after store must not corrupt the cache."""
        batch_file = tmp_path / "sample.bat"
        batch_file.write_text("@ECHO OFF\n", encoding="utf-8")
        cache: Dict[Path, List[str]] = {}
        lines = ["@ECHO OFF\n"]

        store_cached_lines(cache, batch_file, lines)
        lines.append("mutated\n")

        cached = get_cached_lines(cache, batch_file)
        assert cached is not None
        assert len(cached) == 1


class TestThreadSafety:
    """Test thread safety of blinter functions."""

    def test_concurrent_file_reading(self) -> None:
        """Test concurrent file reading with multiple threads."""
        # Create test files
        test_files = []
        try:
            for i in range(5):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".bat", delete=False
                ) as temp_file:
                    temp_file.write(f"@ECHO OFF\necho Test file {i}\nEXIT /B 0\n")
                    test_files.append(temp_file.name)

            def read_file_worker(file_path: str) -> tuple[list[str], str]:
                return read_file_with_encoding(file_path)

            # Test concurrent reading
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(read_file_worker, file_path)
                    for file_path in test_files
                ]
                results = [future.result() for future in as_completed(futures)]

            # All reads should succeed
            assert len(results) == 5
            for lines, encoding in results:
                assert isinstance(lines, list)
                assert isinstance(encoding, str)
                assert len(lines) >= 3  # Should have at least 3 lines

        finally:
            for file_path in test_files:
                try:
                    os.unlink(file_path)
                except OSError:
                    pass

    def test_concurrent_linting(self) -> None:
        """Test concurrent linting of multiple files."""
        # Create test files with different issues
        test_files = []
        try:
            test_contents = [
                "@ECHO OFF\necho test1\n",  # Clean file
                "echo test2\n",  # Missing @ECHO OFF
                "@ECHO OFF\necho %UNDEFINED%\n",  # Undefined variable
                "@ECHO OFF\necho test\ngoto missing\n",  # Missing label
                "@ECHO OFF\necho hello world  \n",  # Trailing whitespace
            ]

            for _, content in enumerate(test_contents):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".bat", delete=False
                ) as temp_file:
                    temp_file.write(content)
                    test_files.append(temp_file.name)

            def lint_worker(file_path: str) -> List[LintIssue]:
                return lint_batch_file(file_path)

            # Test concurrent linting
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(lint_worker, file_path) for file_path in test_files
                ]
                results = [future.result() for future in as_completed(futures)]

            # All linting operations should succeed
            assert len(results) == 5
            for issues in results:
                assert isinstance(issues, list)

        finally:
            for file_path in test_files:
                try:
                    os.unlink(file_path)
                except OSError:
                    pass

    def test_concurrent_same_file_access(self) -> None:
        """Test concurrent access to the same file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as temp_file:
            temp_file.write("@ECHO OFF\necho test\nEXIT /B 0\n")
            temp_path = temp_file.name

        try:

            def lint_same_file() -> List[LintIssue]:
                return lint_batch_file(temp_path)

            # Multiple threads accessing the same file
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(lint_same_file) for _ in range(20)]
                results = [future.result() for future in as_completed(futures)]

            # All results should be identical
            assert len(results) == 20
            first_result = results[0]
            for result in results[1:]:
                assert len(result) == len(first_result)
                # Results should be consistent
                for i, issue in enumerate(result):
                    assert issue.rule.code == first_result[i].rule.code
                    assert issue.line_number == first_result[i].line_number

        finally:
            os.unlink(temp_path)

    def test_thread_safety_with_stress(self) -> None:
        """Stress test thread safety with many concurrent operations."""
        # Create multiple test files
        test_files = []
        try:
            for i in range(10):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".bat", delete=False
                ) as temp_file:
                    # Create files with various issues
                    content = "@ECHO OFF\n"
                    if i % 2 == 0:
                        content += f"echo %VAR{i}%\n"  # Undefined variable
                    if i % 3 == 0:
                        content += f"goto :label{i}\n:label{i}\n"  # Good GOTO
                    else:
                        content += f"goto :missing{i}\n"  # Missing label
                    if i % 4 == 0:
                        content += "echo trailing space  \n"  # Trailing whitespace
                    content += "EXIT /B 0\n"

                    temp_file.write(content)
                    test_files.append(temp_file.name)

            def stress_worker() -> int:
                """Worker function that processes multiple files."""
                total_issues = 0
                for file_path in test_files:
                    issues = lint_batch_file(file_path)
                    total_issues += len(issues)
                return total_issues

            # Run stress test with many threads
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(stress_worker) for _ in range(50)]
                results = [future.result() for future in as_completed(futures)]

            # All stress tests should succeed
            assert len(results) == 50
            # Results should be consistent (all workers see the same issues)
            first_result = results[0]
            for result in results[1:]:
                assert (
                    result == first_result
                ), f"Inconsistent results: {result} != {first_result}"

        finally:
            for file_path in test_files:
                try:
                    os.unlink(file_path)
                except OSError:
                    pass

    def test_race_condition_prevention(self) -> None:
        """Test that race conditions are prevented in data structures."""
        # Test concurrent access to shared data structures
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as temp_file:
            # Create a complex file that exercises many code paths
            content = """@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

REM Test file with multiple constructs
SET "VAR1=value1"
SET "VAR2=value2"
SET "VAR3=value3"

:loop
echo Processing !VAR1!
echo Processing !VAR2!
echo Processing !VAR3!

IF EXIST file.txt (
    echo File exists
    goto process
) ELSE (
    echo File not found
    goto end
)

:process
echo Processing file
copy file.txt backup\\file.txt
del file.txt

:end
ENDLOCAL
EXIT /B 0
"""
            temp_file.write(content)
            temp_path = temp_file.name

        try:

            def concurrent_analysis() -> tuple[int, int, int, int]:
                """Perform concurrent analysis that might share data structures."""
                issues = lint_batch_file(temp_path)
                return (
                    len(issues),
                    len([i for i in issues if i.rule.severity.value == "Error"]),
                    len([i for i in issues if i.rule.severity.value == "Warning"]),
                    len([i for i in issues if i.rule.severity.value == "Style"]),
                )

            # Run many concurrent analyses
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(concurrent_analysis) for _ in range(100)]
                results = [future.result() for future in as_completed(futures)]

            # All results should be identical (no race conditions)
            assert len(results) == 100
            first_result = results[0]
            for result in results[1:]:
                assert (
                    result == first_result
                ), f"Race condition detected: {result} != {first_result}"

        finally:
            os.unlink(temp_path)

    def test_concurrent_shared_lines_cache_with_follow_calls(
        self, tmp_path: Path
    ) -> None:
        """Shared lines_cache must stay consistent under concurrent follow_calls linting."""
        caller = tmp_path / "caller.bat"
        helper = tmp_path / "helper.bat"
        caller.write_text(
            "@ECHO OFF\n" f'call "{helper.name}"\n' "echo %HELPER_VAR%\n",
            encoding="utf-8",
        )
        helper.write_text(
            '@ECHO OFF\nset "HELPER_VAR=ok"\n',
            encoding="utf-8",
        )
        shared_cache: Dict[Path, List[str]] = {}
        config = BlinterConfig(follow_calls=True, scan_root=str(tmp_path.resolve()))

        def lint_worker() -> int:
            issues = lint_batch_file(
                str(caller),
                config=config,
                lines_cache=shared_cache,
            )
            return len(issues)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(lint_worker) for _ in range(24)]
            results = [future.result() for future in as_completed(futures)]

        assert len(results) == 24
        assert len(set(results)) == 1
        assert caller.resolve() in shared_cache

    def test_concurrent_invocation_prefix_cache_isolation(self, tmp_path: Path) -> None:
        """Concurrent lints must not cross-contaminate invocation-prefix state."""
        called_content = """@ECHO OFF
CALL :MySub fifth
GOTO :EOF

:MySub
SET @V=%5& ECHO %@V%
GOTO :EOF
"""
        fallthrough_content = """@ECHO OFF
:first
echo between labels
:second
SET VAR=%1& ECHO %VAR%
GOTO :EOF
"""
        called_file = tmp_path / "called.bat"
        fallthrough_file = tmp_path / "fallthrough.bat"
        called_file.write_text(called_content, encoding="utf-8")
        fallthrough_file.write_text(fallthrough_content, encoding="utf-8")

        expected_called_codes = [
            issue.rule.code for issue in lint_batch_file(str(called_file))
        ]
        expected_fallthrough_codes = [
            issue.rule.code for issue in lint_batch_file(str(fallthrough_file))
        ]
        assert "SEC014" not in expected_called_codes
        assert "SEC014" in expected_fallthrough_codes

        barrier = threading.Barrier(8)
        errors: List[str] = []

        def lint_worker(file_path: Path, expected_has_sec014: bool) -> None:
            for _ in range(50):
                barrier.wait()
                rule_codes = [
                    issue.rule.code for issue in lint_batch_file(str(file_path))
                ]
                has_sec014 = "SEC014" in rule_codes
                if has_sec014 != expected_has_sec014:
                    errors.append(
                        f"{file_path.name}: SEC014={has_sec014}, "
                        f"expected {expected_has_sec014}, codes={rule_codes}"
                    )
                barrier.wait()

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for index in range(8):
                if index % 2 == 0:
                    futures.append(executor.submit(lint_worker, called_file, False))
                else:
                    futures.append(executor.submit(lint_worker, fallthrough_file, True))
            for future in as_completed(futures):
                future.result()

        assert not errors, "Invocation-prefix cache race detected:\n" + "\n".join(
            errors
        )

    def test_concurrent_lint_different_line_lengths(self) -> None:
        """Concurrent lint calls must not share mutable S020 rule state."""
        long_line = "echo " + ("x" * 120) + "\n"
        content = f"@ECHO OFF\n{long_line}"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:

            def lint_with_limit(max_line_length: int) -> List[LintIssue]:
                config = BlinterConfig(max_line_length=max_line_length)
                return lint_batch_file(temp_path, config=config)

            with ThreadPoolExecutor(max_workers=10) as executor:
                short_futures = [
                    executor.submit(lint_with_limit, 80) for _ in range(20)
                ]
                long_futures = [
                    executor.submit(lint_with_limit, 200) for _ in range(20)
                ]
                short_results = [future.result() for future in short_futures]
                long_results = [future.result() for future in long_futures]

            for issues in short_results:
                s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
                assert s020_issues, "Expected S020 for 80-character limit"
                assert all(
                    "80" in issue.context for issue in s020_issues
                ), f"Unexpected S020 context: {s020_issues[0].context}"

            for issues in long_results:
                s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
                assert not s020_issues, "Did not expect S020 for 200-character limit"

        finally:
            os.unlink(temp_path)


class TestPerformance:
    """Test performance characteristics."""

    @pytest.mark.slow
    @pytest.mark.timeout(120)
    def test_large_file_concurrent_lint_completes(self) -> None:
        """Test that large files lint successfully without timing assertions."""
        lines = ["@ECHO OFF", "SETLOCAL"]

        for i in range(1000):
            lines.append(f'SET "VAR{i}=value{i}"')
            lines.append(f"echo Processing VAR{i}: %VAR{i}%")
            if i % 100 == 0:
                lines.append(f":label{i}")
                lines.append(f"echo Reached checkpoint {i}")

        lines.extend(["ENDLOCAL", "EXIT /B 0"])
        content = "\n".join(lines)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            assert isinstance(issues, list)
            assert len(issues) >= 0
        finally:
            os.unlink(temp_path)

    def test_concurrent_lint_no_exceptions(self) -> None:
        """Concurrent linting of multiple files should complete without errors."""

        test_files = []
        try:
            for i in range(20):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".bat", delete=False
                ) as temp_file:
                    content = "@ECHO OFF\n" + f"echo File {i}\n" * 50 + "EXIT /B 0\n"
                    temp_file.write(content)
                    test_files.append(temp_file.name)

            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(lint_batch_file, file_path)
                    for file_path in test_files
                ]
                results = [future.result() for future in as_completed(futures)]

            assert len(results) == len(test_files)
            for issues in results:
                assert isinstance(issues, list)

        finally:
            for file_path in test_files:
                try:
                    os.unlink(file_path)
                except OSError:
                    pass
