"""Tests for thread safety and concurrent operations."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import gc
import os
import tempfile
import time
from typing import List

from blinter import LintIssue, lint_batch_file, read_file_with_encoding


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


class TestPerformance:
    """Test performance characteristics."""

    def test_large_file_performance(self) -> None:
        """Test performance with large files."""
        # Create a large batch file
        lines = ["@ECHO OFF", "SETLOCAL"]

        # Add many operations
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

            start_time = time.time()
            issues = lint_batch_file(temp_path)
            end_time = time.time()

            # Should complete within reasonable time (adjust as needed)
            processing_time = end_time - start_time
            assert (
                processing_time < 10.0
            ), f"Large file took too long: {processing_time}s"

            # Should find issues but not crash
            assert isinstance(issues, list)
            print(
                f"Large file ({len(lines)} lines) processed in "
                f"{processing_time:.2f}s with {len(issues)} issues"
            )

        finally:
            os.unlink(temp_path)

    def test_memory_efficiency(self) -> None:
        """Test memory efficiency with multiple files."""

        # Create multiple files and process them
        test_files = []
        try:
            for i in range(20):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".bat", delete=False
                ) as temp_file:
                    content = "@ECHO OFF\n" + f"echo File {i}\n" * 50 + "EXIT /B 0\n"
                    temp_file.write(content)
                    test_files.append(temp_file.name)

            # Process files and check memory doesn't grow excessively
            initial_objects = len(gc.get_objects())

            all_issues = []
            for file_path in test_files:
                issues = lint_batch_file(file_path)
                all_issues.extend(issues)

            final_objects = len(gc.get_objects())
            object_growth = final_objects - initial_objects

            # Memory growth should be reasonable
            assert object_growth < 10000, f"Excessive object growth: {object_growth}"
            print(f"Processed {len(test_files)} files, object growth: {object_growth}")

        finally:
            for file_path in test_files:
                try:
                    os.unlink(file_path)
                except OSError:
                    pass
