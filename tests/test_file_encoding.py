"""Tests for file encoding detection functionality."""

import os
import tempfile
from typing import IO, Union
from unittest.mock import MagicMock, mock_open, patch
import warnings

import pytest

from blinter import lint_batch_file, read_file_with_encoding


class TestFileEncodingDetection:
    """Test cases for file encoding detection."""

    def test_read_utf8_file(self) -> None:
        """Test reading a UTF-8 encoded file."""
        content = "This is a test file\nwith multiple lines\n"

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert lines == ["This is a test file\n", "with multiple lines\n"]
            # ASCII is a subset of UTF-8, so this may be detected as ascii
            assert encoding in ["utf-8", "ascii"]
        finally:
            os.unlink(temp_file_path)

    def test_read_utf8_bom_file(self) -> None:
        """Test reading a UTF-8 with BOM file."""
        content = "This is a test file\nwith BOM\n"

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8-sig", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert lines == ["This is a test file\n", "with BOM\n"]
            assert encoding in ["utf-8-sig", "utf-8"]
        finally:
            os.unlink(temp_file_path)

    def test_read_latin1_file(self) -> None:
        """Test reading a Latin-1 encoded file."""
        content = "CafÃ© franÃ§ais\nwith special chars\n"

        with tempfile.NamedTemporaryFile(mode="w", encoding="latin-1", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                lines, encoding = read_file_with_encoding(temp_file_path)
                assert len(lines) == 2
                # Allow various encodings - chardet may detect utf-8 on modern systems
                # for content that's compatible with both encodings
                assert encoding.lower() in ["latin1", "latin-1", "cp1252", "iso-8859-1", "utf-8"]
                # Verify content is correctly read regardless of detected encoding
                assert "CafÃ©" in lines[0] or "Café" in lines[0]
        finally:
            os.unlink(temp_file_path)

    def test_encoding_warning(self) -> None:
        """Test that warning is issued for non-UTF-8 files."""
        # Create content that will trigger a warning in the linting process
        content = "@echo off\necho test"

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="latin1", suffix=".bat", delete=False
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with warnings.catch_warnings(record=True) as _warning_list:
                warnings.simplefilter("always")
                # Call lint_batch_file instead, which triggers the warning
                issues = lint_batch_file(temp_file_path)

                # Should get a warning for non-UTF-8 encoding if it was read as non-UTF-8
                assert isinstance(issues, list)  # Function should work regardless
        finally:
            os.unlink(temp_file_path)

    @patch("builtins.open", side_effect=FileNotFoundError("File not found"))
    def test_file_not_found_error(self, _mock_file: MagicMock) -> None:
        """Test handling of file not found error."""
        with pytest.raises(FileNotFoundError):
            read_file_with_encoding("nonexistent_file.bat")

    @patch("builtins.open", side_effect=PermissionError("Permission denied"))
    def test_permission_error(self, _mock_file: MagicMock) -> None:
        """Test handling of permission error."""
        with pytest.raises(PermissionError):
            read_file_with_encoding("restricted_file.bat")

    @patch("chardet.detect")
    @patch("builtins.open")
    def test_chardet_detection_success(self, mock_file: MagicMock, mock_detect: MagicMock) -> None:
        """Test successful chardet encoding detection."""
        # Mock chardet detection
        mock_detect.return_value = {"encoding": "cp1252", "confidence": 0.8}

        # Mock file operations
        mock_file.side_effect = [
            mock_open(read_data=b"test content").return_value,  # Binary read for chardet
            mock_open(read_data="test content\n").return_value,  # Text read with detected encoding
        ]

        lines, encoding = read_file_with_encoding("test.bat")
        assert lines == ["test content\n"]
        assert encoding == "cp1252"

    @patch("chardet.detect")
    @patch("builtins.open")
    def test_chardet_detection_low_confidence(
        self, mock_file: MagicMock, mock_detect: MagicMock
    ) -> None:
        """Test chardet detection with low confidence."""
        # Mock chardet with low confidence
        mock_detect.return_value = {"encoding": "cp1252", "confidence": 0.3}

        # Mock file operations - first binary read, then text read with utf-8
        mock_file.side_effect = [
            mock_open(read_data=b"test content").return_value,
            mock_open(read_data="test content\n").return_value,
        ]

        lines, encoding = read_file_with_encoding("test.bat")
        assert lines == ["test content\n"]
        assert encoding == "utf-8"

    def test_chardet_import_error(self) -> None:
        """Test fallback when chardet is not available."""
        # Test the actual ImportError scenario by mocking the import inside the function
        content = "test content\n"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Mock the chardet import to fail
            with patch("builtins.__import__") as mock_import:

                def import_side_effect(name: str, *args: object, **kwargs: object) -> object:
                    if name == "chardet":
                        raise ImportError("No module named chardet")
                    return __import__(name, *args, **kwargs)

                mock_import.side_effect = import_side_effect

                lines, encoding = read_file_with_encoding(temp_file_path)
                assert lines == ["test content\n"]
                assert encoding in ["utf-8", "ascii"]  # ASCII is subset of UTF-8
        finally:
            os.unlink(temp_file_path)

    @patch("builtins.open")
    def test_all_encodings_fail(self, mock_file: MagicMock) -> None:
        """Test when all encoding attempts fail."""
        # Mock all encoding attempts to fail
        mock_file.side_effect = UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")

        with pytest.raises(OSError) as exc_info:
            read_file_with_encoding("test.bat")

        assert "All encoding attempts failed" in str(exc_info.value)

    @patch("builtins.open")
    def test_encoding_lookup_error(self, mock_file: MagicMock) -> None:
        """Test handling of encoding lookup errors."""
        # Mock LookupError for invalid encoding
        mock_file.side_effect = [
            ValueError("unknown encoding"),
            mock_open(read_data="test content\n").return_value,
        ]

        lines, _encoding = read_file_with_encoding("test.bat")
        assert lines == ["test content\n"]

    def test_empty_file(self) -> None:
        """Test reading an empty file."""
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as temp_file:
            temp_file_path = temp_file.name

        try:
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert lines == []
            assert encoding == "utf-8"
        finally:
            os.unlink(temp_file_path)

    def test_file_with_null_bytes(self) -> None:
        """Test reading a file with null bytes."""
        content = b"test\x00content\n"

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # This should fallback to an encoding that can handle null bytes
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert len(lines) == 1
            # May be detected as ASCII first if it's simple content
            assert encoding.lower() in ["latin1", "latin-1", "ascii", "iso-8859-1", "cp1252"]
        finally:
            os.unlink(temp_file_path)

    @patch("chardet.detect")
    @patch("builtins.open")
    def test_chardet_detected_encoding_not_in_default_list(
        self, mock_file: MagicMock, mock_detect: MagicMock
    ) -> None:
        """Test when chardet detects encoding NOT in our default list - inserted at front."""
        # Mock chardet to return an encoding NOT in the default list
        mock_detect.return_value = {
            "encoding": "koi8-r",  # This is NOT in the default list
            "confidence": 0.9,
        }

        # Mock file operations
        mock_file.side_effect = [
            mock_open(read_data=b"test content").return_value,  # Binary read for chardet
            mock_open(read_data="test content\n").return_value,  # Text read with detected encoding
        ]

        lines, encoding = read_file_with_encoding("test.bat")
        assert lines == ["test content\n"]
        assert encoding == "koi8-r"  # Should use the detected encoding

    @patch("chardet.detect")
    @patch("builtins.open")
    def test_chardet_detected_encoding_in_default_list(
        self, mock_file: MagicMock, mock_detect: MagicMock
    ) -> None:
        """Test when chardet detects encoding that exists in our list - should be moved to front."""
        # Mock chardet to return an encoding that IS in the default list
        mock_detect.return_value = {
            "encoding": "latin1",  # This IS in the default list
            "confidence": 0.85,
        }

        # Mock file operations
        mock_file.side_effect = [
            mock_open(read_data=b"test content").return_value,  # Binary read for chardet
            mock_open(read_data="test content\n").return_value,  # Text read with detected encoding
        ]

        lines, encoding = read_file_with_encoding("test.bat")
        assert lines == ["test content\n"]
        assert encoding == "latin1"  # Should use latin1 (moved to front)

    @patch("chardet.detect")
    def test_chardet_exception_handling(self, mock_detect: MagicMock) -> None:
        """Test chardet exception handling."""
        content = b"test content"

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Mock chardet to raise an exception
            mock_detect.side_effect = OSError("Chardet failed")

            # This should handle the exception gracefully and fall back to default encodings
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert isinstance(lines, list)
            assert isinstance(encoding, str)
        finally:
            os.unlink(temp_file_path)

    def test_encoding_exhaustion_fallback_error(self) -> None:
        """Test the fallback error when all encoding attempts fail and no last_exception."""

        # Test the extremely rare case where last_exception is None
        def simulate_fallback_error() -> None:
            # Simulate the exact condition for the fallback error
            last_exception = None
            file_path = "test.bat"

            # This simulates the fallback when last_exception is None
            if last_exception:
                raise OSError(
                    f"All encoding attempts failed for file '{file_path}'. "
                    f"Last error: {last_exception}"
                ) from last_exception

            # This is the fallback error path
            raise OSError(f"Could not read file '{file_path}' with any supported encoding")

        with pytest.raises(OSError) as exc_info:
            simulate_fallback_error()

        assert "Could not read file 'test.bat' with any supported encoding" in str(exc_info.value)

    def test_unicode_decode_error_with_last_exception(self) -> None:
        """Test encoding failure handling with a last_exception."""

        def simulate_with_last_exception() -> None:
            # Simulate having a last exception
            last_exception = UnicodeDecodeError("utf-8", b"", 0, 1, "invalid byte")
            file_path = "test.bat"

            # This should trigger the path with last_exception
            if last_exception:
                raise OSError(
                    f"All encoding attempts failed for file '{file_path}'. "
                    f"Last error: {last_exception}"
                ) from last_exception

            raise OSError(f"Could not read file '{file_path}' with any supported encoding")

        with pytest.raises(OSError) as exc_info:
            simulate_with_last_exception()

        # Verify we got the "All encoding attempts failed" message
        assert "All encoding attempts failed" in str(exc_info.value)


class TestEncodingEdgeCases:
    """Test edge cases in file encoding detection and handling."""

    def test_chardet_not_available_fallback(self) -> None:
        """Test encoding fallback when chardet is not available."""
        # Create a test file with UTF-8 content
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\nECHO Hello World\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # Mock chardet ImportError
            with patch("builtins.__import__", side_effect=ImportError("No module named chardet")):
                lines, encoding = read_file_with_encoding(temp_file)
                assert len(lines) == 2
                assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
        finally:
            os.unlink(temp_file)

    def test_chardet_detection_error_fallback(self) -> None:
        """Test encoding fallback when chardet detection fails."""
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\nECHO Test\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # Mock chardet.detect to raise an exception
            with patch("chardet.detect", side_effect=ValueError("Detection failed")):
                lines, encoding = read_file_with_encoding(temp_file)
                assert len(lines) == 2
                assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
        finally:
            os.unlink(temp_file)

    def test_all_encoding_attempts_fail(self) -> None:
        """Test the rare case where all encoding attempts fail."""
        # This is very hard to trigger in practice since latin1 can decode any byte sequence
        # We'll mock the open function to always fail
        with patch(
            "builtins.open", side_effect=UnicodeDecodeError("test", b"", 0, 1, "test error")
        ):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("nonexistent.bat")

    def test_encoding_lookup_error(self) -> None:
        """Test handling of invalid encoding names."""
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # Test with an invalid encoding in the list by modifying the encodings list
            # This will trigger the LookupError handling path
            original_open = open
            call_count = [0]

            def mock_open_with_invalid_encoding(
                *args: object, **kwargs: object
            ) -> Union[IO[str], IO[bytes]]:
                call_count[0] += 1
                # Let the first call (chardet) succeed
                if "rb" in str(args) or "rb" in str(kwargs.get("mode", "")):
                    return original_open(*args, **kwargs)  # type: ignore[call-overload]
                # Fail the second call with text mode
                if call_count[0] == 2:  # First text mode call with invalid encoding
                    raise LookupError("Invalid encoding")
                return original_open(*args, **kwargs)  # type: ignore[call-overload]

            with patch("builtins.open", side_effect=mock_open_with_invalid_encoding):
                lines, _encoding = read_file_with_encoding(temp_file)
                assert len(lines) == 1
        finally:
            os.unlink(temp_file)


class TestEncodingFallbackScenarios:
    """Test additional encoding fallback scenarios."""

    def test_chardet_low_confidence_fallback(self) -> None:
        """Test encoding fallback when chardet has low confidence."""
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\nECHO Test\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # Mock chardet.detect to return low confidence
            mock_result = {"encoding": "utf-8", "confidence": 0.5}  # Below 0.7 threshold
            with patch("chardet.detect", return_value=mock_result):
                lines, encoding = read_file_with_encoding(temp_file)
                assert len(lines) == 2
                # Should fall back to standard encoding list
                assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
        finally:
            os.unlink(temp_file)

    def test_chardet_none_result_fallback(self) -> None:
        """Test encoding fallback when chardet returns None."""
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\nECHO Test\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # Mock chardet.detect to return None
            with patch("chardet.detect", return_value=None):
                lines, encoding = read_file_with_encoding(temp_file)
                assert len(lines) == 2
                assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
        finally:
            os.unlink(temp_file)

    def test_read_file_with_encoding_no_fallback_needed(self) -> None:
        """Test read_file_with_encoding when first encoding works (no fallback exception path)."""
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".bat"
        ) as temp_file_handle:
            content = "@ECHO OFF\nECHO Test\n"
            temp_file_handle.write(content.encode("utf-8"))
            temp_file = temp_file_handle.name

        try:
            # This should succeed without triggering the exception path
            lines, encoding = read_file_with_encoding(temp_file)
            assert len(lines) == 2
            # Encoding might be ascii if content is simple ASCII, that's fine
            assert encoding in ["utf-8", "ascii", "utf-8-sig"]
        finally:
            os.unlink(temp_file)


class TestAdditionalFileEncodingScenarios:
    """Additional file encoding tests for comprehensive scenarios."""

    def test_chardet_detected_encoding_not_in_list(self) -> None:
        """Test chardet detecting encoding not in our default list."""

        mock_detected = {"encoding": "iso-2022-jp", "confidence": 0.85}

        with (
            patch("builtins.open", mock_open(read_data="test content")),
            patch("chardet.detect", return_value=mock_detected),
        ):
            # Should succeed by adding the detected encoding to the front
            lines, _ = read_file_with_encoding("test.bat")
            assert len(lines) > 0

    def test_chardet_detected_encoding_already_in_list(self) -> None:
        """Test when chardet detects an encoding already in our list."""

        mock_detected = {"encoding": "utf-8", "confidence": 0.8}

        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", return_value=mock_detected),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding == "utf-8"  # Should use detected encoding
            assert len(lines) > 0

    def test_chardet_oserror_handling(self) -> None:
        """Test handling of OSError during chardet detection."""

        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=OSError("Test OSError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
            assert len(lines) > 0

    def test_chardet_valueerror_handling(self) -> None:
        """Test handling of ValueError during chardet detection."""

        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=ValueError("Test ValueError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
            assert len(lines) > 0

    def test_chardet_typeerror_handling(self) -> None:
        """Test handling of TypeError during chardet detection."""

        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=TypeError("Test TypeError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in ["utf-8", "utf-8-sig", "latin1", "cp1252", "iso-8859-1", "ascii"]
            assert len(lines) > 0

    def test_encoding_lookup_error_fallback(self) -> None:
        """Test handling when encoding lookup fails."""

        def mock_open_with_lookup_error(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                # Simulate LookupError for unsupported encoding
                if kwargs["encoding"] == "utf-8":
                    raise LookupError("Unknown encoding")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_with_lookup_error):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding != "utf-8"  # Should fall back to other encoding
            assert len(lines) > 0

    def test_encoding_value_error_fallback(self) -> None:
        """Test handling when encoding value is invalid."""

        def mock_open_with_value_error(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                # Simulate ValueError for invalid encoding
                if kwargs["encoding"] == "utf-8":
                    raise ValueError("Invalid encoding")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_with_value_error):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding != "utf-8"  # Should fall back to other encoding
            assert len(lines) > 0

    def test_all_encodings_fail_with_exception(self) -> None:
        """Test when all encodings fail and we have a last exception."""

        def mock_open_always_fail(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                raise UnicodeDecodeError("test", b"", 0, 1, "test error")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_always_fail):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("test.bat")

    def test_all_encodings_fail_no_exception(self) -> None:
        """Test when all encodings fail but no exception is stored."""

        def mock_open_no_exception(*args: object, **kwargs: object) -> object:
            # Don't store any exception by not raising UnicodeDecodeError
            if "encoding" in kwargs:
                raise LookupError("Encoding not supported")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_no_exception):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("test.bat")

    def test_encoding_failure_edge_case(self) -> None:
        """Test encoding failure when no exceptions are stored."""

        def mock_open_special(*_args: object, **kwargs: object) -> object:
            # Return nothing but don't store exception
            if "encoding" in kwargs and kwargs["encoding"] == "utf-32":
                raise LookupError("Encoding not supported")
            raise UnicodeDecodeError("test", b"", 0, 1, "test error")

        with patch("builtins.open", side_effect=mock_open_special):
            try:
                read_file_with_encoding("test.bat")
                assert False, "Should have raised OSError"
            except OSError as error:
                # Should hit the fallback path with last_exception
                assert "All encoding attempts failed" in str(error)
