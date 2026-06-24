"""File encoding detection and line-ending analysis."""
from pathlib import Path
from typing import (
    List,
    Optional,
    Tuple,
    cast,
)
import warnings
from blinter.logging_config import logger

def _detect_line_endings(file_path: str) -> Tuple[str, bool, int, int, int]:
    """
    Detect line ending types in a batch file.

    This function analyzes the raw file content to determine what type of line endings
    are used, which is critical for batch file compatibility since Unix line endings
    can cause GOTO/CALL label parsing failures in Windows batch files.

    Thread-safe: Yes - uses only local variables and read-only file operations
    Performance: Optimized to read file in chunks for memory efficiency

    Args:
        file_path: Path to the file to analyze for line endings

    Returns:
        Tuple containing:
            - dominant_type: 'CRLF', 'LF', 'CR', or 'MIXED'
            - has_mixed: True if multiple line ending types found
            - crlf_count: Number of CRLF (\\r\\n) sequences found
            - lf_only_count: Number of standalone LF (\\n) found
            - cr_only_count: Number of standalone CR (\\r) found

    Raises:
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        OSError: If file operation fails due to system issues

    Example:
        >>> ending_type, mixed, crlf, lf, cr = _detect_line_endings("script.bat")
        >>> if ending_type == 'LF':
        ...     print("WARNING: Unix line endings detected!")
    """
    try:
        with open(file_path, "rb") as file_handle:
            content = file_handle.read()
    except (FileNotFoundError, PermissionError, OSError) as file_error:
        raise OSError(f"Cannot read file '{file_path}': {file_error}") from file_error

    # Count different line ending types
    crlf_count = content.count(b"\r\n")
    # Count LF that are NOT part of CRLF
    lf_total = content.count(b"\n")
    lf_only_count = lf_total - crlf_count
    # Count CR that are NOT part of CRLF
    cr_total = content.count(b"\r")
    cr_only_count = cr_total - crlf_count

    # Determine the dominant type and if mixed
    ending_types = []
    if crlf_count > 0:
        ending_types.append("CRLF")
    if lf_only_count > 0:
        ending_types.append("LF")
    if cr_only_count > 0:
        ending_types.append("CR")

    if not ending_types:
        # No line endings found (empty file or single line)
        dominant_type = "NONE"
        has_mixed = False
    elif len(ending_types) == 1:
        dominant_type = ending_types[0]
        has_mixed = False
    else:
        # Multiple types found
        dominant_type = "MIXED"
        has_mixed = True

    logger.debug(
        "Line ending analysis for %s: %s (CRLF: %d, LF-only: %d, CR-only: %d)",
        file_path,
        dominant_type,
        crlf_count,
        lf_only_count,
        cr_only_count,
    )

    return dominant_type, has_mixed, crlf_count, lf_only_count, cr_only_count

def _has_multibyte_chars(lines: List[str]) -> Tuple[bool, List[int]]:
    """
    Check for multi-byte UTF-8 characters in batch file lines.

    Multi-byte characters combined with Unix line endings can cause buffer
    parsing errors in Windows batch files due to parser boundary misalignment.

    Thread-safe: Yes - uses only local variables and immutable operations
    Performance: Processes lines efficiently without regex overhead

    Args:
        lines: List of strings representing file lines

    Returns:
        Tuple containing:
            - has_multibyte: True if any multi-byte characters found
            - affected_lines: List of line numbers (1-based) containing multi-byte chars

    Example:
        >>> has_mb, line_nums = _has_multibyte_chars(["echo Hello", "echo ═══"])
        >>> if has_mb:
        ...     print(f"Multi-byte chars found on lines: {line_nums}")
    """
    has_multibyte = False
    affected_lines: List[int] = []

    for line_num, line in enumerate(lines, start=1):
        # Check if line contains any characters that require more than 1 byte in UTF-8
        try:
            line_bytes = line.encode("utf-8")
            # If UTF-8 byte count > character count, there are multi-byte chars
            if len(line_bytes) > len(line):
                has_multibyte = True
                affected_lines.append(line_num)
        except UnicodeEncodeError:
            # If encoding fails, there are definitely non-ASCII chars
            has_multibyte = True
            affected_lines.append(line_num)

    return has_multibyte, affected_lines

def _detect_encoding_charset_norm(
    file_path: str, encodings_list: List[str]
) -> List[str]:
    """
    Detect file encoding using charset_normalizer library if available.

    Thread-safe: Yes - uses only local variables
    Performance: Single file read operation

    Args:
        file_path: Path to the file to analyze
        encodings_list: List of encodings to prioritize

    Returns:
        Updated list of encodings with detected encoding moved to front
    """
    try:
        # pylint: disable=import-outside-toplevel  # isort: skip
        from charset_normalizer import from_bytes

        with open(file_path, "rb") as file_handle:
            raw_data = file_handle.read()

        best_match = from_bytes(raw_data).best()  # type: ignore[misc]
        detected_match = cast(object, best_match)
        if detected_match is None:
            return encodings_list

        detected_encoding_raw: object = getattr(detected_match, "encoding", None)
        detected_coherence_raw: object = getattr(detected_match, "coherence", 0.0)
        if not isinstance(detected_encoding_raw, str):
            return encodings_list
        if not isinstance(detected_coherence_raw, (int, float)):
            return encodings_list
        if detected_coherence_raw <= 0.7:
            return encodings_list

        detected_encoding: str = detected_encoding_raw.lower()
        logger.debug(
            "charset_normalizer detected encoding: %s (coherence: %.2f)",
            detected_encoding,
            float(detected_coherence_raw),
        )

        # Add detected encoding to the front if not already there
        if detected_encoding not in [enc.lower() for enc in encodings_list]:
            encodings_list.insert(0, detected_encoding)
            return encodings_list

        # Move detected encoding to front if it exists in our list
        for i, enc in enumerate(encodings_list):
            if enc.lower() == detected_encoding:
                encodings_list.insert(0, encodings_list.pop(i))
                break

        return encodings_list

    except ImportError:
        logger.debug(
            "charset_normalizer not available, using fallback encoding detection"
        )
        return encodings_list
    except (OSError, ValueError, TypeError) as detection_error:
        logger.debug("Encoding detection failed: %s, using fallback", detection_error)
        return encodings_list

def _try_read_with_encoding(file_path: str, encoding: str) -> Optional[List[str]]:
    """
    Attempt to read a file with a specific encoding.

    Thread-safe: Yes - uses only local file operations
    Performance: Single file read operation

    Args:
        file_path: Path to the file to read
        encoding: Encoding to try

    Returns:
        List of lines if successful, None if encoding fails
    """
    try:
        logger.debug("Attempting to read file with encoding: %s", encoding)
        with open(file_path, "r", encoding=encoding, errors="strict") as file_handle:
            lines = file_handle.readlines()
        logger.debug(
            "Successfully read %d lines using %s encoding", len(lines), encoding
        )
        return lines
    except (UnicodeDecodeError, LookupError, ValueError) as error:
        logger.debug("Failed to read with %s: %s", encoding, error)
        return None

def read_file_with_encoding(file_path: str) -> Tuple[List[str], str]:
    """
    Reads a file with robust encoding detection and fallback mechanisms.

    This function implements a comprehensive encoding detection strategy:
    1. Attempts to use charset_normalizer for automatic detection (if available)
    2. Falls back to a prioritized list of common encodings
    3. Provides detailed error messages for troubleshooting

    Thread-safe: Yes - uses only local variables and immutable data
    Performance: Optimized for common cases (UTF-8 first)

    Args:
        file_path: Path to the file to read. Can be absolute or relative.

    Returns:
        Tuple containing:
            - lines: List of strings, each representing a line in the file
            - encoding_used: String indicating the encoding that was successful

    Raises:
        UnicodeDecodeError: If all encoding attempts fail (extremely rare)
        FileNotFoundError: If the specified file doesn't exist
        PermissionError: If insufficient permissions to read the file
        OSError: If file operation fails due to system issues

    Example:
        >>> lines, encoding = read_file_with_encoding("script.bat")
        >>> print(f"Read {len(lines)} lines using {encoding} encoding")
    """
    # List of encodings to try in order of preference
    encodings_to_try = [
        "utf-8",  # Standard UTF-8
        "utf-8-sig",  # UTF-8 with BOM
        "latin1",  # ISO 8859-1 (can decode any byte sequence)
        "cp1252",  # Windows-1252 (common Windows encoding)
        "iso-8859-1",  # ISO Latin-1
        "ascii",  # Basic ASCII
        "cp437",  # Original IBM PC encoding
        "utf-16",  # UTF-16 with BOM detection
        "utf-32",  # UTF-32 with BOM detection
    ]

    # Try to detect encoding using charset_normalizer if available
    encodings_to_try = _detect_encoding_charset_norm(file_path, encodings_to_try)

    # Try each encoding until one works
    for encoding in encodings_to_try:
        lines = _try_read_with_encoding(file_path, encoding)
        if lines is not None:
            return lines, encoding

    # If we get here, all encodings failed - this should be extremely rare
    raise OSError(
        f"All encoding attempts failed for file '{file_path}'. "
        f"Could not read file with any supported encoding"
    )

def _validate_and_read_file(file_path: str) -> Tuple[List[str], str]:
    """Validate file and read its contents.

    Returns:
        Tuple of (lines, encoding_used)
    """
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string")

    # Validate file exists and is accessible
    file_obj = Path(file_path)
    if not file_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not file_obj.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    # Check file size for performance warning
    file_size = file_obj.stat().st_size
    if file_size > 10 * 1024 * 1024:  # 10MB
        logger.warning(
            "Large file detected (%dMB). Processing may take longer.",
            file_size // 1024 // 1024,
        )

    lines, encoding_used = read_file_with_encoding(file_path)

    # Issue a warning if we had to fall back from UTF-8, but not for pure ASCII files
    if encoding_used.lower() not in ["utf-8", "utf-8-sig", "ascii"]:
        warnings.warn(
            f"File '{file_path}' was read using '{encoding_used}' encoding instead of UTF-8. "
            f"Consider converting the file to UTF-8 for better compatibility.",
            UserWarning,
            stacklevel=3,
        )
    elif encoding_used.lower() == "ascii":
        # Check if file contains non-ASCII characters (shouldn't happen with ASCII encoding)
        # Only warn if the file actually needs UTF-8 features
        file_content = "".join(lines)
        if any(ord(char) > 127 for char in file_content):
            warnings.warn(
                f"File '{file_path}' contains non-ASCII characters but was read as ASCII. "
                f"Consider converting the file to UTF-8 for proper character support.",
                UserWarning,
                stacklevel=3,
            )

    return lines, encoding_used
