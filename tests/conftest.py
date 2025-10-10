"""pytest configuration and shared fixtures for blinter tests."""

from typing import Generator
import warnings

from hypothesis import HealthCheck, Verbosity, settings
import pytest

try:
    import coverage.misc

    COVERAGE_AVAILABLE = True
except ImportError:
    COVERAGE_AVAILABLE = False

# Configure hypothesis settings globally
settings.register_profile(
    "default",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "ci",
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    verbosity=Verbosity.verbose,
)

settings.register_profile(
    "dev",
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    verbosity=Verbosity.normal,
)

# Load default profile
settings.load_profile("default")


@pytest.fixture(autouse=True)
def suppress_test_warnings() -> Generator[None, None, None]:
    """Suppress expected warnings during tests.

    These warnings are expected when testing various scenarios and
    should not clutter the test output.
    """
    # Suppress encoding warnings
    warnings.filterwarnings(
        "ignore",
        message="File .* was read using .* encoding instead of UTF-8.*",
        category=UserWarning,
    )

    # Suppress coverage warnings about configuration
    if COVERAGE_AVAILABLE:
        warnings.filterwarnings("ignore", category=coverage.misc.CoverageWarning)

    yield
    # Reset warnings after test
    warnings.resetwarnings()


@pytest.fixture(autouse=True)
def clean_environment() -> Generator[None, None, None]:
    """Ensure clean test environment for each test."""
    # This fixture runs before and after each test to ensure isolation
    yield
    # Any cleanup code would go here if needed
