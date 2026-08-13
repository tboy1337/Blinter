# Changelog

All notable changes to Blinter are documented in this file. Release tags follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- CI and release are a single Test workflow: CodeQL, dependency graph submission, and PyPI/GitHub release run in one pipeline with explicit `needs` dependencies (no `workflow_run` chaining)

## [1.1.16] - 2026-08-13

### Changed

- Build-Release-PYPI gated release on Test, CodeQL, and Dependency Graph (superseded by unified Test workflow pipeline)

## [1.1.15] - 2026-08-13

### Fixed

- **W004** only flags backward `goto` jumps (forward exit-handler jumps no longer reported as infinite loops)
- **W043** accepts `tasklist` verification on preceding lines in the same block, not only on the `taskkill` line
- **W014** ignores `set /p VAR=<file` file-input redirection and treats `timeout /t` as an alternative to `pause`
- **P006** skips `exit /b` returns from `call :subroutine` labels
- **SEC013** adds safe patterns for installer-style PowerShell `-File`, quoted executable redirection, and `curl` output
- **W020** and **P009** treat `delims=` as a valid `FOR /F` option for whole-line capture

### Changed

- `scripts/blinter.ini` installer profile shrinks from 21 to 10 disabled rules now that false positives are resolved
- Install and uninstall scripts include clearer comments for resume paths and user-facing messages

### Added

- SSOT corpus negative controls for the fixed rules (`w004-goto-exit-handler`, `w043-tasklist-before-taskkill`, `w014-setp-from-file-valid`, `p006-subroutine-exit-valid`, `sec013-installer-redirection-valid`, `for-f-delims-only-valid`, `p009-w020-for-f-missing-options`)

## [1.1.14] - 2026-08-13

### Changed

- README badge formatting updated from paragraph to `div` layout for presentation consistency

## [1.1.13] - 2026-08-13

### Changed

- README documents batch compatibility and encoding detection behavior more clearly
- PyPI download badges and license text formatting improved in README
- Minor formatting adjustments in `Blinter.spec`

## [1.1.12] - 2026-08-13

### Added

- OpenSSF Best Practices compliance files and README badges
- Dependabot configuration for pip and GitHub Actions updates
- `scripts/extract_release_notes.py` for release workflow changelog extraction

### Changed

- `CHANGELOG.md` moved to the repository root for OpenSSF detection

### Fixed

- `types-pyyaml` entry corrected in `requirements-dev.txt`
- Import order in `extract_release_notes.py` (isort)

## [1.1.11] - 2026-08-13

### Fixed

- SSOT audit strict-mode failures for E038, E019, and E008 negative-control corpus fixtures
- Black formatting in `tests/test_edge_cases.py`

## [1.1.10] - 2026-08-13

### Changed

- CI and quality-gate improvements

## [1.1.9] - 2026-08-12

### Changed

- Continued rule and corpus hardening

## [1.1.8] - 2026-08-12

### Added

- Application icon in the Windows executable build (`Blinter.spec`)
- Tests for icon configuration in the spec file

### Changed

- README updated for versioned standalone download naming

## [1.1.7] - 2026-08-11

### Changed

- Rule registry and checker refinements

## [1.1.0] - 2026-08-04

### Added

- Major 1.1 release line with expanded rule coverage and SSOT-driven rule generation

---

Older 1.0.x releases are available on the [GitHub Releases](https://github.com/tboy1337/Blinter/releases) page.

[1.1.15]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.15
[1.1.14]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.14
[1.1.13]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.13
[1.1.12]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.12
[1.1.11]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.11
[1.1.10]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.10
[1.1.9]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.9
[1.1.8]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.8
[1.1.7]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.7
[1.1.0]: https://github.com/tboy1337/Blinter/releases/tag/v1.1.0
