# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [1.2.0] - 2026-02-23

### Added

- Smart local image detection - automatically detects whether an image exists locally (docker/podman) before attempting remote pull, improving scan speed for local images (#80)
- AppSec logo branding in CI security scan results (#79)

### Changed

- Enhanced secret masking with defense-in-depth approach across all output formatters (human, JSON, SARIF) - secrets are now masked at multiple layers (#77)

### Fixed

- Support empty `--fail-on` flag for informational-only scans that should never fail the build (#78)

### Security

- Defense-in-depth secret masking prevents accidental secret exposure in scan output, proposed fixes, and debug logs (#77)

---

## [1.1.0] - 2026-02-16

### Added

- JWT/VIPR token authentication with `--client-id`, `--client-secret`, `--auth-endpoint` flags (or `ARMIS_CLIENT_ID`, `ARMIS_CLIENT_SECRET`, `ARMIS_AUTH_ENDPOINT` env vars)
- Automatic JWT token refresh (5 minutes before expiry) with tenant ID auto-extraction from token
- `auth` command for testing authentication and obtaining raw JWT tokens
- Colored terminal output with `--color` flag (`auto`/`always`/`never`) respecting `NO_COLOR` and TTY detection
- `--theme` flag (`auto`/`dark`/`light`) for terminal background override with `ARMIS_THEME` env var
- Background version update checking with 24-hour cache (disable with `--no-update-check` or `ARMIS_NO_UPDATE_CHECK`)
- `--summary-top` flag to display summary dashboard before findings
- Lipgloss-based styling with ~50 styles using Tailwind CSS color palette and adaptive light/dark themes
- Chroma-based syntax highlighting with language auto-detection and vulnerable line highlighting
- LCS-based inline diff change detection with context limiting (3 lines around changes)
- Unicode severity indicators with colored styling
- Styled help output with colored commands and flags
- Short flag aliases: `-f` for `--format`, `-t` for `--token`
- `ARMIS_API_URL` environment variable for API base URL override

### Changed

- Case-insensitive `--fail-on` values (e.g., `--fail-on high` now works)
- JUnit formatter respects `--fail-on` severities instead of hardcoding CRITICAL/HIGH
- Diff display limited to 25 lines per hunk with "lines omitted" markers
- Summary dashboard only shows severity levels with findings (count > 0)
- Clean Ctrl+C handling with exit code 130 (standard Unix SIGINT)
- `--include-files` flag now repo-only (moved from scan-level)
- JWT authentication flags hidden from `--help` until backend support available

### Fixed

- **CRITICAL**: FAILED scan status now returns error instead of success
- **CRITICAL**: Reject `--exit-code 0` (must be 1-255 to work with `--fail-on`)
- API response limit increased to 50MB for large scan results
- Docker pull/save output redirected to stderr (prevents JSON/SARIF corruption)
- CommitSHA bounds check prevents panic on short commit hashes
- Timeout validation requires >= 1 minute for `--scan-timeout` and `--upload-timeout`
- Unicode text wrapping uses proper visual width calculation
- Rune-based column highlighting for multi-byte characters
- Path/tarball existence validation before network calls
- Warning when both `--tarball` and image name provided
- Warning when `--sbom-output`/`--vex-output` specified without `--sbom`/`--vex`
- SARIF schema URL updated to valid `main` branch location
- Syntax highlighting skipped for redacted code snippets (prevents colored keywords in redaction messages)

### Security

- Secret masking in SARIF output (patches, proposed fixes, patch files)
- Secret masking in proposed fixes and debug output
- Response body limits: 1MB for auth, 50MB for API, 1MB for HTTP errors
- Snippet loading limits: 10KB per line, 100KB total
- LCS token limit (500) prevents memory exhaustion
- Diff size limits: 100KB max, 2000 lines max
- Highlight code size limit: 100KB
- JSON parsing limit in error messages: 4KB
- Symlink detection fix using `os.Lstat` instead of `os.Stat`
- go-git updated to v5.16.5 (CVE-2026-25934 fix)
- HTTPS enforcement for authentication endpoints

---

## [1.0.7] - 2026-02-02

### Added

- SARIF standard `fixes` array for actionable fix suggestions with `ProposedFixes` and `PatchFiles` support
- Enhanced SARIF rule information with `fullDescription`, `helpUri`, and `help` fields
- Improved finding title generation (priority: CVE+package for SCA > OWASP category > secret type > description)

### Changed

- Separated spinner cleanup from result messages for cleaner progress output
- Only include `Help.Markdown` when it differs from `Help.Text` to avoid redundancy
- Added `stripMarkdown()` utility for SARIF `Help.Text` field per SARIF 2.1.0 spec
- Updated `anchore/sbom-action` from 0.21.1 to 0.22.1
- Updated `tj-actions/changed-files` from 46 to 47
- Updated `actions/checkout` from 4 to 6

### Fixed

- CWE URL validation (validate numeric before generating URL, fallback for invalid CWEs)
- SARIF line number validation (prevent invalid `DeletedRegion` with StartLine/EndLine = 0)
- Description truncation edge cases (period handling at position 80, trailing periods)

### Security

- Path traversal protection: skip paths when `util.SanitizePath` fails instead of falling back to original
- Command injection prevention: defense-in-depth image name validation in `exportImage`

---

## [1.0.6] - 2025-02-01

### Added

- SBOM (Software Bill of Materials) generation in CycloneDX format via `--sbom` flag
- VEX (Vulnerability Exploitability eXchange) document generation via `--vex` flag
- Custom output paths for SBOM/VEX via `--sbom-output` and `--vex-output` flags
- Proposed fix support with AI validation for vulnerability remediation
- Hybrid scan summary with brief status at top of output
- Theme-aware logo support for documentation
- Comprehensive CI integration guide
- OSS best practices and developer tooling documentation

### Changed

- Improved test coverage to 81.1%

### Fixed

- Workflow condition handling to avoid duplicated titles in scan output
- Missing permissions in security-scan workflow

---

## [1.0.5] - Initial Public Release

### Added

- Initial public release
- Repository scanning for security vulnerabilities
- Container image scanning
- CI/CD integration support (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps)
- Multiple output formats (JSON, SARIF, table)
- Configurable ignore patterns via .armisignore
- Multi-platform binaries (Linux, macOS, Windows)
- Docker image support
- Cosign signature verification

### Security

- Added SSRF protection for pre-signed URL downloads (only AWS S3 endpoints allowed)
- Added response size limits (100MB for downloads, 5GB for uploads, 1MB for API responses)
- HTTPS enforcement for credential transmission (except localhost for testing)
- Path traversal protection for artifact names and output paths
- Credential exposure prevention in debug output

---

## Release History

<!--
Release notes are automatically generated by GoReleaser.
See: https://github.com/ArmisSecurity/armis-cli/releases

Manual entries for significant releases:
-->

<!-- Example format for future releases:

## [1.0.0] - 2025-01-15

### Added
- Feature description

### Fixed
- Bug fix description

[1.0.0]: https://github.com/ArmisSecurity/armis-cli/compare/v0.9.0...v1.0.0

-->

[Unreleased]: https://github.com/ArmisSecurity/armis-cli/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/ArmisSecurity/armis-cli/releases/tag/v1.0.5
