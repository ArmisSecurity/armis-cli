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

## [1.12.0] - 2026-06-10

### Added

- Release pipeline now maintains floating major (`v1`) and minor (`v1.12`) version tags, so the GitHub Action can be consumed via `uses: ArmisSecurity/armis-cli@v1` and receive non-breaking updates automatically (#213)
- Documented the one-time GitHub Marketplace publishing steps for the Armis CLI Action in `docs/DISTRIBUTION-SETUP.md` (#213)

### Changed

- CI/CD documentation and example workflows now recommend pinning the GitHub Action to `@v1` instead of `@main` (#213)
- Marketplace sample workflow now references the repository's own `ArmisSecurity/armis-cli@v1` action with structured inputs (#213)

### Deprecated

- The local composite action at `.github/actions/armis-cli-action/` is deprecated in favor of the top-level `action.yml` (`ArmisSecurity/armis-cli@v1`) (#213)

---

## [1.11.1] - 2026-06-08

### Fixed

- `supply-chain init`: the injected shell wrappers no longer break after an `armis-cli` upgrade. The wrapper now references `armis-cli` by bare name (resolved from `PATH` on every call) when it is on `PATH`, falling back to the stable symlink path otherwise — previously it embedded the fully symlink-resolved binary path, which on Homebrew was the version-pinned Cellar directory (e.g. `…/Cellar/armis-cli/1.11.0/…`). After `brew upgrade armis-cli` deleted that directory, every wrapped package manager (npm, pnpm, bun, pip, uv, poetry, npx) failed to run in new shells. The wrappers are also now fail-closed: if `armis-cli` cannot be found at invocation time, the wrapper prints a loud warning to stderr that enforcement has lapsed and runs the real package manager un-wrapped, so installs never silently break. The fish guard now uses fish-native `command -q` (POSIX `command -v` errored under fish and silently disabled enforcement), and the guard adds an executable-path check so an absolute fallback path is detected reliably across shells. Wrappers injected before this fix must be refreshed by re-running `armis-cli supply-chain init` once. (#216)

---

## [1.11.0] - 2026-06-08

### Added

- `supply-chain` command for enforcing package release-age policies, defending against supply-chain attacks (typosquatting, compromised maintainers, dependency confusion) by flagging or blocking packages published more recently than a configurable threshold (default 72h). No Armis Cloud authentication required — queries public registries directly. (#206, #210, #211)
  - Supports 12 package managers across three ecosystems: npm, npx, pnpm, bun, yarn (Node); pip, uv, poetry, pipenv, pdm (Python); Maven, Gradle (Java).
  - Node package managers and pip/uv use a transparent registry proxy that filters out too-young versions during install; poetry, pipenv, pdm, Maven, and Gradle use a pre-install lockfile audit that blocks the build before execution.
  - `npx` is wrapped alongside `npm` (it ships with npm and resolves from the same registry), so ad-hoc `npx <pkg>` runs are filtered through the same proxy. Enforcement applies to packages npx fetches from the registry; a package already in the npx cache or a binary already in `node_modules/.bin` runs without a registry round-trip and is not re-checked. The sibling runners `pnpm dlx` and `yarn dlx` are already covered as subcommands of the existing pnpm/yarn wrappers; `bunx` (a separate binary) is not yet wrapped.
  - `supply-chain check` audits lockfiles in CI; `supply-chain init`/`uninit` set up local shell enforcement; `supply-chain status` reports the active policy and detected ecosystems.
  - Configurable via `.armis-supply-chain.yaml` (`min-age`, `exclusions`, `ecosystems`, `fail-open`); per-invocation bypass via `ARMIS_SUPPLY_CHAIN_SKIP`; master kill switch via `ARMIS_SUPPLY_CHAIN=off`.
  - Gradle lockfile staleness detection (warns when `build.gradle` is newer than `gradle.lockfile`), Maven `pom.xml` partial-coverage notice (direct dependencies only), and a warning for unrecognized ecosystem names in the config.
  - The `ecosystems` config field accepts both `pipenv` (the tool name shown in `--help`) and `pipfile` (the internal name) so either spelling works.
  - The install summary reports each filtered package on one line showing the too-new version, its age, and the older version installed in its place (e.g. `axios 1.17.0 (1 day old) → 1.16.1 installed`). When every package resolves to a safe version it reads as a success; packages with no older safe version are called out individually. If the package manager itself does not complete (for example a dependency pins a version that only the filtered release satisfies), the summary reports the safe version as "available" rather than claiming it was installed, and explains how to relax or exclude the constraint. A one-time explanation of why fresh releases are withheld is shown on the first filtered install in an interactive terminal (suppressed thereafter and in CI).

### Changed

- `supply-chain init`: now wraps every supported package manager found on your `PATH` instead of only the ones with a lockfile in the current directory. The injected shell functions are global (they apply in every directory), so detecting from the current project's lockfiles left gaps — e.g. running `init` in a Go repo wrapped only `npm`/`npx`, so a later `pip install` in a Python project ran unenforced. Detection is now machine-wide; per-project enforcement is still decided dynamically at install time from the nearest `.armis-supply-chain.yaml` (the `ecosystems` scope and policy are re-read on each install), so wrapping a package manager never forces enforcement where the project hasn't opted in. When no supported package manager is on `PATH`, `init` still falls back to wrapping `npm`/`npx`.

### Fixed

- `supply-chain check`: `--fail-on` now accepts lowercase severities (e.g. `--fail-on medium`) and validates the value, matching `scan repo`/`scan image`. Previously a lowercase or invalid value was silently ignored, so the CI gate never fired and a real violation exited 0.
- `supply-chain`: an unknown subcommand (e.g. a typo like `chekc`) now exits non-zero with a "Did you mean" suggestion instead of printing help and exiting 0.
- `supply-chain check`: `--min-age` parse errors no longer print the duration twice; the message now suggests valid formats (`72h`, `3d`, `1w`). Output reads "1 package" (not "1 packages"), and the empty "Scan ID:" line is omitted for the local audit.
- `supply-chain check`: base-lockfile auto-detection now bounds its `git` subprocesses with a timeout (and honors cancellation), so a wedged or misconfigured `git` invocation can no longer hang the command indefinitely.
- `supply-chain`: the config `ecosystems` field now actually scopes enforcement. Previously it was parsed and typo-checked but ignored, so `ecosystems: [npm]` still enforced every ecosystem. `check` now skips an out-of-scope lockfile, `wrap` passes an out-of-scope package manager straight through, and `init` only wraps in-scope package managers. The gate fails safe: an empty list (or a list of only unrecognized names) enforces everything, so a typo cannot silently disable the control.

### Security

- `supply-chain wrap` (pip/uv): age enforcement now actually filters. The local-enforcement proxy previously only understood the npm registry format, so pip and uv installs were pointed at the proxy but their PyPI Simple API requests passed through unfiltered — young packages installed silently. The proxy now speaks the PyPI Simple API (PEP 691/700 JSON), removing distribution files published more recently than the policy threshold; a file with no upload timestamp is removed (fail-closed) rather than allowed.

---

## [1.10.2] - 2026-05-28

### Fixed

- Gemini CLI hook now uses the correct timeout unit (seconds instead of milliseconds) preventing premature request timeouts (#204)

---

## [1.10.1] - 2026-05-27

### Fixed

- Copilot CLI hook now installs to the correct path (`~/.copilot/settings.json`) instead of the VS Code extension directory (#202)
- Separated Copilot CLI hook target from VS Code extension target to prevent cross-contamination during install (#201)

---

## [1.10.0] - 2026-05-27

### Added

- Interactive MCP install wizard with hook-based integration for seamless plugin setup (#199)

### Fixed

- Added inline suppression directives for remaining CI findings (#198)

---

## [1.9.4] - 2026-05-25

### Fixed

- Added inline suppression directives for remaining CI findings (#194)

---

## [1.9.3] - 2026-05-25

### Fixed

- Suppression directives updated for compatibility with the new inline matching engine (#192)

### Changed

- Added comprehensive unit tests for install, uninstall, scan, and inline suppression flows (#191)

---

## [1.9.2] - 2026-05-25

### Fixed

- Inline suppression now matches directives by applicability (CWE, category, rule) before accepting, preventing false suppressions from stacked comments and ensuring fall-through to the correct directive (#189)

---

## [1.9.1] - 2026-05-24

### Fixed

- Inline suppression now correctly sees through function signatures, matching findings inside annotated functions regardless of signature length (#187)

### Changed

- Updated go-git/go-git to v5.19.1 (#183)
- Updated golang.org/x/sys to v0.44.0, golang.org/x/term to v0.43.0 (#167, #168)
- Updated alecthomas/chroma to v2.24.1 (#156)
- Updated mattn/go-runewidth to v0.0.23 (#139)
- Updated sigstore/cosign-installer to v4.1.2 (#165)

---

## [1.9.0] - 2026-05-21

### Added

- `uninstall` command for cleanly removing installed plugins, with manifest tracking and upgrade detection (#182)

### Fixed

- Suppressed findings are now excluded from SARIF output, allowing GitHub Code Scanning alerts to auto-close when findings are suppressed via `.armisignore` or inline directives (#185)
- Python binary discovery now probes versioned names (`python3.11`, `python3.12`, etc.) in addition to `python3` and `python`, resolving install failures on systems without a generic `python3` symlink (#184)

---

## [1.8.4] - 2026-05-18

### Added

- Claude Desktop app as an install target for the `install` command (#179)

### Fixed

- Secrets no longer leak in `--help` output when default values contain credentials (#180)

---

## [1.8.3] - 2026-05-13

### Changed

- Inline suppression now matches findings within a 5-line window around the directive, improving coverage for multi-line code patterns (#175)

---

## [1.8.2] - 2026-05-13

### Added

- Inline `armis:ignore` comment suppression — suppress findings directly in source code with parameterized matching by category, rule, CWE, or severity; supports all major comment syntaxes with security-hardened parsing (#170)

### Fixed

- Recurring findings no longer reopen on the GitHub Code Scanning tab — separated PR and scheduled scan SARIF categories (#171)
- `PrintWarning` now masks secrets consistently with `PrintError` (#172)
- HTTP client disallows redirects to strengthen SSRF protection (#172)
- Inline suppression file handle errors properly propagated instead of suppressed (#172)
- Stale Code Scanning alerts now close correctly when findings are suppressed via inline directives (#173)

---

## [1.8.1] - 2026-05-11

### Added

- Client-side finding suppression via `.armisignore` directives — findings matching severity, category, CWE, or rule patterns are excluded from `--fail-on` evaluation and human/JUnit output, with proper suppression metadata in SARIF and JSON (#162)
- `--show-suppressed` flag to include suppressed findings in output (#162)

### Changed

- GitHub Action updated to use JWT authentication as default, removing unused Basic auth secrets from scan workflows (#164)

### Fixed

- `LICENSE_COMPLIANCE_RISK` findings now correctly classified as LICENSE type (#162)

---

## [1.8.0] - 2026-05-11

### Added

- JWT authentication support for the GitHub Action with `client-id`, `client-secret`, and `region` inputs as the recommended auth method (#155)
- Suppression directive parsing in `.armisignore` for finding-level filtering by rule, category, severity, and CWE (#157)

---

## [1.7.0] - 2026-05-05

### Added

- Agent detection `collect` subcommand for reporting detected AI coding agents to Armis Cloud inventory (#153)
- Local AI agent discovery capability for detecting installed coding assistants

### Fixed

- SARIF rule IDs normalized to stable CWE/CVE identifiers, removing unstable fingerprints for consistent GitHub Code Scanning deduplication (#154)
- Install script now surfaces credential write failures instead of silently swallowing errors (#151)
- Release pipeline fixed by upgrading cosign-installer to v4 (v3 bootstrap binary was delisted) (#149)

---

## [1.4.0] - 2026-03-15

### Added

- JWT authentication via `--client-id` / `--client-secret` is now the recommended authentication method, taking priority over `--token` when both are provided (#95)

### Changed

- Removed `--auth-endpoint` flag — JWT endpoint is now derived automatically from the API URL and region (#98)
- Documentation updated to establish JWT as the recommended authentication method over Basic auth (#99)

---

## [1.3.0] - 2026-03-08

### Added

- `--changed` flag for scanning only git-changed files, enabling faster incremental scans (#93)
- `--output` flag for specifying output file path with improved CI detection and progress display (#92)
- Streaming multipart uploads for improved memory efficiency on large repositories (#91)

### Fixed

- Update notification now displays consistently after all commands (#94)

### Changed

- Updated go-git to v5.17.0 (#88)
- Updated GitHub Actions: upload-artifact v7 (#87), download-artifact v8 (#89), sbom-action v0.23.0 (#90)

---

## [1.2.1] - 2026-02-26

### Changed

- Updated golang.org/x/term to v0.40.0 (#76)
- Updated github.com/mattn/go-runewidth to v0.0.20 (#82)
- Updated goreleaser/goreleaser-action to v7 (#83)
- Optimized CI testing workflow (#85)
- Improved GitHub theme-aware markdown for AppSec logo (#84)

---

## [1.2.0] - 2026-02-23

### Added

- Smart local image detection - automatically detects whether an image exists locally (docker/podman) before attempting remote pull, improving scan speed for local images
- AppSec logo branding in CI security scan results

### Fixed

- Support empty `--fail-on` flag for informational-only scans that should never fail the build

### Security

- Defense-in-depth secret masking prevents accidental secret exposure in scan output, proposed fixes, and debug logs

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

[Unreleased]: https://github.com/ArmisSecurity/armis-cli/compare/v1.12.0...HEAD
[1.12.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.4...v1.10.0
[1.9.4]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.3...v1.9.4
[1.9.3]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.2...v1.9.3
[1.9.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.4...v1.9.0
[1.8.4]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.6.1...v1.7.0
[1.4.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/ArmisSecurity/armis-cli/releases/tag/v1.0.5
