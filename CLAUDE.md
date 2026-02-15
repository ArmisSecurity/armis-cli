# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Armis CLI is an enterprise-grade security scanning tool written in Go that integrates with Armis Cloud. It scans repositories and container images for security vulnerabilities, secrets, and license risks.

**Prerequisites:** Go 1.24+, [golangci-lint](https://golangci-lint.run/) v2.0+, Make

## Build Commands

```bash
make build          # Build binary to bin/armis-cli
make install        # Install binary to /usr/local/bin (or PREFIX)
make test           # Run all tests with verbose output (uses gotestsum if installed)
make lint           # Run golangci-lint
make clean          # Remove build artifacts
make release        # Build for all platforms (linux/darwin/windows, amd64/arm64)
make scan           # Run security scan on this repository (requires built binary)
make tools          # Install dev tools (gotestsum)
```

Run a single test:

```bash
go test -v ./internal/api -run TestClientStartIngest
go test -v ./internal/output/... -run TestHumanFormatter
```

## Architecture

### Entry Point and Command Structure

- `cmd/armis-cli/main.go` - Entry point. Sets version info, initializes colors via `cli.InitColors()`, calls `cmd.Execute()`.
- `internal/cmd/` - Cobra command definitions:
  - `root.go` - Root command with global flags. `PersistentPreRunE` initializes color mode, syncs output styles, and starts background update check. `getAuthProvider()` delegates to `auth.NewAuthProvider()`.
  - `scan.go` - Parent scan command with shared flags. Its `PersistentPreRunE` manually chains to `rootCmd.PersistentPreRunE` (Cobra does not auto-chain when a child also defines `PersistentPreRunE`).
  - `scan_repo.go` - Repository scanning subcommand
  - `scan_image.go` - Container image scanning subcommand (`--tarball` flag for pre-exported images)
  - `auth.go` - Standalone `auth` command for testing JWT authentication (prints raw token)
  - `context.go` - Signal handling: `NewSignalContext()` creates context canceled on SIGINT/SIGTERM

### Core Packages

- `internal/auth/` - Authentication provider supporting two modes. JWT (priority): client credentials exchange at `/api/v1/authenticate`, auto-refresh 5min before expiry, tenant ID extracted from `customer_id` JWT claim. Basic (fallback): static token + explicit tenant ID. Implements `AuthHeaderProvider` interface used by the API client.
- `internal/api/` - API client for Armis Cloud. Two HTTP clients: one for general calls (60s timeout), one for uploads (no timeout). Functional options pattern (`WithHTTPClient()`, `WithAllowLocalURLs()`). Enforces HTTPS, validates presigned S3 URLs against SSRF.
- `internal/model/` - Data structures: `Finding` (23 fields), `ScanResult`, `Summary`, `Fix`, `FindingValidation` (with taint/reachability analysis), API response types (`NormalizedFinding`, pagination).
- `internal/output/` - Output formatters (human, json, sarif, junit) implementing the `Formatter` interface. `styles.go` defines ~50 lipgloss styles using Tailwind CSS color palette. `icons.go` defines Unicode constants (severity dots, box-drawing chars). `SyncColors()` switches between full-color and plain styles based on `cli.ColorsEnabled()`.
- `internal/cli/` - Centralized color state management. `InitColors(mode)` resolves `--color` flag (auto/always/never) with `NO_COLOR` env, `TERM=dumb`, and TTY detection on stderr. `PrintError()`/`PrintWarning()` parse JSON `{"detail":"..."}` from API errors for clean display.
- `internal/scan/repo/` - Repository scanner: creates tar.gz (with `.armisignore` support via go-git gitignore matcher), uploads, polls, fetches paginated results. Builder pattern with `WithPollInterval()`, `WithIncludeFiles()`, `WithSBOMVEXOptions()`.
- `internal/scan/image/` - Image scanner: validates image names via `distribution/reference`, uses docker/podman to export, then uploads. Also supports direct tarball scanning.
- `internal/scan/` - Shared scan utilities: `status.go` (status formatting, severity mapping), `finding_type.go` (classifies findings as VULNERABILITY/SCA/SECRET/MISCONFIG/LICENSE), `sbom_vex.go` (downloads SBOM/VEX from presigned S3 URLs).
- `internal/progress/` - Braille-dot spinner with timer display, lipgloss styling, cursor hiding, CI detection (auto-disables animation). Context-aware with configurable timeout (default 30min). Upload progress via `NewReader()`/`NewWriter()` wrappers.
- `internal/update/` - Background version checker against GitHub Releases API with file-based caching (~/.cache/armis-cli/, 24h TTL). Semver comparison. Skipped in CI, dev builds.
- `internal/httpclient/` - HTTP client with exponential backoff retry (cenkalti/backoff). Retries on 5xx errors.
- `internal/util/` - Path sanitization (`SanitizePath`, `SafeJoinPath` for traversal prevention), secret masking (12 regex patterns), category formatting.

### Key Interfaces

- `output.Formatter` - `Format()` and `FormatWithOptions()` for all output formatters
- `api.AuthHeaderProvider` - `GetAuthorizationHeader(ctx)` decouples auth from API client

### Scan Flow

1. Scanner creates compressed archive (repo tar.gz with `.armisignore` filtering) or exports image to tarball via docker/podman
2. API client uploads to `/api/v1/ingest/tar` with progress tracking
3. Client polls `/api/v1/ingest/status/` with spinner status updates until scan completes
4. Client fetches paginated results from `/api/v1/ingest/normalized-results` (cursor-based)
5. `NormalizedFinding` converted to internal `model.Finding` (type classification, secret masking, code location extraction)
6. Results formatted for output; SBOM/VEX downloaded from presigned S3 URLs if requested
7. `ExitIfNeeded()` checks findings against `--fail-on` severity levels

### Key Constants

- Max repository size: 2GB (`repo.MaxRepoSize`)
- Max image size: 5GB (`image.MaxImageSize`)
- Default scan timeout: 60 minutes
- Default upload timeout: 10 minutes
- Page limit range: 1-1000 (default 500)

### Environment Variables

- `ARMIS_CLIENT_ID` - Client ID for JWT authentication (recommended)
- `ARMIS_CLIENT_SECRET` - Client secret for JWT authentication
- `ARMIS_AUTH_ENDPOINT` - JWT authentication service endpoint URL
- `ARMIS_API_TOKEN` - API token for Basic authentication (fallback)
- `ARMIS_TENANT_ID` - Tenant identifier (required only with Basic auth; JWT extracts it from token)
- `ARMIS_FORMAT` - Default output format
- `ARMIS_PAGE_LIMIT` - Results pagination size
- `ARMIS_THEME` - Terminal background theme: auto, dark, light (default: auto)

When both JWT and Basic credentials are configured, JWT takes precedence.

### Styling Architecture

Terminal output uses lipgloss with a centralized two-phase initialization:

1. `main.go` calls `cli.InitColors(auto)` early for error display
2. `root.PersistentPreRunE` re-initializes with the `--color` flag value, applies `--theme` override, then calls `output.SyncColors()` to set the active style set (`DefaultStyles` or `NoColorStyles`)

All styles are defined in `internal/output/styles.go` using `lipgloss.AdaptiveColor` for automatic light/dark theme adaptation. Colors use Tailwind CSS palette with separate light/dark variants (e.g., gray-600 on light, gray-500 on dark). The `--theme` flag (auto/dark/light) overrides auto-detection via `lipgloss.SetHasDarkBackground()`. The lipgloss renderer targets stderr. Terminal width is detected from stderr with fallback=68, min=60, max=120.

## Testing

Tests use table-driven patterns. Mock HTTP responses with `internal/testutil/httptest.go`. The `test/` directory contains a mock server and sample repository for integration testing.

## Linting

Uses golangci-lint v2 config (`.golangci.yml`) with: errcheck, govet, ineffassign, staticcheck, unused, gosec, goconst, misspell.

## Conventions

- Error wrapping: always use `fmt.Errorf("context: %w", err)`
- Commit messages: conventional commits (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`)
- All output (spinners, styled text) writes to stderr; only scan results go to stdout
