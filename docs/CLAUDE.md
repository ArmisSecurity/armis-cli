# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Armis CLI is an enterprise-grade security scanning tool written in Go that integrates with Armis Cloud. It scans repositories and container images for security vulnerabilities, secrets, and license risks.

## Build Commands

```bash
make build          # Build binary to bin/armis-cli
make test           # Run all tests with verbose output
make lint           # Run golangci-lint (must be installed)
make clean          # Remove build artifacts
make release        # Build for all platforms (linux/darwin/windows, amd64/arm64)
```

Run a single test:
```bash
go test -v ./internal/api -run TestClientStartIngest
go test -v ./internal/output/... -run TestHumanFormatter
```

## Architecture

### Entry Point and Command Structure
- `cmd/armis-cli/main.go` - Entry point, sets version info and calls `cmd.Execute()`
- `internal/cmd/` - Cobra command definitions
  - `root.go` - Root command with global flags (token, format, fail-on, tenant-id, debug)
  - `scan.go` - Parent scan command with shared flags (include-tests, scan-timeout, group-by)
  - `scan_repo.go` - Repository scanning subcommand
  - `scan_image.go` - Container image scanning subcommand

### Core Packages
- `internal/api/` - API client for Armis Cloud communication (upload, status polling, results fetching)
- `internal/model/` - Data structures for findings, scan results, API responses
- `internal/output/` - Output formatters (human, json, sarif, junit) implementing `Formatter` interface
- `internal/scan/repo/` - Repository scanner: creates tar.gz, uploads, polls for results
- `internal/scan/image/` - Image scanner: uses docker/podman to export images, then uploads
- `internal/progress/` - Progress spinner for CLI feedback
- `internal/httpclient/` - HTTP client with retry logic and exponential backoff

### Scan Flow
1. Scanner creates compressed archive (repo) or exports image to tarball (image)
2. API client uploads to `/api/v1/ingest/tar` endpoint
3. Client polls `/api/v1/ingest/status/` until scan completes
4. Client fetches paginated results from `/api/v1/ingest/normalized-results`
5. Results converted to internal `Finding` model and formatted for output

### Key Constants
- Max repository size: 2GB (`repo.MaxRepoSize`)
- Max image size: 5GB (`image.MaxImageSize`)
- Default scan timeout: 20 minutes
- Default upload timeout: 10 minutes
- Page limit range: 1-1000 (default 500)

### Environment Variables
- `ARMIS_API_TOKEN` - API authentication token
- `ARMIS_TENANT_ID` - Tenant identifier
- `ARMIS_FORMAT` - Default output format
- `ARMIS_PAGE_LIMIT` - Results pagination size

## Testing

Tests use table-driven patterns. Mock HTTP responses with `internal/testutil/httptest.go`. The `test/` directory contains a mock server and sample repository for integration testing.

## Linting

Uses golangci-lint with these linters enabled: errcheck, govet, ineffassign, staticcheck, unused, gosec, goconst, misspell.
