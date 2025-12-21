# CI/CD Setup for Armis CLI

This document explains the CI/CD pipeline configured for the Armis CLI repository itself.

## Overview

The Armis CLI uses GitHub Actions to automatically scan itself on every commit and pull request. This ensures that the codebase remains secure and demonstrates the tool's capabilities.

## Pipeline Workflow

The pipeline consists of two jobs:

### 1. Build & Unit Tests
- Runs on every push and pull request
- Sets up Go 1.21
- Downloads dependencies
- Runs all unit tests
- Builds the CLI binary

### 2. Security Scan
- Runs after successful build and tests
- Uses the Armis CLI to scan its own repository
- Fails the pipeline if CRITICAL or HIGH severity issues are found
- Uploads SARIF results to GitHub Security tab
- Displays human-readable results in the workflow logs

## Configuration

### Required Secrets

The pipeline requires one GitHub secret:

- `ARMIS_API_TOKEN`: API token for authenticating with Armis Cloud

To set this up:
1. Go to your repository settings
2. Navigate to Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `ARMIS_API_TOKEN`
5. Value: Your Armis Cloud API token

### Severity Thresholds

The pipeline is configured to:
- **FAIL** on: CRITICAL, HIGH severity findings
- **WARN** on: MEDIUM, LOW severity findings (shown but don't fail the build)

### Branches

The pipeline runs on:
- All branches on push
- All pull requests

## Local Testing

You can run the same security scan locally:

```bash
make build
make scan
```

Or manually:

```bash
export ARMIS_API_TOKEN="your-token"
./bin/armis scan repo . --fail-on CRITICAL,HIGH
```

## Viewing Results

### GitHub Security Tab
SARIF results are automatically uploaded to GitHub's Security tab:
1. Go to your repository
2. Click on "Security" tab
3. Click on "Code scanning alerts"
4. View detailed findings from Armis scans

### Workflow Logs
Human-readable results are printed in the workflow logs:
1. Go to "Actions" tab
2. Click on a workflow run
3. Click on "Armis Security Scan" job
4. View the "Run security scan (Human-readable)" step

## Customization

### Changing Severity Thresholds

Edit `.github/workflows/cli-self-scan.yml`:

```yaml
- name: Run security scan (SARIF)
  run: |
    ./bin/armis scan repo . \
      --format sarif \
      --fail-on CRITICAL,HIGH,MEDIUM \  # Add MEDIUM here
      --output armis-results.sarif
```

### Adding Exclusions

If you need to exclude certain paths:

```yaml
- name: Run security scan (SARIF)
  run: |
    ./bin/armis scan repo . \
      --format sarif \
      --fail-on CRITICAL,HIGH \
      --exclude "test/*,vendor/*" \
      --output armis-results.sarif
```

### Running on Specific Branches Only

Edit the `on` section in `.github/workflows/cli-self-scan.yml`:

```yaml
on:
  push:
    branches: [ "main", "develop" ]  # Only these branches
  pull_request:
    branches: [ "main" ]  # Only PRs to main
```

## Troubleshooting

### Pipeline Fails with "ARMIS_API_TOKEN not set"
- Ensure the secret is configured in repository settings
- Check that the secret name matches exactly: `ARMIS_API_TOKEN`

### Pipeline Fails with "API connection error"
- Verify the API token is valid
- Check if Armis Cloud API is accessible from GitHub Actions runners
- Review the API endpoint configuration

### SARIF Upload Fails
- Ensure the repository has "security-events: write" permission
- Check that the SARIF file is valid JSON
- Verify GitHub Advanced Security is enabled (for private repos)

## Badge

The README includes a status badge showing the current CI status:

```markdown
![CI](https://github.com/ArmisSecurity/armis-cli/actions/workflows/cli-self-scan.yml/badge.svg)
```

This badge updates automatically based on the latest workflow run.
