<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-light.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo-dark.svg">
  <img alt="Armis AppSec Logo" src="docs/assets/logo-dark.svg">
</picture>

# Armis CLI

[![Build Status](https://github.com/ArmisSecurity/armis-cli/actions/workflows/release.yml/badge.svg)](https://github.com/ArmisSecurity/armis-cli/actions)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![Coverage](https://img.shields.io/badge/coverage-check%20CI-blue)](https://github.com/ArmisSecurity/armis-cli/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard-blue)](https://securityscorecards.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/ArmisSecurity/armis-cli)](https://goreportcard.com/report/github.com/ArmisSecurity/armis-cli)

Enterprise-grade CLI for static application security scanning with Armis Cloud. Integrate security scanning into developer workflows and CI/CD pipelines.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Verification](#verification)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Environment Variables](#environment-variables)
- [Security Considerations](#security-considerations)
- [Severity Levels](#severity-levels)
- [Finding Types](#finding-types)
- [Exit Codes](#exit-codes)
- [Releases](#releases)
- [Building from Source](#building-from-source)
- [Development](#development)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)

---

## Features

- Scan repositories and container images
- Multiple output formats: human, JSON, SARIF, JUnit XML
- CI/CD ready: GitHub Actions, Jenkins, GitLab, Azure, Bitbucket, CircleCI
- Configurable exit codes and fail-on severity
- Secure authentication, size limits, and best practices

## Installation

### Homebrew (macOS/Linux)

**Prerequisites:** [Homebrew](https://brew.sh) must be installed first.

```bash
brew install armissecurity/tap/armis-cli
```

### Quick Install Script

**Linux/macOS:**

```bash
curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
```

The script will automatically:

- Install to `~/.local/bin` (no sudo required) or `/usr/local/bin` as fallback
- Verify the installation
- Check if the command is in your PATH

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex
```

### Scoop (Windows)

```powershell
scoop bucket add armis https://github.com/ArmisSecurity/scoop-bucket
scoop install armis-cli
```

### Manual Download

Download the latest release for your platform from the [releases page](https://github.com/ArmisSecurity/armis-cli/releases).

### Using Go

```bash
go install github.com/ArmisSecurity/armis-cli/cmd/armis-cli@latest
```

### Verify Installation

After installation, verify that the CLI is working:

```bash
which armis-cli
armis-cli --version
```

### Troubleshooting: "command not found"

If you see "command not found" after installation:

1. **Check if it's installed:**

   ```bash
   ls -la ~/.local/bin/armis-cli
   # or
   ls -la /usr/local/bin/armis-cli
   ```

2. **Check your PATH:**

   ```bash
   echo $PATH
   ```

3. **Add to PATH if needed:**

   For **zsh** (default on macOS):

   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```

   For **bash**:

   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile
   source ~/.bash_profile
   ```

4. **Or open a new terminal window** and try again.

5. **Run directly with full path:**

   ```bash
   ~/.local/bin/armis-cli --help
   ```

---

## Verification

All releases include cryptographic signatures, SBOMs, and SLSA Level 3 provenance attestations for supply chain security.

### Verify Checksums (Cosign)

```bash
# Download the binary, checksums, and signature
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-linux-amd64.tar.gz
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt.sig

# Verify the signature
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature armis-cli-checksums.txt.sig \
  armis-cli-checksums.txt

# Verify the checksum
sha256sum --ignore-missing -c armis-cli-checksums.txt
```

### Verify SLSA Provenance (Supply Chain Security)

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download provenance
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-linux-amd64.tar.gz.intoto.jsonl

# Verify SLSA Level 3 provenance
slsa-verifier verify-artifact \
  --provenance-path armis-cli-linux-amd64.tar.gz.intoto.jsonl \
  --source-uri github.com/ArmisSecurity/armis-cli \
  armis-cli-linux-amd64.tar.gz
```

### Inspect SBOM (Software Bill of Materials)

```bash
# Download SBOM (CycloneDX JSON format)
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-linux-amd64.tar.gz.sbom.cdx.json

# View dependencies
cat armis-cli-linux-amd64.tar.gz.sbom.cdx.json | jq '.components[] | {name: .name, version: .version}'

# Or use CycloneDX CLI tools
npm install -g @cyclonedx/cyclonedx-cli
cyclonedx-cli validate --input-file armis-cli-linux-amd64.tar.gz.sbom.cdx.json
```

**Learn more:**

- [SLSA Framework](https://slsa.dev/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)
- [CycloneDX SBOM](https://cyclonedx.org/)

---

## Quick Start

### Set up authentication

```bash
export ARMIS_API_TOKEN="your-api-token-here"
```

### Scan a repository

```bash
armis-cli scan repo ./my-project
```

### Scan a container image

```bash
armis-cli scan image nginx:latest
```

---

## Usage

### Global Flags

```text
--token string          API token for authentication (or use ARMIS_API_TOKEN env var)
--api-url string        Armis Cloud API base URL (default: https://api.armis.cloud/v1)
--format string         Output format: human, json, sarif, junit (default: human)
--no-progress           Disable progress indicators
--fail-on strings       Fail build on severity levels (default: [CRITICAL])
--exit-code int         Exit code to use when failing (default: 1)
```

### Scan Repository

Scans a local directory, creates a tarball, and uploads to Armis Cloud for analysis.

```bash
armis-cli scan repo [path] --tenant-id [tenant-id]
```

**Size Limit**: 2GB
**Example**:

```bash
armis-cli scan repo ./my-app --tenant-id my-tenant --format json --fail-on HIGH,CRITICAL
```

### Scan Container Image

Scans a container image (local or remote) or a tarball.

```bash
armis-cli scan image [image-name] --tenant-id [tenant-id]
armis-cli scan image --tarball [path-to-tarball] --tenant-id [tenant-id]
```

**Size Limit**: 5GB
**Examples**:

```bash
# Scan remote image
armis-cli scan image nginx:latest --tenant-id my-tenant
# Scan local image
armis-cli scan image my-app:v1.0.0 --tenant-id my-tenant
# Scan tarball
armis-cli scan image --tarball ./image.tar --tenant-id my-tenant
```

---

## Output Formats

### Human-Readable (Default)

Colorful, formatted output with tables and summaries.

```bash
armis-cli scan repo ./my-app
```

### JSON

Machine-readable JSON output.

```bash
armis-cli scan repo ./my-app --format json
```

### SARIF

Static Analysis Results Interchange Format for tool integration.

```bash
armis-cli scan repo ./my-app --format sarif > results.sarif
```

### JUnit XML

Test report format for CI/CD integration.

```bash
armis-cli scan repo ./my-app --format junit > results.xml
```

---

## CI/CD Integration

For advanced patterns (PR scanning with changed files, scheduled scans, container image scanning) and other CI platforms, see the **[CI Integration Guide](docs/CI-INTEGRATION.md)**.

### GitHub Actions

#### Option 1: Reusable Workflow (Recommended)

The simplest way to integrate Armis scanning. This reusable workflow handles everything: scanning, PR comments, SARIF uploads, and artifact storage.

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  security-scan:
    uses: ArmisSecurity/armis-cli/.github/workflows/reusable-security-scan.yml@main
    with:
      fail-on: CRITICAL,HIGH
    secrets:
      api-token: ${{ secrets.ARMIS_API_TOKEN }}
      tenant-id: ${{ secrets.ARMIS_TENANT_ID }}
```

**Available inputs:**

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `scan-type` | string | `repo` | Type of scan: `repo` or `image` |
| `scan-target` | string | `.` | Path for repo scan, image name for image scan |
| `fail-on` | string | `CRITICAL` | Severity levels to fail on (e.g., `HIGH,CRITICAL`) |
| `pr-comment` | boolean | `true` | Post scan results as PR comment |
| `upload-artifact` | boolean | `true` | Upload SARIF results as artifact |
| `artifact-retention-days` | number | `30` | Days to retain artifacts |
| `image-tarball` | string | | Path to image tarball (for image scans) |
| `scan-timeout` | number | `60` | Scan timeout in minutes |
| `include-files` | string | | Comma-separated file paths to scan (for targeted scanning) |

**Required secrets:**

- `api-token`: Armis API token for authentication
- `tenant-id`: Tenant identifier for Armis Cloud

#### Option 2: GitHub Action

Use the action directly for more control over your workflow:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ArmisSecurity/armis-cli@main
        with:
          scan-type: repo
          api-token: ${{ secrets.ARMIS_API_TOKEN }}
          tenant-id: ${{ secrets.ARMIS_TENANT_ID }}
          format: sarif
          output-file: results.sarif
          fail-on: HIGH,CRITICAL
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
```

#### Option 3: Manual Installation

For full control, install and run the CLI directly:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Install Armis CLI
        run: |
          curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
      - name: Scan Repository
        env:
          ARMIS_API_TOKEN: ${{ secrets.ARMIS_API_TOKEN }}
        run: |
          armis-cli scan repo . \
            --tenant-id "${{ secrets.ARMIS_TENANT_ID }}" \
            --format sarif \
            --fail-on HIGH,CRITICAL \
            > results.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl bash
    - curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
  script:
    - armis-cli scan repo . --tenant-id "$ARMIS_TENANT_ID" --format json --fail-on CRITICAL
  variables:
    ARMIS_API_TOKEN: $ARMIS_API_TOKEN
    ARMIS_TENANT_ID: $ARMIS_TENANT_ID
```

### Jenkins

```groovy
pipeline {
    agent any
    environment {
        ARMIS_API_TOKEN = credentials('armis-api-token')
        ARMIS_TENANT_ID = credentials('armis-tenant-id')
    }
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
                    armis-cli scan repo . --tenant-id "$ARMIS_TENANT_ID" --format junit > scan-results.xml
                '''
                junit 'scan-results.xml'
            }
        }
    }
}
```

### Azure DevOps

```yaml
trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
- script: |
    curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
  displayName: 'Install Armis CLI'
- script: |
    armis-cli scan repo . --tenant-id "$(ARMIS_TENANT_ID)" --format junit > $(Build.ArtifactStagingDirectory)/scan-results.xml
  env:
    ARMIS_API_TOKEN: $(ARMIS_API_TOKEN)
  displayName: 'Run Security Scan'
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: '**/scan-results.xml'
```

### CircleCI

```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Armis CLI
          command: |
            curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
      - run:
          name: Run Security Scan
          command: |
            armis-cli scan repo . --tenant-id "$ARMIS_TENANT_ID" --format json --fail-on HIGH,CRITICAL
workflows:
  version: 2
  scan:
    jobs:
      - security-scan:
          context: armis-credentials
```

### BitBucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: Security Scan
        image: alpine:latest
        script:
          - apk add --no-cache curl bash
          - curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
          - armis-cli scan repo . --tenant-id "$ARMIS_TENANT_ID" --format json --fail-on CRITICAL
```

---

## Environment Variables

- `ARMIS_API_TOKEN` - API token for authentication
- `ARMIS_API_URL` - Custom API base URL
- `ARMIS_FORMAT` - Default output format

---

## Security Considerations

- **Size Limits**: Enforced to prevent resource exhaustion
  - Repositories: 2GB
  - Container Images: 5GB
- **Authentication**: API tokens are never logged or exposed
- **Secure Transport**: All API communication uses HTTPS
- **Automatic Cleanup**: Temporary files are cleaned up after use
- **CI Detection**: Progress bars automatically disabled in CI environments

---

## Severity Levels

- `CRITICAL` - Critical vulnerabilities requiring immediate attention
- `HIGH` - High-severity vulnerabilities
- `MEDIUM` - Medium-severity vulnerabilities
- `LOW` - Low-severity vulnerabilities
- `INFO` - Informational findings

---

## Finding Types

- `VULNERABILITY` – Code vulnerabilities (SAST)
- `CONTAINER` – Container image vulnerabilities
- `SCA` – Software Composition Analysis (dependency vulnerabilities)
- `SECRET` – Exposed secrets and credentials
- `LICENSE` – License compliance risks
- `IAC` – Infrastructure as Code misconfigurations

---

## Exit Codes

- `0` - Scan completed successfully with no blocking findings
- `1` - Scan found blocking findings (configurable with `--fail-on`)
- `>1` - Error occurred during scan

---

## Releases

New versions are automatically built and published when version tags are pushed. Each release includes:

- Pre-built binaries for macOS, Linux, and Windows (amd64 and arm64)
- SHA256 checksums for verification
- Automated changelog generation

Visit the [releases page](https://github.com/ArmisSecurity/armis-cli/releases) to download specific versions.

---

## Building from Source

```bash
git clone https://github.com/ArmisSecurity/armis-cli.git
cd armis-cli
make build
```

The binary will be in `bin/armis-cli`.

---

## Development

```bash
# Run tests
make test
# Run linters
make lint
# Build for all platforms
make release
```

---

## Contributing

We welcome contributions! Please see:

- [CONTRIBUTING.md](.github/CONTRIBUTING.md) for contribution guidelines
- [CODE_OF_CONDUCT.md](.github/CODE_OF_CONDUCT.md) for community standards
- [Issue Templates](.github/ISSUE_TEMPLATE/) for reporting bugs or requesting features

---

## Support

- For issues, open a [GitHub Issue](https://github.com/ArmisSecurity/armis-cli/issues)
- For security concerns, see [SECURITY.md](.github/SECURITY.md)
- For questions, contact <support@armis.com>

---

## License

This CLI is open source software licensed under the Apache License 2.0.
It is intended to be used as a client for interacting with the Armis cloud platform APIs. The CLI itself does not contain any proprietary detection logic or security analysis engines.
Use of the CLI is subject to the terms of service of the corresponding cloud APIs.
