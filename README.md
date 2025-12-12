# Armis Security Scanner CLI

![CI]([data:image/png;base64,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](https://www.armis.com/wp-content/themes/armis/resources/images/svg/logo-dark.svg))

Enterprise-grade CLI tool for static application security scanning integrated with Armis Cloud. Easily integrate security scanning into your CI/CD pipeline.

## Features

- 🔍 **Multiple Scan Types**: Scan repositories and container images
- 🚀 **CI/CD Ready**: Works seamlessly with Jenkins, GitHub Actions, GitLab CI, Azure DevOps, BitBucket, CircleCI, and more
- 📊 **Multiple Output Formats**: Human-readable, JSON, SARIF, and JUnit XML
- 🎯 **Configurable Exit Codes**: Fail builds based on severity thresholds
- 🔄 **Automatic Retries**: Built-in retry logic with exponential backoff
- 📈 **Progress Indicators**: Visual progress bars (auto-disabled in CI environments)
- 🔒 **Security First**: Size limits, secure authentication, and best practices

## Installation

### Homebrew (macOS/Linux)

```bash
brew install armis/tap/armis-cli
```

### Quick Install Script

**Linux/macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.ps1 | iex
```

### Using Go

```bash
go install github.com/silk-security/armis-cli/cmd/armis-cli@latest
```

### Scoop (Windows)

```powershell
scoop bucket add armis https://github.com/silk-security/scoop-bucket
scoop install armis-cli
```

### Manual Download

Download the latest release for your platform from the [releases page](https://github.com/silk-security/armis-cli/releases).

### Verification

All releases are signed with [cosign](https://docs.sigstore.dev/cosign/installation/). To verify a download:

```bash
# Download the binary, checksums, and signature
curl -LO https://github.com/silk-security/armis-cli/releases/latest/download/armis-cli-linux-amd64.tar.gz
curl -LO https://github.com/silk-security/armis-cli/releases/latest/download/armis-cli-checksums.txt
curl -LO https://github.com/silk-security/armis-cli/releases/latest/download/armis-cli-checksums.txt.sig

# Verify the signature
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/silk-security/armis-cli/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature armis-cli-checksums.txt.sig \
  armis-cli-checksums.txt

# Verify the checksum
sha256sum --ignore-missing -c armis-cli-checksums.txt
```

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

## Usage

### Global Flags

```
--token string          API token for authentication (or use ARMIS_API_TOKEN env var)
--api-url string        Armis Cloud API base URL (default: https://api.armis.cloud/v1)
--format string         Output format: human, json, sarif, junit (default: human)
--no-progress          Disable progress indicators
--fail-on strings      Fail build on severity levels (default: [CRITICAL])
--exit-code int        Exit code to use when failing (default: 1)
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

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Armis CLI
        run: |
          curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
      
      - name: Scan Repository
        env:
          ARMIS_API_TOKEN: ${{ secrets.ARMIS_API_TOKEN }}
        run: |
          armis-cli scan repo . --format sarif --fail-on HIGH,CRITICAL
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl bash
    - curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
  script:
    - armis-cli scan repo . --format json --fail-on CRITICAL
  variables:
    ARMIS_API_TOKEN: $ARMIS_API_TOKEN
```

### Jenkins

```groovy
pipeline {
    agent any
    
    environment {
        ARMIS_API_TOKEN = credentials('armis-api-token')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
                    armis-cli scan repo . --format junit > scan-results.xml
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
    curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
  displayName: 'Install Armis CLI'

- script: |
    armis-cli scan repo . --format junit > $(Build.ArtifactStagingDirectory)/scan-results.xml
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
            curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
      - run:
          name: Run Security Scan
          command: |
            armis-cli scan repo . --format json --fail-on HIGH,CRITICAL

workflows:
  version: 2
  scan:
    jobs:
      - security-scan
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
          - curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
          - armis-cli scan repo . --format json --fail-on CRITICAL
```

## Environment Variables

- `ARMIS_API_TOKEN` - API token for authentication
- `ARMIS_API_URL` - Custom API base URL
- `ARMIS_FORMAT` - Default output format

## Security Considerations

- **Size Limits**: Enforced to prevent resource exhaustion
  - Repositories: 2GB
  - Container Images: 5GB
- **Authentication**: API tokens are never logged or exposed
- **Secure Transport**: All API communication uses HTTPS
- **Automatic Cleanup**: Temporary files are cleaned up after use
- **CI Detection**: Progress bars automatically disabled in CI environments

## Severity Levels

- `CRITICAL` - Critical vulnerabilities requiring immediate attention
- `HIGH` - High-severity vulnerabilities
- `MEDIUM` - Medium-severity vulnerabilities
- `LOW` - Low-severity vulnerabilities
- `INFO` - Informational findings

## Finding Types

- `VULNERABILITY` - Code vulnerabilities (SAST)
- `SCA` - Software Composition Analysis (dependency vulnerabilities)
- `SECRET` - Exposed secrets and credentials
- `LICENSE` - License compliance risks

## Exit Codes

- `0` - Scan completed successfully with no blocking findings
- `1` - Scan found blocking findings (configurable with `--fail-on`)
- `>1` - Error occurred during scan

## Releases

New versions are automatically built and published when version tags are pushed. Each release includes:

- Pre-built binaries for macOS, Linux, and Windows (amd64 and arm64)
- SHA256 checksums for verification
- Automated changelog generation

Visit the [releases page](https://github.com/silk-security/armis-cli/releases) to download specific versions.

## Building from Source

```bash
git clone https://github.com/silk-security/armis-cli.git
cd armis-cli
make build
```

The binary will be in `bin/armis-cli`.

## Development

```bash
# Run tests
make test

# Run linters
make lint

# Build for all platforms
make release
```

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/silk-security/armis-cli).

## License

Copyright © 2024 Silk Security. All rights reserved.
