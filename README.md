# Armis Security Scanner CLI

Enterprise-grade CLI tool for static application security scanning integrated with Armis Cloud. Easily integrate security scanning into your CI/CD pipeline.

## Features

- 🔍 **Multiple Scan Types**: Scan repositories, container images, and individual files
- 🚀 **CI/CD Ready**: Works seamlessly with Jenkins, GitHub Actions, GitLab CI, Azure DevOps, BitBucket, CircleCI, and more
- 📊 **Multiple Output Formats**: Human-readable, JSON, SARIF, and JUnit XML
- 🎯 **Configurable Exit Codes**: Fail builds based on severity thresholds
- 🔄 **Automatic Retries**: Built-in retry logic with exponential backoff
- 📈 **Progress Indicators**: Visual progress bars (auto-disabled in CI environments)
- 🔒 **Security First**: Size limits, secure authentication, and best practices

## Installation

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
```

### Using Go

```bash
go install github.com/silk-security/Moose-CLI/cmd/armis@latest
```

### Manual Download

Download the latest release for your platform from the [releases page](https://github.com/silk-security/Moose-CLI/releases).

## Quick Start

### Set up authentication

```bash
export ARMIS_API_TOKEN="your-api-token-here"
```

### Scan a repository

```bash
armis scan repo ./my-project
```

### Scan a container image

```bash
armis scan image nginx:latest
```

### Scan a file

```bash
armis scan file ./app.jar
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

Scans a local directory, zips it, and uploads to Armis Cloud for analysis.

```bash
armis scan repo [path]
```

**Size Limit**: 2GB

**Example**:
```bash
armis scan repo ./my-app --format json --fail-on HIGH,CRITICAL
```

### Scan Container Image

Scans a container image (local or remote) or a tarball.

```bash
armis scan image [image-name]
armis scan image --tarball [path-to-tarball]
```

**Size Limit**: 5GB

**Examples**:
```bash
# Scan remote image
armis scan image nginx:latest

# Scan local image
armis scan image my-app:v1.0.0

# Scan tarball
armis scan image --tarball ./image.tar
```

### Scan File

Scans a single file for vulnerabilities.

```bash
armis scan file [path]
```

**Size Limit**: 50MB

**Example**:
```bash
armis scan file ./app.jar --format sarif
```

## Output Formats

### Human-Readable (Default)

Colorful, formatted output with tables and summaries.

```bash
armis scan repo ./my-app
```

### JSON

Machine-readable JSON output.

```bash
armis scan repo ./my-app --format json
```

### SARIF

Static Analysis Results Interchange Format for tool integration.

```bash
armis scan repo ./my-app --format sarif > results.sarif
```

### JUnit XML

Test report format for CI/CD integration.

```bash
armis scan repo ./my-app --format junit > results.xml
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
          curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
      
      - name: Scan Repository
        env:
          ARMIS_API_TOKEN: ${{ secrets.ARMIS_API_TOKEN }}
        run: |
          armis scan repo . --format sarif --fail-on HIGH,CRITICAL
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl bash
    - curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
  script:
    - armis scan repo . --format json --fail-on CRITICAL
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
                    curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
                    armis scan repo . --format junit > scan-results.xml
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
    curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
  displayName: 'Install Armis CLI'

- script: |
    armis scan repo . --format junit > $(Build.ArtifactStagingDirectory)/scan-results.xml
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
            curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
      - run:
          name: Run Security Scan
          command: |
            armis scan repo . --format json --fail-on HIGH,CRITICAL

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
          - curl -sSL https://raw.githubusercontent.com/silk-security/Moose-CLI/main/scripts/install.sh | bash
          - armis scan repo . --format json --fail-on CRITICAL
```

## Environment Variables

- `ARMIS_API_TOKEN` - API token for authentication
- `ARMIS_API_URL` - Custom API base URL
- `ARMIS_FORMAT` - Default output format

## Security Considerations

- **Size Limits**: Enforced to prevent resource exhaustion
  - Repositories: 2GB
  - Container Images: 5GB
  - Files: 50MB
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

## Building from Source

```bash
git clone https://github.com/silk-security/Moose-CLI.git
cd Moose-CLI
make build
```

The binary will be in `bin/armis`.

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

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/silk-security/Moose-CLI).

## License

Copyright © 2024 Silk Security. All rights reserved.
