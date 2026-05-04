# CI/CD Integration Guide

Integrate Armis security scanning into your CI/CD pipeline to automatically detect vulnerabilities in pull requests and monitor your codebase over time.

---

## Table of Contents

- [Quick Start](#quick-start)
- [GitHub Actions](#github-actions)
  - [Option 1: Reusable Workflow (Recommended)](#option-1-reusable-workflow-recommended)
  - [Option 2: GitHub Action](#option-2-github-action)
  - [Option 3: Manual Installation](#option-3-manual-installation)
- [Advanced Patterns](#advanced-patterns)
  - [PR Scanning with Changed Files](#pr-scanning-with-changed-files)
  - [Scheduled Repository Scans](#scheduled-repository-scans)
  - [SBOM and VEX Generation](#sbom-and-vex-generation)
  - [Container Image Scanning](#container-image-scanning)
- [Other CI Platforms](#other-ci-platforms)
  - [GitLab CI](#gitlab-ci)
  - [Jenkins](#jenkins)
  - [Azure DevOps](#azure-devops)
  - [CircleCI](#circleci)
  - [Bitbucket Pipelines](#bitbucket-pipelines)
- [Output Formats](#output-formats)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)

---

## Quick Start

### GitHub Actions (Recommended)

Add this to `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  scan:
    uses: ArmisSecurity/armis-cli/.github/workflows/reusable-security-scan.yml@main
    secrets:
      client-id: ${{ secrets.ARMIS_CLIENT_ID }}
      client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
```

That's it! This will:

- Scan your repository on every PR
- Post results as a PR comment
- Upload findings to GitHub Code Scanning
- Fail on CRITICAL vulnerabilities

### For Other CI Platforms

```bash
# Install
curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash

# Run scan (JWT auth - recommended)
export ARMIS_CLIENT_ID="your-client-id"
export ARMIS_CLIENT_SECRET="your-client-secret"
armis-cli scan repo . --format sarif --fail-on CRITICAL
```

---

## Authentication

The Armis CLI supports two authentication methods. JWT authentication is recommended.

### JWT Authentication (Recommended)

Obtain client credentials from the VIPR external API screen in the Armis platform.

| Credential | Environment Variable | CLI Flag | Description |
|------------|---------------------|----------|-------------|
| Client ID | `ARMIS_CLIENT_ID` | `--client-id` | Client ID for JWT authentication |
| Client Secret | `ARMIS_CLIENT_SECRET` | `--client-secret` | Client secret for JWT authentication |

The tenant ID is automatically extracted from the JWT token — no need to set it separately.

**Example:**

```bash
export ARMIS_CLIENT_ID="your-client-id"
export ARMIS_CLIENT_SECRET="your-client-secret"

armis-cli scan repo .
```

### Basic Authentication (Legacy)

| Credential | Environment Variable | CLI Flag | Description |
|------------|---------------------|----------|-------------|
| API Token | `ARMIS_API_TOKEN` | `--token` | API token for authentication |
| Tenant ID | `ARMIS_TENANT_ID` | `--tenant-id` | Tenant identifier |

---

## GitHub Actions

### Option 1: Reusable Workflow (Recommended)

The reusable workflow is the simplest way to integrate Armis scanning. It handles:

- CLI installation with checksum verification
- SARIF upload to GitHub Code Scanning
- Detailed PR comments with severity breakdown
- Artifact storage for historical tracking

#### Basic Usage

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
      fail-on: 'CRITICAL,HIGH'
      pr-comment: true
    secrets:
      client-id: ${{ secrets.ARMIS_CLIENT_ID }}
      client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
```

#### Input Reference

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `scan-type` | string | `repo` | Type of scan: `repo` or `image` |
| `scan-target` | string | `.` | Path for repo scan, image name for image scan |
| `fail-on` | string | `CRITICAL` | Comma-separated severity levels to fail on (e.g., `HIGH,CRITICAL`). Set to empty string to never fail. |
| `pr-comment` | boolean | `true` | Post scan results as PR comment |
| `upload-artifact` | boolean | `true` | Upload SARIF results as artifact |
| `artifact-retention-days` | number | `30` | Days to retain artifacts |
| `image-tarball` | string | | Path to image tarball (for image scans) |
| `scan-timeout` | number | `60` | Scan timeout in minutes |
| `include-files` | string | | Comma-separated list of file paths to scan (for targeted scanning) |
| `build-from-source` | boolean | `false` | Build CLI from source instead of release (for testing) |

#### Required Secrets

| Secret | Description |
|--------|-------------|
| `client-id` | Client ID for JWT authentication (recommended) |
| `client-secret` | Client secret for JWT authentication (recommended) |
| `api-token` | Armis API token (legacy fallback) |
| `tenant-id` | Tenant identifier (legacy fallback, not needed with JWT) |

#### Required Permissions

```yaml
permissions:
  contents: read          # Read repository content
  security-events: write  # Upload SARIF to Code Scanning
  pull-requests: write    # Post PR comments
  actions: read           # Access workflow artifacts
```

#### What You Get

**PR Comments**: Detailed breakdown of findings by severity with expandable details for each issue:

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 12 |

**GitHub Code Scanning**: Findings appear in the Security tab, inline in PR diffs, and as check annotations.

**Artifacts**: SARIF results are stored for the configured retention period, enabling historical analysis.

---

### Option 2: GitHub Action

Use the action directly when you need more control over your workflow.

> **Note:** The GitHub Action currently supports Linux and macOS runners only. For Windows runners (`windows-latest`), use [Option 3: Manual Installation](#option-3-manual-installation) with the PowerShell install script:
>
> ```powershell
> irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex
> ```

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

      - name: Run Armis Security Scan
        uses: ArmisSecurity/armis-cli@main
        with:
          scan-type: repo
          client-id: ${{ secrets.ARMIS_CLIENT_ID }}
          client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
          format: sarif
          output-file: results.sarif
          fail-on: HIGH,CRITICAL

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
```

#### Action Input Reference

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scan-type` | Yes | | Type of scan: `repo` or `image` |
| `scan-target` | No | `.` | Path for repo, image name for image scan |
| `client-id` | No* | | Client ID for JWT authentication (recommended) |
| `client-secret` | No* | | Client secret for JWT authentication (recommended) |
| `region` | No | | Armis cloud region for JWT authentication |
| `api-token` | No* | | Armis API token (legacy) |
| `tenant-id` | No* | | Tenant identifier (legacy, not needed with JWT) |
| `format` | No | `sarif` | Output format: `human`, `json`, `sarif`, `junit` |
| `fail-on` | No | `CRITICAL` | Severity levels to fail on |
| `exit-code` | No | `1` | Exit code when failing |
| `no-progress` | No | `true` | Disable progress indicators |
| `image-tarball` | No | | Path to image tarball (image scans) |
| `output-file` | No | | File path for results |
| `scan-timeout` | No | `60` | Timeout in minutes |
| `include-files` | No | | Comma-separated file paths to scan |
| `build-from-source` | No | `false` | Build from source (testing) |

\* One authentication method is required: either `client-id` + `client-secret` (recommended) or `api-token` + `tenant-id` (legacy).

#### Action Outputs

| Output | Description |
|--------|-------------|
| `results` | Scan results in the specified format |
| `exit-code` | Exit code from the scan |

---

### Option 3: Manual Installation

For maximum control, install and run the CLI directly:

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

      - name: Run Security Scan
        env:
          ARMIS_CLIENT_ID: ${{ secrets.ARMIS_CLIENT_ID }}
          ARMIS_CLIENT_SECRET: ${{ secrets.ARMIS_CLIENT_SECRET }}
        run: |
          armis-cli scan repo . \
            --format sarif \
            --fail-on HIGH,CRITICAL \
            > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Advanced Patterns

### PR Scanning with Changed Files

Scan only the files that changed in a PR for faster feedback:

```yaml
name: PR Security Scan
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  get-changed-files:
    runs-on: ubuntu-latest
    outputs:
      files: ${{ steps.changed-files.outputs.all_changed_files }}
      any_changed: ${{ steps.changed-files.outputs.any_changed }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v46
        with:
          separator: ','
          # Exclude test files from security scan
          files_ignore: |
            **/*_test.go
            **/testdata/**

  security-scan:
    needs: get-changed-files
    if: needs.get-changed-files.outputs.any_changed == 'true'
    uses: ArmisSecurity/armis-cli/.github/workflows/reusable-security-scan.yml@main
    with:
      fail-on: 'CRITICAL,HIGH'
      include-files: ${{ needs.get-changed-files.outputs.files }}
    secrets:
      client-id: ${{ secrets.ARMIS_CLIENT_ID }}
      client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
```

**Key points:**

- Uses `tj-actions/changed-files` to detect modified files
- Passes changed files via `include-files` input
- Only runs if files actually changed
- Excludes test files that may contain intentional security test patterns

---

### Scheduled Repository Scans

Run comprehensive scans on a schedule for ongoing monitoring:

```yaml
name: Scheduled Security Scan
on:
  workflow_dispatch:  # Manual trigger
  schedule:
    - cron: '0 6 * * *'  # Daily at 06:00 UTC

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    uses: ArmisSecurity/armis-cli/.github/workflows/reusable-security-scan.yml@main
    with:
      fail-on: ''              # Don't fail - monitoring only
      pr-comment: false        # No PR context
      upload-artifact: true
      scan-timeout: 120        # Allow more time for full scan
    secrets:
      client-id: ${{ secrets.ARMIS_CLIENT_ID }}
      client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
```

**Key points:**

- Set `fail-on` to empty string for monitoring without blocking
- Disable PR comments since there's no PR context
- Increase timeout for comprehensive scans
- Results still uploaded to GitHub Code Scanning

---

### SBOM and VEX Generation

Generate Software Bill of Materials and VEX documents for compliance and supply chain security:

```yaml
name: Security Scan with SBOM/VEX
on:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Armis CLI
        run: |
          curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash

      - name: Run Security Scan with SBOM/VEX
        env:
          ARMIS_CLIENT_ID: ${{ secrets.ARMIS_CLIENT_ID }}
          ARMIS_CLIENT_SECRET: ${{ secrets.ARMIS_CLIENT_SECRET }}
        run: |
          armis-cli scan repo . \
            --format sarif \
            --sbom --vex \
            --sbom-output ./artifacts/sbom.json \
            --vex-output ./artifacts/vex.json \
            > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload SBOM/VEX Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sbom-vex-${{ github.sha }}
          path: ./artifacts/
          retention-days: 90
```

**Key points:**

- SBOM and VEX are generated server-side during the scan
- Files are downloaded after scan completion
- Store artifacts for compliance and audit purposes
- VEX helps prioritize vulnerabilities that are actually exploitable

---

### Container Image Scanning

#### Scan After Build

```yaml
name: Build and Scan Image
on:
  push:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Run Armis Image Scan
        uses: ArmisSecurity/armis-cli@main
        with:
          scan-type: image
          scan-target: myapp:${{ github.sha }}
          client-id: ${{ secrets.ARMIS_CLIENT_ID }}
          client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
          format: sarif
          output-file: image-results.sarif
          fail-on: CRITICAL,HIGH

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: image-results.sarif
          category: container-scan
```

#### Image Pull Policy

Control how images are fetched before scanning with the `--pull` flag:

| Policy | Use Case |
|--------|----------|
| `always` | CI/CD - ensures latest image from registry |
| `missing` | Development - saves time by reusing local images (default) |
| `never` | Air-gapped - requires pre-pulled images |

For CI/CD pipelines scanning remote images, use `--pull=always` to ensure you're scanning the latest version:

```yaml
- name: Scan container image
  run: |
    armis-cli scan image ${{ env.IMAGE_TAG }} \
      --pull=always \
      --fail-on CRITICAL \
      --format sarif
```

#### Scan from Tarball

For images built in a previous job or CI step:

```yaml
- name: Save Image as Tarball
  run: docker save myapp:latest -o image.tar

- name: Scan Image Tarball
  uses: ArmisSecurity/armis-cli@main
  with:
    scan-type: image
    image-tarball: image.tar
    client-id: ${{ secrets.ARMIS_CLIENT_ID }}
    client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
```

---

## Other CI Platforms

### GitLab CI

```yaml
stages:
  - security

security-scan:
  stage: security
  image: alpine:latest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  before_script:
    - apk add --no-cache curl bash
    - curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
  script:
    - armis-cli scan repo . --format json --fail-on CRITICAL
  variables:
    ARMIS_CLIENT_ID: $ARMIS_CLIENT_ID
    ARMIS_CLIENT_SECRET: $ARMIS_CLIENT_SECRET
```

Configure credentials as [protected CI/CD variables](https://docs.gitlab.com/ee/ci/variables/#protected-cicd-variables).

---

### Jenkins

```groovy
pipeline {
    agent any

    environment {
        ARMIS_CLIENT_ID = credentials('armis-client-id')
        ARMIS_CLIENT_SECRET = credentials('armis-client-secret')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
                    armis-cli scan repo . \
                        --format junit \
                        --fail-on HIGH,CRITICAL \
                        > scan-results.xml
                '''
                junit 'scan-results.xml'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'scan-results.xml', allowEmptyArchive: true
        }
    }
}
```

Configure credentials using [Jenkins Credentials](https://www.jenkins.io/doc/book/using/using-credentials/).

#### Jenkins (Windows Agent)

```groovy
pipeline {
    agent { label 'windows' }

    environment {
        ARMIS_CLIENT_ID = credentials('armis-client-id')
        ARMIS_CLIENT_SECRET = credentials('armis-client-secret')
    }

    stages {
        stage('Security Scan') {
            steps {
                powershell '''
                    irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex
                    armis-cli scan repo . `
                        --format junit `
                        --fail-on HIGH,CRITICAL `
                        > scan-results.xml
                '''
                junit 'scan-results.xml'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'scan-results.xml', allowEmptyArchive: true
        }
    }
}
```

---

### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: armis-credentials  # Contains ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET

steps:
  - script: |
      curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
    displayName: 'Install Armis CLI'

  - script: |
      armis-cli scan repo . \
        --format junit \
        --fail-on HIGH,CRITICAL \
        > $(Build.ArtifactStagingDirectory)/scan-results.xml
    displayName: 'Run Security Scan'
    env:
      ARMIS_CLIENT_ID: $(ARMIS_CLIENT_ID)
      ARMIS_CLIENT_SECRET: $(ARMIS_CLIENT_SECRET)

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '**/scan-results.xml'
    condition: always()
```

Configure secrets using [Variable Groups](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups).

#### Azure DevOps (Windows Runner)

```yaml
trigger:
  - main

pool:
  vmImage: 'windows-latest'

variables:
  - group: armis-credentials

steps:
  - powershell: |
      irm https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.ps1 | iex

      armis-cli scan repo . `
        --format junit `
        --fail-on HIGH,CRITICAL `
        > $(Build.ArtifactStagingDirectory)\scan-results.xml
    displayName: 'Install Armis CLI and Run Security Scan'
    env:
      ARMIS_CLIENT_ID: $(ARMIS_CLIENT_ID)
      ARMIS_CLIENT_SECRET: $(ARMIS_CLIENT_SECRET)

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '**/scan-results.xml'
    condition: always()
```

---

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
            armis-cli scan repo . \
              --format json \
              --fail-on HIGH,CRITICAL

workflows:
  version: 2
  security:
    jobs:
      - security-scan:
          context: armis-credentials  # Contains ARMIS_CLIENT_ID, ARMIS_CLIENT_SECRET
```

Configure secrets using [Contexts](https://circleci.com/docs/contexts/).

---

### Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Security Scan
          image: alpine:latest
          script:
            - apk add --no-cache curl bash
            - curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
            - armis-cli scan repo . --format json --fail-on CRITICAL

  branches:
    main:
      - step:
          name: Security Scan
          image: alpine:latest
          script:
            - apk add --no-cache curl bash
            - curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
            - armis-cli scan repo . --format json --fail-on CRITICAL
```

Configure `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` as [secured repository variables](https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/).

---

## Output Formats

| Format | Best For | CI Integration |
|--------|----------|----------------|
| `sarif` | GitHub, VS Code | GitHub Code Scanning, IDE extensions |
| `junit` | Jenkins, Azure | Native test result publishing |
| `json` | Custom processing | Scripts, dashboards, APIs |
| `human` | Local debugging | Terminal output (not recommended for CI) |

---

## Troubleshooting

### Authentication Errors

#### "authentication required"

- No valid authentication credentials were provided
- Set `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` for JWT auth (recommended), or `ARMIS_API_TOKEN` and `ARMIS_TENANT_ID` for legacy auth

#### "tenant ID required"

- This only applies to Basic (legacy) authentication
- Provide `--tenant-id` along with `--token`, or switch to JWT authentication (recommended) where tenant ID is extracted automatically

#### "API token not set"

- If using JWT: ensure `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` are configured as secrets
- If using Basic auth: ensure `ARMIS_API_TOKEN` is configured as a secret
- Check that the secret is accessible to the workflow/job
- Verify the secret name matches exactly (case-sensitive)

#### "Invalid token" or "Unauthorized"

- Verify the credentials are valid and not expired
- If using Basic auth, check that the tenant ID matches the token's tenant
- Ensure the credentials have sufficient permissions

### Timeout Issues

#### Scan times out

- Increase `scan-timeout` (default: 60 minutes)
- For large repositories, consider using `include-files` to scan specific paths
- Check network connectivity to Armis Cloud

### SARIF Upload Failures

#### "Resource not accessible by integration"

- Ensure `security-events: write` permission is set
- For private repositories, GitHub Advanced Security must be enabled
- Check that the SARIF file was created successfully

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings above threshold |
| `1` | Scan completed, findings exceed `fail-on` threshold |
| `>1` | Scan error (authentication, network, timeout) |

**Distinguishing findings from errors:**
The reusable workflow's "Check for Failures" step differentiates between:

- Scans that failed (timeout, API error) - always fails the workflow
- Scans that found vulnerabilities - fails based on `fail-on` setting

---

## Security Best Practices

### Secret Management

- **Never commit credentials** to version control
- Use **JWT authentication** (client ID/secret) for production — it supports automatic token refresh
- Use **organization-level secrets** when possible for centralized management
- Use **environment-specific credentials** for production vs development
- Rotate credentials periodically
- Store client ID and client secret as separate secrets

### Permissions

- Grant **minimum required permissions** to workflows
- Use `permissions` block to explicitly declare needs
- For forked PRs, be aware that secrets may not be available

### Supply Chain Security

- **Pin action versions** to specific tags or commit SHAs:

  ```yaml
  # Good: pinned to version
  uses: ArmisSecurity/armis-cli@v1.0.0

  # Better: pinned to commit SHA
  uses: ArmisSecurity/armis-cli@abc123def456
  ```

- The CLI installation verifies **checksums** automatically
- Release binaries include **SLSA provenance** for verification

---

## See Also

- [README - Quick Start](../README.md#quick-start)
- [CLI Usage Reference](../README.md#usage)
- [Output Formats](../README.md#output-formats)
- [Example Workflow Files](ci-examples/)
