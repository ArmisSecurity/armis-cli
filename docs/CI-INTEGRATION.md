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
| `pr-comment` | boolean | `true` | Post a branded PR comment (as `armis-appsec[bot]`) via the Armis backend. Requires the [armis-appsec GitHub App](#branded-pr-comments) installed on the repo; otherwise the comment is silently skipped. |
| `upload-artifact` | boolean | `true` | Upload SARIF results as artifact |
| `artifact-retention-days` | number | `30` | Days to retain artifacts |
| `image-tarball` | string | | Path to image tarball (for image scans) |
| `scan-timeout` | number | `60` | Scan timeout in minutes |
| `include-files` | string | | Comma-separated list of file paths to scan (for targeted scanning) |
| `region` | string | | Armis cloud region (overrides auto-discovery) |
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

**Branded PR Comments**: A detailed breakdown of findings by severity with expandable details for each issue, posted as `armis-appsec[bot]`:

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 12 |

<a id="branded-pr-comments"></a>
> **How it works:** The action sends the raw SARIF results to the Armis backend, which formats and posts the comment server-side (the same formatter used by the `armis-appsec` bot when assigned to a PR). This keeps formatting consistent across integrations and lets it improve without an action release. It requires the **armis-appsec GitHub App** to be installed on the repository — without it the backend cannot post as the bot and the comment is skipped (the scan itself still runs and uploads results). Authentication reuses your existing `client-id`/`client-secret` (JWT) or `api-token` (legacy) credentials; commenting failures never fail the build.

**GitHub Code Scanning**: Findings appear in the Security tab, inline in PR diffs, and as check annotations.

**Artifacts**: SARIF results are stored for the configured retention period, enabling historical analysis.

---

### Option 2: GitHub Action

Use the action directly when you need more control over your workflow. Pin to the major version
tag (`@v1`) to automatically receive non-breaking updates, or pin to an exact version (`@v1.10.2`)
or commit SHA to freeze the action definition. Note that the action installs the latest released
CLI binary by default, so pinning the action ref alone does not pin the CLI version. See
[Supply Chain Security](#supply-chain-security) below.

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
        uses: ArmisSecurity/armis-cli@v1
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
| `pr-comment` | No | `false` | Post a branded PR comment (as `armis-appsec[bot]`) via the Armis backend. Only runs on `pull_request` events and requires the [armis-appsec GitHub App](#branded-pr-comments) installed on the repo. Needs a persisted SARIF file — keep the default `format: sarif` and set `output-file` (e.g. `armis-results.sarif`), or the comment is skipped. |
| `api-url` | No | | Override the Armis API base URL (advanced; defaults to region-derived or production). Equivalent to `ARMIS_API_URL`. |

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

> **Tip — native `--changed` flag:** Outside GitHub Actions (local pre-commit
> hooks, GitLab, Jenkins, etc.), the CLI can detect changed files itself with no
> extra tooling. Use `armis-cli scan repo . --changed=origin/main` to scan only
> what differs from the base branch, or `--changed` for uncommitted work. See
> [Scan Only Changed Files](../README.md#scan-only-changed-files) for all three modes.

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
        uses: ArmisSecurity/armis-cli@v1
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
  uses: ArmisSecurity/armis-cli@v1
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

- **Pin action versions** to a tag or commit SHA. The action publishes floating
  major (`v1`) and minor (`v1.10`) tags that always point at the latest matching
  release, so you can choose how much you want to track automatically:

  ```yaml
  # Good: floating major — receives non-breaking updates automatically
  uses: ArmisSecurity/armis-cli@v1

  # Good: pinned to an exact version — frozen action definition
  uses: ArmisSecurity/armis-cli@v1.10.2

  # Best: pinned to a commit SHA — immutable, recommended for high-security setups
  uses: ArmisSecurity/armis-cli@abc123def456
  ```

  These refs pin the **action definition**, not the CLI binary. The action installs the
  latest released CLI by default (from `releases/latest`), so the CLI version can still
  advance between runs even with the action ref pinned.

- The CLI installation verifies **checksums** automatically
- Release binaries include **SLSA provenance** for verification

---

## Supply Chain Enforcement in CI

The `supply-chain` feature enforces a minimum package **release age** to defend
against typosquatting and compromised-maintainer attacks. See
[FEATURES.md → Supply Chain Enforcement](FEATURES.md#-supply-chain-enforcement)
for the full model; this section covers CI specifics.

### Generating an audit trail

Set `ARMIS_SUPPLY_CHAIN_REPORT` (for wrapped installs) or pass `--report` (for
`supply-chain check`) to emit a machine-readable JSON compliance report — the
evidence a security team needs to prove no young package entered a build:

```yaml
- name: Install dependencies (age-enforced) with compliance report
  env:
    ARMIS_SUPPLY_CHAIN_REPORT: supply-chain-report.json
  run: npm ci

- name: Gate on the compliance report
  run: |
    jq -e '.install_status == "ok" and (.warned_through | length) == 0' \
      supply-chain-report.json

- name: Upload compliance report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: supply-chain-report
    path: supply-chain-report.json
```

The report includes the effective `policy`, the enforcement `mode`
(`proxy` / `pre-install` / `check`), and the `checked` / `blocked` / `resolved` /
`warned_through` / `conflicts` sets.

### Supply Chain Troubleshooting

- **An install failed right after a supply-chain filter.** A brand-new release
  was withheld and an older surviving version may not satisfy a dependent's
  range. On the npm family the failure note names the dependency and who
  required it; unblock with the
  [escape hatches](FEATURES.md#supply-chain-escape-hatches), preferring the most
  surgical option (`ARMIS_SUPPLY_CHAIN_SKIP=<pkg>`) over the kill switch.

- **A pip/uv install failed but no culprit was named.** The one-hop constraint
  attribution is npm-family only. Run `uv tree` or `pipdeptree` to find which
  package requires the blocked dependency.

- **"warn-on-transitive requested but the direct set could not be determined".**
  You set `transitive-policy: warn` (or `ARMIS_SUPPLY_CHAIN_TRANSITIVE=warn`) but
  Armis could not read a root manifest to tell direct from transitive, so it
  failed safe and blocked. Ensure a readable `package.json` is present, or accept
  the safe `block` behavior.

- **A young transitive keeps breaking CI and you accept the risk.** Either add it
  to `exclusions:` in `.armis-supply-chain.yaml` (reviewed, scoped), or enable
  `transitive-policy: warn` (lets young *transitive* deps through with a warning
  while still blocking young *direct* deps — see the residual-risk note in
  FEATURES.md).

### Making enforcement visible to your developers (platform teams)

A developer who didn't add Armis to the pipeline may be confused when a build is
blocked by an unfamiliar `[armis supply-chain]` message. If you roll this out via
shared CI templates, make it discoverable: name the step clearly (e.g.
"Supply-chain age enforcement (managed by Platform)"), link your internal runbook,
and surface the `--report` artifact so the block is auditable rather than opaque.

---

## See Also

- [README - Quick Start](../README.md#quick-start)
- [CLI Usage Reference](../README.md#usage)
- [Output Formats](../README.md#output-formats)
- [Example Workflow Files](ci-examples/)
