<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-light.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/logo-dark.svg">
  <img alt="Armis AppSec Logo" src="docs/assets/logo-dark.svg">
</picture>

# Armis CLI

[![Build Status](https://github.com/ArmisSecurity/armis-cli/actions/workflows/release.yml/badge.svg)](https://github.com/ArmisSecurity/armis-cli/actions)
[![Go Version](https://img.shields.io/badge/go-1.25+-blue)](https://golang.org/dl/)
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
- [Shell Completion](#shell-completion)
- [Quick Start](#quick-start)
- [Verification](#verification)
- [Usage](#usage)
- [Supply Chain Protection](#supply-chain-protection)
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
- **SBOM generation**: Generate CycloneDX Software Bill of Materials
- **VEX generation**: Generate Vulnerability Exploitability eXchange documents
- **Supply chain protection**: Block packages published too recently (typosquatting, compromised maintainers, dependency confusion) across npm, Python, and Java — no Armis Cloud auth required
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

### Scoop (Windows) — Coming Soon

> Scoop support is planned. For now, use the PowerShell installer above or [download manually](#manual-download).

### Manual Download

Download the latest release for your platform from the [releases page](https://github.com/ArmisSecurity/armis-cli/releases).

<details>
<summary>Windows manual install steps</summary>

1. Download `armis-cli-windows-amd64.zip` from the [releases page](https://github.com/ArmisSecurity/armis-cli/releases)
2. Extract the ZIP (right-click > **Extract All**, or use PowerShell):

   ```powershell
   Expand-Archive armis-cli-windows-amd64.zip -DestinationPath .
   ```

3. Move `armis-cli.exe` to a directory in your PATH, or add its location:

   ```powershell
   $dir = "C:\Tools\armis-cli"
   New-Item -ItemType Directory -Path $dir -Force
   Move-Item armis-cli.exe $dir\
   $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
   if ([string]::IsNullOrEmpty($userPath)) {
     $newPath = $dir
   } else {
     $newPath = "$userPath;$dir"
   }
   [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
   ```

4. Restart your terminal for PATH changes to take effect.

> **Note:** These instructions use the `windows/amd64` (64-bit Intel/AMD) build. If other Windows architectures (such as ARM64) are available on the releases page, download the archive that matches your system and follow the same steps.

</details>

### Using Go

```bash
go install github.com/ArmisSecurity/armis-cli/cmd/armis-cli@latest
```

### Verify Installation

After installation, verify that the CLI is working:

**Linux/macOS:**

```bash
which armis-cli
armis-cli --version
```

**Windows (PowerShell):**

```powershell
Get-Command armis-cli
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

#### Windows (PowerShell)

1. **Check if it's installed:**

   ```powershell
   Test-Path "$env:LOCALAPPDATA\armis-cli\armis-cli.exe"
   ```

2. **Check your PATH:**

   ```powershell
   $env:Path -split ';' | Where-Object { $_ -like '*armis*' }
   ```

3. **Add to PATH if needed:**

   ```powershell
   $dir = "$env:LOCALAPPDATA\armis-cli"
   $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
   if ([string]::IsNullOrEmpty($userPath)) {
     $newPath = $dir
   } else {
     $newPath = "$userPath;$dir"
   }
   [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
   ```

   Then restart your terminal.

4. **Run directly with full path:**

   ```powershell
   & "$env:LOCALAPPDATA\armis-cli\armis-cli.exe" --help
   ```

### Shell Completion

`armis-cli` ships tab-completion for commands, subcommands, and flag values (e.g.
`--format <TAB>` offers `human/json/sarif/junit`). Generate the script for your
shell with `armis-cli completion <shell>`; run `armis-cli completion <shell> --help`
for the full instructions.

**Bash** (requires the `bash-completion` package):

```bash
# Current shell session
source <(armis-cli completion bash)

# Every new session (Linux)
armis-cli completion bash > /etc/bash_completion.d/armis-cli

# Every new session (macOS)
armis-cli completion bash > $(brew --prefix)/etc/bash_completion.d/armis-cli
```

**Zsh** (enable completion once with `echo "autoload -U compinit; compinit" >> ~/.zshrc`):

```zsh
# Current shell session
source <(armis-cli completion zsh)

# Every new session (Linux)
armis-cli completion zsh > "${fpath[1]}/_armis-cli"

# Every new session (macOS)
armis-cli completion zsh > $(brew --prefix)/share/zsh/site-functions/_armis-cli
```

**Fish:**

```fish
# Current shell session
armis-cli completion fish | source

# Every new session
armis-cli completion fish > ~/.config/fish/completions/armis-cli.fish
```

**PowerShell:**

```powershell
# Current shell session
armis-cli completion powershell | Out-String | Invoke-Expression

# Every new session: add the output of the above command to your PowerShell profile
```

Start a new shell for the persistent setup to take effect.

---

## Quick Start

### Try it without credentials

No Armis account needed — audit your project's dependencies for supply-chain risk in one command. Run it from a project directory that contains a supported lockfile (e.g. `package-lock.json`, `poetry.lock`, `pom.xml`):

```bash
brew install armissecurity/tap/armis-cli
cd path/to/your/project
armis-cli supply-chain check
```

This checks your lockfile against public registries (npm, PyPI, Maven Central) for recently published packages — a common signal of typosquatting or compromised maintainers. If no lockfile is found, the command reports `no lockfile detected` — point it at a project with `armis-cli supply-chain check <path>` or `--lockfile <file>`. See [Supply Chain Protection](#supply-chain-protection) for details. To scan code for vulnerabilities and secrets, set up authentication below.

### Set up authentication

#### JWT Authentication (Recommended)

Obtain client credentials from the VIPR external API screen in the Armis platform.

```bash
export ARMIS_CLIENT_ID="your-client-id"
export ARMIS_CLIENT_SECRET="your-client-secret"
```

**PowerShell:**

```powershell
$env:ARMIS_CLIENT_ID = "your-client-id"
$env:ARMIS_CLIENT_SECRET = "your-client-secret"
```

The tenant ID is automatically extracted from the JWT token — no need to set it separately.

#### Basic Authentication (Legacy)

```bash
export ARMIS_API_TOKEN="your-api-token"
export ARMIS_TENANT_ID="your-tenant-id"
```

**PowerShell:**

```powershell
$env:ARMIS_API_TOKEN = "your-api-token"
$env:ARMIS_TENANT_ID = "your-tenant-id"
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

## Verification

All releases include cryptographic signatures, SBOMs, and SLSA Level 3 provenance attestations for supply chain security. Verifying them is optional — expand the section below when you need it.

<details>
<summary>Verify release signatures, SLSA provenance &amp; SBOM</summary>

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

<details>
<summary>PowerShell equivalent</summary>

```powershell
# Download the binary, checksums, and signature
Invoke-WebRequest -Uri "https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-windows-amd64.zip" -OutFile armis-cli-windows-amd64.zip
Invoke-WebRequest -Uri "https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt" -OutFile armis-cli-checksums.txt
Invoke-WebRequest -Uri "https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt.sig" -OutFile armis-cli-checksums.txt.sig

# Verify the signature (requires cosign: https://docs.sigstore.dev/cosign/installation/)
cosign verify-blob `
  --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  --signature armis-cli-checksums.txt.sig `
  armis-cli-checksums.txt

# Verify the checksum
$expected = (Get-Content armis-cli-checksums.txt | Select-String "armis-cli-windows-amd64.zip") -replace '\s+.*'
$actual = (Get-FileHash armis-cli-windows-amd64.zip -Algorithm SHA256).Hash.ToLower()
if ($expected -eq $actual) { Write-Host "Checksum OK" -ForegroundColor Green } else { Write-Error "Checksum mismatch" }
```

</details>

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

<details>
<summary>PowerShell equivalent</summary>

```powershell
# Download SBOM
Invoke-WebRequest -Uri "https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-windows-amd64.zip.sbom.cdx.json" -OutFile sbom.cdx.json

# View dependencies
(Get-Content sbom.cdx.json | ConvertFrom-Json).components | Select-Object name, version | Format-Table
```

</details>

**Learn more:**

- [SLSA Framework](https://slsa.dev/)
- [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/)
- [CycloneDX SBOM](https://cyclonedx.org/)

</details>

---

## Usage

### Global Flags

#### Authentication Flags

```text
--client-id string      Client ID for JWT authentication (env: ARMIS_CLIENT_ID) [recommended]
--client-secret string  Client secret for JWT authentication (env: ARMIS_CLIENT_SECRET) [recommended]
--region string         Armis cloud region (env: ARMIS_REGION)
--token string          API token for Basic authentication (env: ARMIS_API_TOKEN) [legacy]
--tenant-id string      Tenant identifier for Basic auth (env: ARMIS_TENANT_ID) [legacy]
```

#### General Flags

```text
--format string         Output format: human, json, sarif, junit (default: human)
--no-progress           Disable progress indicators
--fail-on strings       Fail build on severity levels (default: [CRITICAL])
--exit-code int         Exit code to use when failing (default: 1)
--page-limit int        Results page size for pagination (default: 500, range: 1-1000)
--color string          Control colored output: auto, always, never (default: auto)
--theme string          Terminal background theme: auto, dark, light (default: auto)
--no-update-check       Disable automatic update checking
--dev                   Use development environment instead of production
--debug                 Enable debug mode for detailed API responses
```

> The `--sbom`, `--vex`, `--sbom-output`, and `--vex-output` flags are specific to the `scan` commands — see [Scan Repository](#scan-repository).

### Scan Repository

Scans a local directory, creates a tarball, and uploads to Armis Cloud for analysis.

```bash
armis-cli scan repo [path]
```

**Size Limit**: 2GB
**Example**:

```bash
armis-cli scan repo ./my-app --format json --fail-on HIGH,CRITICAL

# Generate SBOM and VEX documents
armis-cli scan repo ./my-app --sbom --vex
```

#### Scan Only Changed Files

Speed up PR and pre-commit feedback by scanning only the files that changed,
instead of the whole repository. The `--changed` flag has three modes:

```bash
# All uncommitted changes (staged + unstaged + untracked) vs HEAD
armis-cli scan repo . --changed

# Staged changes only (what `git commit` would include)
armis-cli scan repo . --changed=staged

# Changes relative to a branch, tag, or commit (great for PRs)
armis-cli scan repo . --changed=main
armis-cli scan repo . --changed=origin/main
armis-cli scan repo . --changed=HEAD~3
```

Notes:

- Requires a git repository. If no files changed, the scan exits early with nothing to do.
- `staged` and `uncommitted` are reserved keywords and cannot be used as ref names.
- `--changed` is mutually exclusive with `--include-files` (use one or the other).

See [PR Scanning with Changed Files](docs/CI-INTEGRATION.md#pr-scanning-with-changed-files) for CI usage.

### Scan Container Image

Scans a container image (local or remote) or a tarball.

```bash
armis-cli scan image [image-name]
armis-cli scan image --tarball [path-to-tarball]
```

**Size Limit**: 5GB
**Examples**:

```bash
# Scan remote image
armis-cli scan image nginx:latest
# Scan local image
armis-cli scan image my-app:v1.0.0
# Scan tarball
armis-cli scan image --tarball ./image.tar
```

#### Pull Policy

Control how images are fetched before scanning:

```bash
# Use local image if available, otherwise pull (default)
armis-cli scan image nginx:latest --pull=missing

# Always pull latest from registry (recommended for CI/CD)
armis-cli scan image nginx:latest --pull=always

# Never pull, require local image (for air-gapped environments)
armis-cli scan image nginx:latest --pull=never
```

### Other Commands

```bash
# Detect AI coding agents (Claude Code, Cursor, Copilot, ...) and whether
# the Armis AppSec MCP is enabled. Run with sudo to scan all user profiles.
armis-cli agent-detection

# Install a git pre-commit hook that blocks commits unless scanning passed.
# Use --fail-open to warn instead of block, or --remove to uninstall.
armis-cli hook init

# Generate a shell completion script (bash, zsh, fish, PowerShell).
armis-cli completion zsh > "${fpath[1]}/_armis-cli"
```

Run `armis-cli <command> --help` for the full flag reference of any command.

---

## Supply Chain Protection

The `supply-chain` command enforces a minimum **release age** on your dependencies. Packages published more recently than the threshold (default 72h) are flagged or blocked — a cheap, effective defense against typosquatting, compromised maintainer accounts, and dependency-confusion attacks, which almost always rely on a freshly published malicious version.

No Armis Cloud authentication is required: `supply-chain` queries public registries (npm, PyPI, Maven Central) directly.

**Supported ecosystems:** npm, npx, pnpm, bun, yarn (Node); pip, uv, uvx, poetry, pipenv, pdm (Python); Maven, Gradle (Java).

### Audit a lockfile (CI)

```bash
# Audit the lockfile in the current directory (auto-detected)
armis-cli supply-chain check

# Custom threshold, exclude your own scoped packages, fail the build on findings
armis-cli supply-chain check --min-age 7d --exclude "@myorg/*" --fail-on medium

# Machine-readable output for CI
armis-cli supply-chain check --format sarif --fail-on high

# Write results to a file (format auto-detected from the extension)
armis-cli supply-chain check -o supply-chain.sarif --fail-on high
```

By default `check` only reports packages that are **new** versus the base branch lockfile (auto-detected from `origin/main`). Use `--all` to audit every package, and `--fail-open` to pass when the registry is unreachable.

> **Fail the build:** `check` reports findings as MEDIUM/HIGH severity. To gate CI, pass `--fail-on medium` (or `high`) — the default `--fail-on` is CRITICAL, which supply-chain findings never reach.

### Enforce locally during installs

```bash
# Wrap your package managers in ~/.bashrc / ~/.zshrc (interactive)
armis-cli supply-chain init

# Preview changes without writing
armis-cli supply-chain init --dry-run

# Generate a committable policy file (.armis-supply-chain.yaml)
armis-cli supply-chain init --mode config

# Show the active policy, detected ecosystems, and shell status
armis-cli supply-chain status

# Remove the shell wrappers
armis-cli supply-chain uninit
```

### Configuration

Commit a `.armis-supply-chain.yaml` to share policy with your team:

```yaml
version: 1
min-age: 72h
exclusions:
  - "@myorg/*"
# ecosystems:          # optional: restrict to specific ecosystems (default: all detected)
#   - npm
#   - pip
# transitive-policy: warn   # optional: let young TRANSITIVE deps through with a warning
#                           # (direct deps still blocked); default: block
fail-open: false
```

### Unblocking a build (most surgical → most blunt)

When a brand-new release is blocking you, prefer the most reviewable option:

1. **Allow one package** (persists in this env, exempts its future versions): `ARMIS_SUPPLY_CHAIN_SKIP=<pkg> npm install`
2. **Permanent team exception**: add `<pkg>` to `exclusions:` in `.armis-supply-chain.yaml`
3. **Relax the window for all packages**: edit `min-age:` in `.armis-supply-chain.yaml`
4. **Emergency kill switch**: `ARMIS_SUPPLY_CHAIN=off npm install`

Because the age proxy is graph-blind, a withheld young version can make a transitive dependency unsatisfiable and fail an install. On the npm family Armis names the culprit (and who required it); you can also opt into `transitive-policy: warn` to let young *transitive* deps through while still blocking young *direct* ones. Generate an audit trail with `ARMIS_SUPPLY_CHAIN_REPORT=<path>` (wrapped installs) or `--report <path>` (`check`). See **[docs/FEATURES.md → Supply Chain Enforcement](docs/FEATURES.md#-supply-chain-enforcement)** for the full model, limitations, and residual-risk notes.

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
  actions: read
  security-events: write
  pull-requests: write

jobs:
  security-scan:
    uses: ArmisSecurity/armis-cli/.github/workflows/reusable-security-scan.yml@main
    with:
      fail-on: CRITICAL,HIGH
    secrets:
      client-id: ${{ secrets.ARMIS_CLIENT_ID }}
      client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
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
| `region` | string | | Armis cloud region (overrides auto-discovery) |

**Required secrets:**

- `client-id`: Client ID for JWT authentication (from VIPR external API screen)
- `client-secret`: Client secret for JWT authentication

> **Legacy:** For backward compatibility, `api-token` and `tenant-id` secrets are also accepted.

#### Option 2: GitHub Action

Use the action directly for more control over your workflow. Pin to the major version tag
(`@v1`) to receive non-breaking updates automatically, or pin to an exact tag (`@v1.10.2`) or
commit SHA to freeze the action definition. Note that the action installs the latest released
CLI binary by default, so pinning the action ref alone does not pin the CLI version itself:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ArmisSecurity/armis-cli@v1
        with:
          scan-type: repo
          client-id: ${{ secrets.ARMIS_CLIENT_ID }}
          client-secret: ${{ secrets.ARMIS_CLIENT_SECRET }}
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
      actions: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Install Armis CLI
        run: |
          curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
      - name: Scan Repository
        env:
          ARMIS_CLIENT_ID: ${{ secrets.ARMIS_CLIENT_ID }}
          ARMIS_CLIENT_SECRET: ${{ secrets.ARMIS_CLIENT_SECRET }}
        run: |
          armis-cli scan repo . \
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
    - armis-cli scan repo . --format json --fail-on CRITICAL
  variables:
    ARMIS_CLIENT_ID: $ARMIS_CLIENT_ID
    ARMIS_CLIENT_SECRET: $ARMIS_CLIENT_SECRET
```

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
    curl -sSL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/scripts/install.sh | bash
  displayName: 'Install Armis CLI'
- script: |
    armis-cli scan repo . --format junit > $(Build.ArtifactStagingDirectory)/scan-results.xml
  env:
    ARMIS_CLIENT_ID: $(ARMIS_CLIENT_ID)
    ARMIS_CLIENT_SECRET: $(ARMIS_CLIENT_SECRET)
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
            armis-cli scan repo . --format json --fail-on HIGH,CRITICAL
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
          - armis-cli scan repo . --format json --fail-on CRITICAL
```

---

## Environment Variables

**JWT Authentication (Recommended):**

| Variable | Description |
|----------|-------------|
| `ARMIS_CLIENT_ID` | Client ID for JWT authentication (from VIPR external API screen) |
| `ARMIS_CLIENT_SECRET` | Client secret for JWT authentication |
| `ARMIS_REGION` | Armis cloud region (equivalent to `--region` flag) |

When using JWT authentication, the tenant ID is automatically extracted from the token.

**Basic Authentication (Legacy):**

| Variable | Description |
|----------|-------------|
| `ARMIS_API_TOKEN` | API token for Basic authentication |
| `ARMIS_TENANT_ID` | Tenant identifier (required only with Basic auth) |

**General:**

| Variable | Description |
|----------|-------------|
| `ARMIS_FORMAT` | Default output format |
| `ARMIS_PAGE_LIMIT` | Results pagination size (default: 500) |
| `ARMIS_THEME` | Terminal background theme: auto, dark, light (default: auto) |
| `ARMIS_NO_UPDATE_CHECK` | Disable automatic update checking |

---

## Security Considerations

- **Size Limits**: Enforced to prevent resource exhaustion
  - Repositories: 2GB
  - Container Images: 5GB
- **Authentication Security**:
  - Client credentials and API tokens should be stored securely and never committed to version control
  - Use JWT authentication (client ID/secret) for production — it supports automatic token refresh and does not require a separate tenant ID
  - Rotate credentials periodically
  - Credentials are never logged or exposed in output
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

- Pre-built binaries for macOS and Linux (amd64 and arm64) and Windows (amd64)
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

**Windows (without Make):**

```powershell
git clone https://github.com/ArmisSecurity/armis-cli.git
cd armis-cli
go build -o bin\armis-cli.exe ./cmd/armis-cli
```

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
