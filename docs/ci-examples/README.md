# CI/CD Example Configurations

This directory contains ready-to-use configuration examples for integrating Armis security scanning into your CI/CD pipeline.

For comprehensive documentation including advanced patterns and troubleshooting, see the [CI Integration Guide](../CI-INTEGRATION.md).

## GitHub Actions

| File | Description |
|------|-------------|
| [github-actions-reusable.yml](github-actions-reusable.yml) | **Recommended** - Uses the reusable workflow for simplest setup |
| [github-actions.yml](github-actions.yml) | Direct action usage for more control |
| [github-actions-pr-scan.yml](github-actions-pr-scan.yml) | PR scanning with changed file detection |
| [github-actions-scheduled.yml](github-actions-scheduled.yml) | Scheduled full repository scans |

## Other Platforms

| File | Description |
|------|-------------|
| [gitlab-ci.yml](gitlab-ci.yml) | GitLab CI/CD configuration |
| [Jenkinsfile](Jenkinsfile) | Jenkins declarative pipeline |
| [azure-pipelines.yml](azure-pipelines.yml) | Azure DevOps pipeline |
| [circleci-config.yml](circleci-config.yml) | CircleCI configuration |
| [bitbucket-pipelines.yml](bitbucket-pipelines.yml) | Bitbucket Pipelines configuration |

## Required Secrets

All examples require authentication secrets to be configured in your CI platform.

**JWT Authentication (Recommended):**

Obtain credentials from the VIPR external API screen in the Armis platform.

| Secret | Description |
|--------|-------------|
| `ARMIS_CLIENT_ID` | Client ID for JWT authentication |
| `ARMIS_CLIENT_SECRET` | Client secret for JWT authentication |

**Basic Authentication (Legacy):**

| Secret | Description |
|--------|-------------|
| `ARMIS_API_TOKEN` | API token for Basic authentication |
| `ARMIS_TENANT_ID` | Tenant identifier (not needed with JWT) |

## SBOM and VEX Generation

Generate Software Bill of Materials and Vulnerability Exploitability eXchange documents alongside your scans:

```bash
armis-cli scan repo . \
  --sbom --vex \
  --sbom-output ./artifacts/sbom.json \
  --vex-output ./artifacts/vex.json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Generate SBOM (CycloneDX by default) | `false` |
| `--sbom-format` | SBOM format: `cyclonedx` or `spdx` (SPDX 2.3) | `cyclonedx` |
| `--vex` | Generate VEX document | `false` |
| `--sbom-output` | Custom SBOM output path | `.armis/<artifact>-sbom.json` |
| `--vex-output` | Custom VEX output path | `.armis/<artifact>-vex.json` |
| `--bom` | BOM types to download: `sbom`, `aibom`, `cbom`, `all` | none |
| `--bom-format` | BOM format, such as `cyclonedx-1.7` or `spdx-2.3` | `cyclonedx-1.7` |
| `--bom-output` | Directory for BOM files, or `-` for stdout | `.armis` |

Store SBOM/VEX artifacts for compliance and audit purposes. See the [CI Integration Guide](../CI-INTEGRATION.md#sbom-and-vex-generation) for detailed examples.

To download an AI-BOM and a CBOM (BOM generation must be enabled for your tenant):

```bash
armis-cli scan repo . --bom aibom,cbom --bom-output ./artifacts
```

A BOM that was built but cannot be downloaded exits `2`, unless `--fail-on` triggers first. See [AI-BOM, CBOM and other BOMs](../CI-INTEGRATION.md#ai-bom-cbom-and-other-boms).

## Quick Start

### For GitHub Actions

Copy the appropriate example file to `.github/workflows/` in your repository:

```bash
# Recommended: Reusable workflow
curl -o .github/workflows/security-scan.yml \
  https://raw.githubusercontent.com/ArmisSecurity/armis-cli/main/docs/ci-examples/github-actions-reusable.yml
```

### For Other Platforms

Copy the example file for your platform to the appropriate location:

- **GitLab**: `.gitlab-ci.yml` (root)
- **Jenkins**: `Jenkinsfile` (root)
- **Azure DevOps**: `azure-pipelines.yml` (root or `.azure-pipelines/`)
- **CircleCI**: `.circleci/config.yml`
- **Bitbucket**: `bitbucket-pipelines.yml` (root)
