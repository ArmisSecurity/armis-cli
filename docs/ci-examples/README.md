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

All examples require these secrets to be configured in your CI platform:

| Secret | Description |
|--------|-------------|
| `ARMIS_API_TOKEN` | Your Armis API token for authentication |
| `ARMIS_TENANT_ID` | Your Armis tenant identifier |

## SBOM and VEX Generation

Generate Software Bill of Materials and Vulnerability Exploitability eXchange documents alongside your scans:

```bash
armis-cli scan repo . \
  --tenant-id "$ARMIS_TENANT_ID" \
  --sbom --vex \
  --sbom-output ./artifacts/sbom.json \
  --vex-output ./artifacts/vex.json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Generate CycloneDX SBOM | `false` |
| `--vex` | Generate VEX document | `false` |
| `--sbom-output` | Custom SBOM output path | `.armis/<artifact>-sbom.json` |
| `--vex-output` | Custom VEX output path | `.armis/<artifact>-vex.json` |

Store SBOM/VEX artifacts for compliance and audit purposes. See the [CI Integration Guide](../CI-INTEGRATION.md#sbom-and-vex-generation) for detailed examples.

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
