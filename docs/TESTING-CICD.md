# Testing CI/CD Pipeline with Armis CLI

This document explains how to test the Armis CLI security scanning in a CI/CD pipeline with intentional failures.

## Overview

The test pipeline demonstrates how Armis CLI integrates into CI/CD workflows and prevents deployments when critical security findings are detected.

## Test Setup

### Test Branch
The test pipeline is configured on the `test-cicd-pipeline` branch.

### Test Files
- **Vulnerable Test File**: `test/vulnerable-test.js`
  - Contains intentional security vulnerabilities (SQL injection, command injection, hardcoded secrets, etc.)
  - Used to trigger critical findings during scanning

### GitHub Actions Workflow
- **Location**: `.github/workflows/test-scan-pipeline.yml`
- **Jobs**:
  1. **scan**: Scans the repository using Armis CLI
     - Installs Armis CLI
     - Runs security scan with `--fail-on CRITICAL`
     - Fails if critical findings are detected
  2. **deploy**: Simulates application deployment
     - Depends on the `scan` job
     - Only runs if scan passes
     - Will NOT execute when critical findings are found

## How It Works

1. **Scan Job Execution**:
   ```bash
   armis-cli scan repo . --format json --fail-on CRITICAL
   ```
   - Scans the entire repository
   - Detects vulnerabilities in `test/vulnerable-test.js`
   - Exits with code 1 when critical findings are found

2. **Deploy Job Blocking**:
   - The `deploy` job has `needs: scan` dependency
   - GitHub Actions automatically skips dependent jobs when a required job fails
   - This prevents deployment of vulnerable code

## Running the Test

### Prerequisites
- GitHub repository with Armis CLI integration
- `ARMIS_API_TOKEN` secret configured in repository settings

### Trigger the Pipeline

**Option 1: Push to branch**
```bash
git checkout test-cicd-pipeline
git push origin test-cicd-pipeline
```

**Option 2: Manual trigger**
- Go to Actions tab in GitHub
- Select "Test Security Scan Pipeline"
- Click "Run workflow"
- Select `test-cicd-pipeline` branch

### Expected Behavior

1. **Scan Job**: ❌ FAILS
   - Detects critical vulnerabilities in test file
   - Exits with non-zero code
   - Logs show critical findings

2. **Deploy Job**: ⏭️ SKIPPED
   - Does not execute
   - Shows as skipped in GitHub Actions UI
   - Prevents vulnerable code from being deployed

## Testing Without Failures

To test a successful pipeline run:

1. Remove or rename the vulnerable test file:
   ```bash
   git mv test/vulnerable-test.js test/vulnerable-test.js.disabled
   ```

2. Push the change:
   ```bash
   git add test/
   git commit -m "Disable vulnerable test file"
   git push origin test-cicd-pipeline
   ```

3. Expected behavior:
   - **Scan Job**: ✅ PASSES (no critical findings)
   - **Deploy Job**: ✅ RUNS (deployment proceeds)

## Customizing Failure Thresholds

Modify the `--fail-on` flag to change which severity levels block deployment:

```yaml
# Fail on HIGH or CRITICAL
armis-cli scan repo . --fail-on HIGH,CRITICAL

# Fail on MEDIUM, HIGH, or CRITICAL
armis-cli scan repo . --fail-on MEDIUM,HIGH,CRITICAL

# Only fail on CRITICAL (default)
armis-cli scan repo . --fail-on CRITICAL
```

## Output Formats

The test pipeline uses JSON format, but you can use other formats:

```yaml
# SARIF format (for GitHub Code Scanning)
armis-cli scan repo . --format sarif > results.sarif

# JUnit XML (for test reporting)
armis-cli scan repo . --format junit > results.xml

# Human-readable (default)
armis-cli scan repo . --format human
```

## Cleanup

To remove the test setup:

```bash
# Delete the test branch
git checkout main
git branch -D test-cicd-pipeline
git push origin --delete test-cicd-pipeline

# Remove test files (if merged to main)
git rm test/vulnerable-test.js
git rm .github/workflows/test-scan-pipeline.yml
git commit -m "Remove CI/CD test files"
```

## Integration with Real Workflows

To integrate this pattern into your production workflows:

1. Add the scan job to your existing workflow
2. Make deployment jobs depend on the scan job using `needs: scan`
3. Configure appropriate `--fail-on` thresholds for your security requirements
4. Store `ARMIS_API_TOKEN` in GitHub Secrets
5. Consider using SARIF output for GitHub Code Scanning integration

## Troubleshooting

### Scan Job Passes When It Should Fail
- Verify `test/vulnerable-test.js` exists and contains vulnerabilities
- Check that `ARMIS_API_TOKEN` is correctly configured
- Ensure the scan is analyzing the correct directory

### Deploy Job Runs When Scan Fails
- Verify the `needs: scan` dependency is configured
- Check GitHub Actions logs for job dependencies

### CLI Not Found
- Ensure the install script runs successfully
- Verify `$HOME/.local/bin` is added to PATH
- Check the install step logs for errors

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Armis CLI README](../README.md)
- [CI/CD Examples](./ci-examples/)
