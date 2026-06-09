# Distribution Setup Guide

This document outlines the steps needed to complete the distribution setup for armis-cli.

## ✅ Completed Changes

1. **Fixed GoReleaser Signing**
   - Added `id-token: write` permission to GitHub Actions workflow
   - Added `COSIGN_YES` and `COSIGN_EXPERIMENTAL` environment variables
   - This fixes the "context deadline exceeded" error with Sigstore/Rekor

2. **Updated Repository References**
   - Changed module name from `github.com/silk-security/armis-cli` to `github.com/silk-security/armis-cli`
   - Updated all import paths in Go code
   - Updated all URLs in README and documentation

3. **Enhanced Distribution Channels**
   - Configured Homebrew tap: `ArmisSecurity/homebrew-tap`
   - Configured Scoop bucket: `ArmisSecurity/scoop-bucket`
   - Enhanced install scripts with signature verification
   - Created Windows PowerShell installer

4. **Improved Install Scripts**
   - `scripts/install.sh`: Now verifies signatures with cosign and checksums
   - `scripts/install.ps1`: New Windows installer with verification

5. **Updated Documentation**
   - README now includes all installation methods
   - Added verification instructions
   - Updated all CI/CD examples

## 🔧 Required Setup Steps

### 1. Create GitHub Repositories

You need to create two new repositories in the `armis` organization:

#### Homebrew Tap Repository

```bash
# Create repository: ArmisSecurity/homebrew-tap
# This will be auto-populated by GoReleaser on each release
```

**Repository Settings:**

- Name: `homebrew-tap`
- Description: "Homebrew formulae for Armis CLI tools"
- Public repository
- Initialize with README (optional)

#### Scoop Bucket Repository

```bash
# Create repository: ArmisSecurity/scoop-bucket
# This will be auto-populated by GoReleaser on each release
```

**Repository Settings:**

- Name: `scoop-bucket`
- Description: "Scoop bucket for Armis CLI tools"
- Public repository
- Initialize with README (optional)

### 2. Update Main Repository

If you're moving from `silk-security/armis-cli` to `armis/armis-cli`:

1. **Create the new repository** `armis/armis-cli`
2. **Push your code** to the new repository
3. **Update GitHub secrets** (if any) in the new repository
4. **Archive the old repository** with a redirect notice

### 3. Test the Release Process

Before creating a real release, test with a snapshot:

```bash
# Install GoReleaser locally
brew install goreleaser

# Test the release configuration
goreleaser release --snapshot --skip-publish --clean

# Check the dist/ directory for generated artifacts
ls -la dist/
```

### 4. Create Your First Release

Once everything is set up:

```bash
# Tag a new version
git tag -a v1.0.0 -m "First release with new distribution setup"

# Push the tag (this triggers the release workflow)
git push origin v1.0.0
```

GoReleaser will automatically:

- Build binaries for all platforms
- Sign checksums with cosign
- Create GitHub release with notes
- Update Homebrew tap formula
- Update Scoop bucket manifest

## 🛒 Publishing the GitHub Action to the Marketplace

The repository ships a composite GitHub Action defined in the top-level
[`action.yml`](../action.yml) (`name: Armis Security Scanner`). Consumers reference it as
`uses: ArmisSecurity/armis-cli@v1`. Publishing it to the GitHub Marketplace is a **one-time
manual step** done through the GitHub UI — it cannot be automated by the release workflow.

### Prerequisites (already satisfied)

- `action.yml` exists at the repository root with a unique `name`, a `description`, and a
  `branding:` block (`icon: shield`, `color: blue`). GitHub requires `branding` for Marketplace
  listing.
- At least one release tag exists (the latest is created automatically by
  [`release.yml`](../.github/workflows/release.yml)).

### One-time publish steps

1. Go to the repository's **Releases** page on GitHub and open (or draft) a release for the
   latest version tag.
2. Check **"Publish this Action to the GitHub Marketplace"**.
3. Accept the GitHub Marketplace Developer Agreement (first time only).
4. Choose a primary category of **Security** (and an optional secondary category such as
   *Continuous integration*).
5. Resolve any validation warnings GitHub surfaces (it re-validates `action.yml` and `branding`).
6. Publish the release.

### Versioning and floating tags

The release workflow maintains **floating major and minor tags** (`v1`, `v1.10`) that always
point at the latest matching stable release (see the `update-aliases` job in `release.yml`).
This lets consumers pin at the level of stability they want:

| Reference | Behavior |
|-----------|----------|
| `@v1` | Latest `v1.x.y` — non-breaking updates delivered automatically (recommended) |
| `@v1.10` | Latest `v1.10.x` — patch updates only |
| `@v1.10.2` | Exact action definition — frozen action logic |
| `@<sha>` | Immutable commit pin — strongest supply-chain guarantee |

> **Note:** These refs pin the *action definition*, not the CLI binary. The action installs the
> latest released CLI by default (`releases/latest`), so the scanned-with CLI version can advance
> even when the action ref is pinned.

Re-publishing to the Marketplace is only required when you want the Marketplace listing's
"latest version" pointer to advance; the floating tags update on every release regardless.

## 📦 Installation Methods After Setup

Once released, users can install via:

### Homebrew (macOS/Linux)

```bash
brew install armis/tap/armis-cli
```

### Scoop (Windows)

```powershell
scoop bucket add armis https://github.com/ArmisSecurity/scoop-bucket
scoop install armis-cli
```

### Install Script (Linux/macOS)

```bash
curl -sSL https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.sh | bash
```

### Install Script (Windows)

```powershell
irm https://raw.githubusercontent.com/armis/armis-cli/main/scripts/install.ps1 | iex
```

### Go Install

```bash
go install github.com/ArmisSecurity/armis-cli/cmd/armis-cli@latest
```

### Manual Download

Download from: <https://github.com/ArmisSecurity/armis-cli/releases>

## 🔐 Signature Verification

All releases are signed with cosign (keyless signing via GitHub OIDC).

Users can verify downloads:

```bash
# Download files
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-linux-amd64.tar.gz
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt
curl -LO https://github.com/ArmisSecurity/armis-cli/releases/latest/download/armis-cli-checksums.txt.sig

# Verify signature
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/ArmisSecurity/armis-cli/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature armis-cli-checksums.txt.sig \
  armis-cli-checksums.txt

# Verify checksum
sha256sum --ignore-missing -c armis-cli-checksums.txt
```

## 🐛 Troubleshooting

### Cosign Signing Still Fails

If you still see timeout errors:

1. Check that `id-token: write` permission is set in the workflow
2. Verify `COSIGN_YES` and `COSIGN_EXPERIMENTAL` are set
3. Check GitHub Actions logs for detailed error messages
4. Ensure you're using cosign v2.2.2 or later

### Homebrew/Scoop Updates Fail

If GoReleaser can't push to tap/bucket repositories:

1. Verify the repositories exist and are public
2. Check that `GITHUB_TOKEN` has write access to those repos
3. Review GoReleaser logs in GitHub Actions

### Module Import Issues

If users report import issues:

1. Ensure `go.mod` has the correct module name: `github.com/ArmisSecurity/armis-cli`
2. Tag and push a new release
3. Wait for Go proxy to update (can take a few minutes)

## 📝 Next Steps

1. ✅ Create `ArmisSecurity/homebrew-tap` repository
2. ✅ Create `ArmisSecurity/scoop-bucket` repository
3. ✅ Create `ArmisSecurity/armis-cli` repository (if moving from silk-security)
4. ✅ Push code to new repository
5. ✅ Test snapshot release locally
6. ✅ Create and push first version tag
7. ✅ Verify all installation methods work
8. ✅ Update any external documentation/links

## 🎉 Success Criteria

You'll know everything is working when:

- ✅ GitHub release is created automatically on tag push
- ✅ Binaries are built for all platforms
- ✅ Checksums are signed with cosign
- ✅ Homebrew formula is updated in `ArmisSecurity/homebrew-tap`
- ✅ Scoop manifest is updated in `ArmisSecurity/scoop-bucket`
- ✅ Users can install via `brew install armis/tap/armis-cli`
- ✅ Users can install via `scoop install armis-cli`
- ✅ Install scripts work and verify signatures
