# BOM Guide: AI-BOM, CBOM and SBOM

This guide covers the bills of materials (BOMs) that Armis builds from the code or container image the Armis CLI uploads. It describes armis-cli 1.28.0.

## Contents

- [BOM types](#bom-types)
- [Before you start](#before-you-start)
- [Choose a command](#choose-a-command)
- [BOMs with a security scan: `scan --bom`](#boms-with-a-security-scan-scan---bom)
- [BOMs without a security scan: `bom repo` and `bom image`](#boms-without-a-security-scan-bom-repo-and-bom-image)
- [Formats](#formats)
- [Output files](#output-files)
- [Writing a BOM to stdout](#writing-a-bom-to-stdout)
- [Exit codes](#exit-codes)
- [Warnings and what to do](#warnings-and-what-to-do)
- [CI examples](#ci-examples)
- [Reading the files](#reading-the-files)
- [API](#api)
- [Limits](#limits)
- [Data handling](#data-handling)
- [Troubleshooting](#troubleshooting)

## BOM types

| Type | Value | What it lists | What it is for |
|------|-------|---------------|----------------|
| SBOM (software bill of materials) | `sbom` | The packages in the code or image, with versions and package URLs (purls), and the lock files, manifests or binaries they came from. | Supply chain and license reviews, vulnerability tracking, SBOM requests from customers and regulators. |
| AI-BOM (AI bill of materials) | `aibom` | AI models, AI providers, MCP servers and their tools, AI and MCP packages, and AI-related files. See the list below the table. | Knowing which AI the code uses and where: AI usage reviews, MCP server approval, AI governance. |
| CBOM (cryptographic bill of materials) | `cbom` | Certificates, public keys and algorithms found in certificate, key and configuration files, and algorithms called in source code. | Finding weak or quantum-vulnerable cryptography, expiring certificates, and planning a post-quantum migration. |
| Combined BOM | `all` | The SBOM, AI-BOM and CBOM in one document, with duplicates merged. | One file for tools that read a single BOM. |

The AI-BOM lists:

- AI models named in the code;
- the AI providers and MCP servers the code uses or implements, and the tools those servers register;
- AI and MCP packages;
- MCP configuration files, and agent-instruction, skill and prompt files, by path, without their content.

Items found in code name the file and line.

Every BOM is a JSON file. The default format is CycloneDX 1.7. The SBOM is also offered in SPDX 2.3.

## Before you start

- **CLI version.** `armis-cli scan ... --bom` needs armis-cli 1.27.0 or later. `armis-cli bom` needs 1.28.0 or later. Check with `armis-cli --version`.
- **BOM generation.** BOM generation is on by default for every tenant. Armis can turn it off for a tenant. When it is off, `armis-cli bom` exits with code 1 and `bom_generation_disabled`, and `scan --bom` runs the scan but writes no BOM.
- **Authentication.** The `bom` and `scan` commands use the same credentials:
  - In CI, use client credentials. Create them in Armis Centrix under **Settings > API Access > Create API Credentials**, then set `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET`. The tenant ID comes from the token.
  - On a developer machine, sign in with SSO: `armis-cli auth login --tenant-id <tenant-id>` (or with `ARMIS_TENANT_ID` set), or set `ARMIS_DEFAULT_AUTH_METHOD=SSO` with `ARMIS_TENANT_ID`. See the [SSO Setup Guide](SSO-SETUP.md).
  - The legacy API token (`ARMIS_API_TOKEN` with `ARMIS_TENANT_ID`) also works.
- **Role.** The API calls behind these commands accept the developer and admin roles.
- **Region.** The CLI finds the region from your credentials. Set `--region` or `ARMIS_REGION` to override it.
- **Images.** To build the BOMs of an image by name, Docker or Podman must be running. Without one, save the image first (`docker save -o image.tar <image>`) and pass `--tarball`.

## Choose a command

| You want | Use |
|----------|-----|
| Findings and BOMs from one scan, for example in an existing CI security step | `armis-cli scan repo <path> --bom <types>` or `armis-cli scan image <image> --bom <types>` |
| Only the BOMs, as fast as possible | `armis-cli bom repo <path>` or `armis-cli bom image <image>` |
| A `--fail-on` gate on findings | `scan --bom` (`bom` has no findings and no `--fail-on`) |
| BOMs of only some files of a repository | `scan repo --changed` or `--include-files`, or `bom repo --include-files` |

Both build the same BOMs from the same upload and write the same files. `bom` skips the security scan, so it takes less time. In our tests on two small public repositories, `bom repo` took 9 to 40 seconds, and `scan repo --bom` usually took 45 seconds to about 10 minutes (one test run took 28 minutes).

## BOMs with a security scan: `scan --bom`

Add `--bom` to `scan repo` or `scan image`. The scan runs as usual. After the results, the CLI downloads one file per BOM type.

```bash
# AI-BOM and CBOM of a repository
armis-cli scan repo . --bom aibom,cbom

# Combined BOM in CycloneDX 1.6, written to ./boms
armis-cli scan repo . --bom all --bom-format cyclonedx-1.6 --bom-output ./boms

# SBOM and CBOM of an image (the flag may be repeated)
armis-cli scan image python:3.12-slim --bom sbom --bom cbom

# CBOM of a saved image, to stdout
armis-cli scan image --tarball ./image.tar --bom cbom --bom-output -
```

| Flag | Values | Default |
|------|--------|---------|
| `--bom` | `sbom`, `aibom`, `cbom`, `all` (combined); comma-separated or repeated | none: no BOM |
| `--bom-format` | `cyclonedx-1.7`, `cyclonedx-1.6`, `spdx-2.3`, `spdx-3.0.1`, or the aliases `cyclonedx` and `spdx` | `cyclonedx-1.7` |
| `--bom-output` | A directory, or `-` to write one BOM to stdout | `.armis` |

Notes:

- `--bom-format` and `--bom-output` need `--bom`. Without it, the CLI prints `--bom-format is ignored without --bom flag` (or the same for `--bom-output`) and scans as usual.
- `--fail-on` and `--exit-code` work as usual. A scan that fails on findings still writes the BOM files.
- With `--changed` or `--include-files`, the BOMs cover only the uploaded files.
- `--sbom` is a separate, older flag. It still writes `.armis/<artifact>-sbom.json` (`<artifact>-sbom.spdx.json` with `--sbom-format spdx`), or the file named by `--sbom-output`.
- `scan sbom` and `scan status` ignore `--bom` and print a warning.
- `scan` has its own `--format` and `--output` flags for the findings report. They are not BOM flags.

## BOMs without a security scan: `bom repo` and `bom image`

```bash
armis-cli bom repo [path]
armis-cli bom image [image-name]
armis-cli bom image --tarball <file>
```

```bash
# Combined BOM of the current folder (the default type)
armis-cli bom repo .

# AI-BOM and CBOM in CycloneDX 1.6, written to ./boms
armis-cli bom repo . --type aibom,cbom --format cyclonedx-1.6 --output ./boms

# SPDX 2.3 SBOM of an image
armis-cli bom image python:3.12-slim --type sbom --format spdx

# SBOM and CBOM of an image, always pulling it first
armis-cli bom image nginx:1.27 --type sbom,cbom --pull always

# CBOM of a saved image, to stdout
armis-cli bom image --tarball ./image.tar --type cbom --output - > cbom.json
```

Flags of both commands:

| Flag | Values | Default |
|------|--------|---------|
| `--type` | `sbom`, `aibom`, `cbom`, `all` (combined, one file); comma-separated or repeated | `all` |
| `--format` | `cyclonedx-1.7`, `cyclonedx-1.6`, `spdx-2.3`, `spdx-3.0.1`, or the aliases `cyclonedx` and `spdx` | `cyclonedx-1.7` |
| `--output` | A directory, or `-` to write one BOM to stdout | `.armis` |
| `--scan-timeout` | Minutes to wait for the BOMs | `60` |
| `--upload-timeout` | Minutes to wait for the upload | `10` |
| `--no-progress` | Suppress progress output, for CI and scripts | off |
| `--tenant-id`, `--region`, `--client-id`, `--client-secret` | Credentials and target, as for `scan` | from the environment |

`bom repo` only:

| Flag | Values | Default |
|------|--------|---------|
| `--include-files` | Comma-separated file paths, relative to the repository root, to upload instead of the whole folder | all files |
| `--include-tests` | Upload test folders and test files too | off |

`bom image` only:

| Flag | Values | Default |
|------|--------|---------|
| `--pull` | `always`, `missing` or `never`. Ignored with `--tarball` | `missing` |
| `--tarball` | Path to a saved image (`docker save` output) | none |

Notes:

- There is no findings report and no `--fail-on`. stderr shows the progress and one line per file written. stdout gets a BOM only with `--output -`.
- An `--output` path that does not exist and ends in `.json` is refused before upload, with a hint to use `--output -` (one type) or a directory.
- When `bom repo` uploads a whole git checkout from its root, it sends the repository name (from the `origin` remote) and, if the working tree is clean, the commit, as `scan repo` does, so the BOMs name them. With `--include-files` it sends neither.
- `bom image` sends the image name (with `--tarball`, the first tag in the tarball's manifest), so the BOMs name the image.

## Formats

| Type | CycloneDX 1.7 | CycloneDX 1.6 | SPDX 2.3 | SPDX 3.0.1 |
|------|---------------|---------------|----------|------------|
| `sbom` | Yes (default) | Yes | Yes | Not yet |
| `aibom` | Yes (default) | Yes | No | Not yet |
| `cbom` | Yes (default) | Yes | No | No |
| `all` | Yes (default) | Yes | No | No |

- `cyclonedx` is an alias of CycloneDX 1.7. `spdx` is an alias of SPDX 2.3 for `sbom` and of SPDX 3.0.1 for `aibom`.
- One format applies to every requested type.
- **Refused before upload** (exit 1, nothing is sent): `aibom` with `spdx-2.3`, and `cbom` or `all` with any SPDX value. The message names the pair, for example `--format spdx-2.3 is not available for --type cbom: the CBOM has no SPDX form`.
- **Refused after upload** (exit 1): the service does not offer SPDX 3.0.1 yet. `spdx-3.0.1`, and `--bom aibom --bom-format spdx`, fail with `the server refused the BOM request (...): The BOM type is not offered in this format (export_format_unavailable)`.
- Without `--type`, a refused pair says `--type all (the default)`.

## Output files

- Each requested type is one file: `<dir>/<artifact>-bom-<type>.json`. SPDX files end in `.spdx.json`.
- `<dir>` is `.armis` in the current directory, or the `--bom-output` / `--output` directory. A missing directory is created.
- `<artifact>` is:
  - for a repository, the folder name, for example `my-app`;
  - for an image, the last part of the image name, plus `-<tag>` when you give a tag (a digest is left out, so `python@sha256:...` gives `python`), for example `python-3.12-slim` for `python:3.12-slim`, and `app-1.2` for `ghcr.io/org/app:1.2`;
  - with `--tarball`, the tarball's file name without its last extension: `image.tar` gives `image`, and `app.tar.gz` gives `app.tar`.
- The CLI prints one line per file, such as `AI-BOM saved to: .armis/my-app-bom-aibom.json`. The labels are `SBOM`, `AI-BOM`, `CBOM` and `Combined BOM`.
- Each file holds the stored document, pretty-printed.
- A rerun replaces the files of the types it writes. A type that gets no file in the rerun keeps its old file, and the CLI warns `<path> is from an earlier run, not this scan`. Each file is written to a temp file and renamed over the old one. A symlink or a non-regular file at a BOM's name is refused, so a link committed in the scanned folder cannot redirect the write. The directory itself may be a symlink.
- The default `.armis` folder is refused when it is not a plain directory, such as a symlink. The CLI checks this before it uploads.
- On Linux and macOS the files get mode 0600. On Windows they take the folder's permissions.
- An empty BOM is still written, and the CLI says so: `No AI components found in <target>`, `No crypto components found in <target>`, `No packages found in <target>`, or `No components found in <target>`. The exit code does not change.

## Writing a BOM to stdout

`--bom-output -` (with `scan`) or `--output -` (with `bom`) writes one BOM to stdout instead of a file.

```bash
armis-cli bom repo . --type cbom --output - > cbom.json
armis-cli scan repo . --bom aibom --bom-output - --output report.json > aibom.json
```

- It takes one type. `--output -` with two or more types is refused before upload.
- stdout gets the document as stored, without pretty-printing.
- With `scan`, the findings report goes to stderr unless `--output` names a file for it.
- With `bom`, if there is nothing to write, nothing is written and the command exits 2.
- In Windows PowerShell 5.1, `>` saves stdout as UTF-16, which many JSON tools reject. Use a directory there, or cmd.exe or PowerShell 7.4 or later.

## Exit codes

`armis-cli scan` with `--bom`:

| Code | Meaning |
|------|---------|
| `0` | Scan completed with no blocking findings |
| `--exit-code` value (default `1`) | Findings at a `--fail-on` severity |
| `1` | Error: invalid flags, authentication, upload, timeout, a failed scan, or a refused BOM request |
| `2` | Scan completed, but its results or a requested BOM could not be downloaded. A `--fail-on` exit takes precedence over 2 |
| `130` | Cancelled with Ctrl+C |

With the default `--exit-code 1`, findings and errors share code `1`. Set `--exit-code` to another value to tell them apart.

`armis-cli bom`:

| Code | Meaning |
|------|---------|
| `0` | At least one BOM was written and none failed to download |
| `2` | No BOM was written (for example, every requested type ended in a warning below), or a built BOM could not be downloaded |
| `1` | Error, including `bom_generation_disabled`, a refused format, and a server that does not support BOM-only scans |
| `130` | Cancelled with Ctrl+C |

## Warnings and what to do

These warnings print on stderr and do not change the exit code of `scan`. The first five mean a requested type got no file. `bom` exits 2 if no requested type was written.

| Warning | Meaning | What to do |
|---------|---------|------------|
| `<type> is not supported for this scan` | The service does not build this type for this input. Today this is the AI-BOM of a container image. | Request it for the repository instead, or ask Armis about image AI-BOMs for your tenant. |
| `<type> failed on the server (tools that failed in this scan: ...)` | The BOM step failed for this type. | Rerun. If it fails again, contact Armis support with the scan ID. |
| `<type> was too large to store` | The BOM is over 50 MB and was not stored. | Narrow the upload with `.armisignore` or `--include-files`, or split the repository. |
| `<type> is not available in <format>` | The type was built, but not in this format, for example a converted format over 50 MB. | Request CycloneDX 1.7. |
| `<type> was requested but not available in results` | The results list no BOM: BOM generation is off for the tenant, the server's BOM step failed, or the server builds no BOMs. | Check that BOM generation is on for your tenant, then rerun. |
| `BOM tools failed on the server: <tools>; <types> may be incomplete` | A BOM was written, but a tool that feeds it failed. | Treat the file as partial. Rerun to get a complete one. |
| `--bom-format is ignored without --bom flag` | `--bom-format` or `--bom-output` was given without `--bom`. | Add `--bom <types>`. |

## CI examples

### GitHub Actions

This job builds an SBOM, AI-BOM and CBOM on every push to `main` and keeps them as a build artifact. Store `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` as repository secrets.

```yaml
name: BOMs
on:
  push:
    branches: [main]
jobs:
  boms:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - name: Install Armis CLI
        run: curl -sSfL https://raw.githubusercontent.com/ArmisSecurity/armis-cli/v1.28.0/scripts/install.sh | bash -s -- v1.28.0
      - name: Build BOMs
        env:
          ARMIS_CLIENT_ID: ${{ secrets.ARMIS_CLIENT_ID }}
          ARMIS_CLIENT_SECRET: ${{ secrets.ARMIS_CLIENT_SECRET }}
        run: armis-cli bom repo . --type sbom,aibom,cbom --output ./boms
      - name: Keep the BOMs
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7
        with:
          name: boms
          path: ./boms/
```

The step fails when `armis-cli bom` exits with a non-zero code, including 2 (no BOM written).

To get the BOMs from a security scan step you already have, add the flags to it:

```bash
armis-cli scan repo . --fail-on HIGH,CRITICAL --bom aibom,cbom --bom-output ./boms
```

### Plain shell

This script works with `set -e`, as GitLab CI (`set -eo pipefail`) and Jenkins (`sh -xe`) run it:

```bash
rc=0
armis-cli bom repo . --type all --output ./boms || rc=$?
case "$rc" in
  0) echo "BOMs written to ./boms" ;;
  2) echo "No BOM was written, or a download failed"; exit 2 ;;
  *) echo "armis-cli failed with exit code $rc"; exit "$rc" ;;
esac
```

## Reading the files

Every CycloneDX BOM has `metadata`, `components` and `dependencies`. `services` appears only in the AI-BOM and the combined BOM. The excerpts below are trimmed from real BOMs of the public [MCP quickstart repository](https://github.com/modelcontextprotocol/quickstart-resources) (commit `abb2533`) and the `eclipse-temurin:21-jre` image.

### Common fields

| Field | In | What it holds |
|-------|----|---------------|
| `metadata.component` | Every BOM | The root. For an image, the image. For a repository, the root package the tools pick, which may not carry the folder name. |
| `metadata.tools` | Every BOM | The generator, `Armis-AppSec-SBOM`. |
| `components[]` | Every BOM | Each item found. `type` says what it is. |
| `components[].properties[]` | Every BOM | Name and value pairs. Armis properties start with `armis:`. SBOM entries also carry scanner properties without the prefix, such as `PkgID` and `PkgType`. In the CBOM, only items found in source code have properties, such as `armis:opengrep:ruleId`. |
| `components[].evidence.occurrences[]` | Every BOM | Where the item was found: `location` is the file. Items found in code add `#L` and the line number (see the note below the table). |
| `services[]` | AI-BOM, combined BOM | AI services, and MCP servers and clients. |
| `dependencies[]` | Every BOM | Links between items. For an MCP server, `provides` lists the tools it registers. |

Items found in code are AI-BOM items and CBOM algorithms. SBOM entries for AI and MCP packages can also carry occurrences, with a line but no `#L`.

The top of a file:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:f1305dd3-8e44-5c14-bf62-43b5a8335484",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-17T15:25:15Z",
    "tools": { "components": [ { "type": "application", "name": "Armis-AppSec-SBOM", "version": "0.0.0" } ] },
    "component": { "name": "mcp-quickstart-ts", "version": "1.0.0", "type": "application", "purl": "pkg:npm/mcp-quickstart-ts@1.0.0" }
  }
}
```

### AI-BOM

Component types: `machine-learning-model` (a model), `library` (an AI or MCP package), `application` (an MCP tool, prompt or resource) and `file` (an MCP configuration file, or an agent-instruction, skill or prompt file). AI and MCP packages carry no file path in the AI-BOM.

A model, with the lines where it was found:

```json
{
  "type": "machine-learning-model",
  "bom-ref": "armis:machine-learning-model:c1df17c33d353309",
  "group": "anthropic",
  "name": "claude-sonnet-5",
  "properties": [
    { "name": "armis:ai:provider", "value": "anthropic" },
    { "name": "armis:ai:modelFamily", "value": "claude" },
    { "name": "armis:ai:confidence", "value": "medium" },
    { "name": "armis:detection:layer", "value": "opengrep-pack" }
  ],
  "evidence": {
    "occurrences": [
      { "location": "mcp-client-python/client.py#L15", "line": 15, "symbol": "claude-sonnet-5" },
      { "location": "mcp-client-typescript/index.ts#L12", "line": 12, "symbol": "claude-sonnet-5" }
    ]
  }
}
```

An MCP server, from `services[]`:

```json
{
  "bom-ref": "urn:service:mcp:weather:1.0.0",
  "name": "weather",
  "version": "1.0.0",
  "group": "mcp",
  "properties": [
    { "name": "armis:mcp:officialSdk", "value": "true" },
    { "name": "armis:mcp:serviceType", "value": "server" },
    { "name": "armis:mcp:sourceLine", "value": "137" },
    { "name": "armis:mcp:toolCount", "value": "2" },
    { "name": "armis:SrcFile", "value": "weather-server-typescript/src/index.ts" }
  ]
}
```

`armis:mcp:serviceType` is `server`, `client`, or `configured-server` (a server named in an MCP configuration file). The tools it registers, from `dependencies[]`:

```json
{
  "ref": "urn:service:mcp:weather:1.0.0",
  "dependsOn": [],
  "provides": [ "urn:mcp:tool:weather:get-alerts", "urn:mcp:tool:weather:get-forecast" ]
}
```

One of those tools, from `components[]`:

```json
{
  "type": "application",
  "bom-ref": "urn:mcp:tool:weather:get-alerts",
  "name": "get-alerts",
  "description": "Get weather alerts for a state",
  "properties": [
    { "name": "armis:mcp:role", "value": "tool" },
    { "name": "armis:mcp:serviceRef", "value": "urn:service:mcp:weather:1.0.0" },
    { "name": "armis:SrcFile", "value": "weather-server-typescript/src/index.ts" }
  ],
  "evidence": { "occurrences": [ { "location": "weather-server-typescript/src/index.ts#L142", "line": 142, "symbol": "get-alerts" } ] }
}
```

An AI package and an agent-instruction file:

```json
{
  "type": "library",
  "name": "anthropic",
  "version": "2.6.0",
  "purl": "pkg:pypi/anthropic@2.6.0",
  "properties": [
    { "name": "armis:detection:layer", "value": "catalogue" },
    { "name": "armis:catalogue:category", "value": "ai-provider-sdk" },
    { "name": "armis:catalogue:provider", "value": "anthropic" }
  ]
}
```

```json
{
  "type": "file",
  "bom-ref": "urn:file:ai:AGENTS.md",
  "name": "AGENTS.md",
  "properties": [
    { "name": "armis:ai:kind", "value": "agent-instruction-file" },
    { "name": "armis:SrcFile", "value": "AGENTS.md" }
  ]
}
```

Useful `jq` commands:

```bash
# Components by type
jq -r '[.components[].type] | group_by(.) | map("\(.[0]): \(length)") | .[]' .armis/my-app-bom-aibom.json

# Models and where they were found
jq '.components[] | select(.type=="machine-learning-model") | {name, group, found_at: [.evidence.occurrences[].location]}' .armis/my-app-bom-aibom.json

# AI services and MCP servers and clients
jq -r '.services[] | [.name, (.version // ""), .group] | @tsv' .armis/my-app-bom-aibom.json
```

### CBOM

Every component has `type` `cryptographic-asset`. `cryptoProperties.assetType` is `algorithm`, `certificate` or `related-crypto-material` (such as a public key). CBOM components carry their data in `cryptoProperties`. Only items found in source code also have `properties`, such as `armis:opengrep:ruleId`, and an occurrence with `#L` and the line.

A certificate:

```json
{
  "bom-ref": "crypto:certificate:sha256:018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05",
  "type": "cryptographic-asset",
  "name": "DigiCert TLS ECC P384 Root G5",
  "evidence": {
    "occurrences": [
      { "location": "etc/ssl/certs/ca-certificates.crt" },
      { "location": "usr/share/ca-certificates/mozilla/DigiCert_TLS_ECC_P384_Root_G5.crt" }
    ]
  },
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "subjectName": "CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\\, Inc.,C=US",
      "issuerName": "CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\\, Inc.,C=US",
      "notValidBefore": "2021-01-15T00:00:00+00:00",
      "notValidAfter": "2046-01-14T23:59:59+00:00",
      "certificateFormat": "X.509",
      "fingerprint": { "alg": "SHA-256", "content": "018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05" },
      "relatedCryptographicAssets": [
        { "type": "algorithm", "ref": "crypto:algorithm:oid:1.2.840.10045.4.3.3" },
        { "type": "publicKey", "ref": "crypto:key:public:spki-sha256:a02fafa192c8cb81cb1341554f9c05b71cca2a890b0d1298d683647c961efbdf" }
      ]
    }
  }
}
```

An algorithm (the certificate's signature algorithm) and a public key:

```json
{
  "bom-ref": "crypto:algorithm:oid:1.2.840.10045.4.3.3",
  "type": "cryptographic-asset",
  "name": "ECDSA-SHA-384",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "signature", "algorithmFamily": "ECDSA" },
    "oid": "1.2.840.10045.4.3.3"
  }
}
```

```json
{
  "bom-ref": "crypto:key:public:spki-sha256:05570ae6eb0fceb4210e6db79486b7094caf200401e149b6677441b5f25e449b",
  "type": "cryptographic-asset",
  "name": "RSA-4096 public key",
  "cryptoProperties": {
    "assetType": "related-crypto-material",
    "relatedCryptoMaterialProperties": { "type": "public-key", "size": 4096 }
  }
}
```

Useful `jq` commands:

```bash
# Assets by type
jq -r '[.components[].cryptoProperties.assetType] | group_by(.) | map("\(.[0]): \(length)") | .[]' .armis/my-image-bom-cbom.json

# Certificates by signature algorithm
jq -r '(.components | map({key: ."bom-ref", value: .name}) | from_entries) as $n
  | [.components[] | select(.cryptoProperties.assetType=="certificate")
     | .cryptoProperties.certificateProperties.relatedCryptographicAssets[]?
     | select(.type=="algorithm") | $n[.ref]]
  | group_by(.) | map("\(.[0]): \(length)") | .[]' .armis/my-image-bom-cbom.json

# Certificates that expire before a date
jq -r '.components[] | select(.cryptoProperties.assetType=="certificate")
  | select(.cryptoProperties.certificateProperties.notValidAfter < "2030-01-01")
  | [.name, .cryptoProperties.certificateProperties.notValidAfter] | @tsv' .armis/my-image-bom-cbom.json
```

### SBOM

Component types: `library` (a package), `application` (a lock file, manifest or binary that holds packages) and, for an image, `operating-system`.

```json
{ "type": "library", "name": "fs_extra", "version": "1.3.0", "purl": "pkg:cargo/fs_extra@1.3.0",
  "properties": [ { "name": "PkgID", "value": "fs_extra@1.3.0" }, { "name": "PkgType", "value": "cargo" } ] }
```

```json
{ "type": "application", "name": "mcp-client-typescript/package-lock.json",
  "properties": [ { "name": "Class", "value": "lang-pkgs" }, { "name": "Type", "value": "npm" } ] }
```

Each lock file, manifest, binary or operating system lists its direct packages in `dependencies[]`; other packages link through the packages that pull them in. In a repository SBOM, packages lead back to the lock file or manifest that lists them; in an image SBOM, to the operating system or binary that holds them.

### Combined BOM

The combined BOM holds the components of the SBOM, AI-BOM and CBOM, with duplicates merged, plus the AI-BOM's `services`. For the MCP quickstart repository, the SBOM had 461 components and the AI-BOM 20 components and 4 services; the combined BOM had 467 components and 4 services.

## API

The CLI uses the public ingest API. Teams that do not use the CLI can call it directly. The API reference is at `https://moose.armis.com/openapi.json` (US) and `https://eu.moose.armis.com/openapi.json` (EU).

Every API call except the token call needs `Authorization: Bearer <token>`. The upload to the presigned URL does not take it; the signed form fields authorize it.

### 1. Get a token

`POST /api/v1/auth/token`

```json
{ "client_id": "<client id>", "client_secret": "<client secret>" }
```

Response:

```json
{ "token": "<JWT>", "region": "eu1" }
```

A `region` of `eu1` uses `https://eu.moose.armis.com`. Other regions use `https://moose.armis.com`.

### 2. Reserve an upload

`POST /api/v1/ingest/presigned-url`

```json
{ "artifact_type": "repo", "filename": "app.tar.gz" }
```

`artifact_type` is `repo` or `image`. `filename` must end in `.tar`, `.tar.gz` or `.tgz`. Response fields:

| Field | Meaning |
|-------|---------|
| `scan_id` | The reserved scan ID |
| `tenant_id` | Your tenant ID; use it in the status and results calls |
| `artifact_type` | As sent |
| `presigned_url` | Where to upload the file |
| `fields` | Form fields to send with the upload |
| `max_upload_bytes` | The upload size limit (2 GiB) |
| `expires_in` | Seconds the upload link is valid (1800) |

### 3. Upload the file

Send a multipart POST to `presigned_url` with every entry of `fields` as a form field, then the file as `file`. A success answers `200` or `204`.

### 4. Start the BOM build

`POST /api/v1/ingest/scan`

```json
{
  "scan_id": "<scan_id>",
  "scan_type": "bom",
  "bom_types": ["sbom", "cbom"],
  "bom_format": "cyclonedx-1.7",
  "image_ref": "eclipse-temurin:21-jre"
}
```

| Field | Values |
|-------|--------|
| `scan_type` | `bom` for BOMs only; `full` for a security scan plus the BOMs in `bom_types` |
| `bom_types` | Any of `sbom`, `aibom`, `cbom`, `all`. Required for `bom` |
| `bom_format` | `cyclonedx-1.7` (default), `cyclonedx-1.6`, `spdx-2.3`, `spdx-3.0.1`, `cyclonedx`, `spdx` |
| `image_ref` | For an image: its reference, so the BOMs name it. Up to 512 characters |

A `bom` scan takes no `custom_scans`, and `sbom_generate` and `vex_generate` must be false. If the server refuses a BOM request, it answers 422 with a `code`. A body that fails validation also answers 422, with a list of errors in `detail`.

```json
{ "detail": { "code": "bom_generation_disabled", "message": "BOM generation is not enabled for this tenant" } }
```

| Code | Cause |
|------|-------|
| `bom_generation_disabled` | A `bom` scan on a tenant with BOM generation off |
| `export_format_unavailable` | A requested type is not offered in `bom_format` |
| `bom_types_required` | A `bom` scan with no `bom_types` |
| `custom_scans_not_allowed` | A `bom` scan with `custom_scans` |
| `sbom_vex_not_allowed` | A `bom` scan with `sbom_generate` or `vex_generate` set |
| `artifact_type_not_supported` | A `bom` scan of an upload reserved as `sbom` |

A `full` scan with `bom_types` on a tenant with BOM generation off is not refused. It runs without BOMs.

A 409 means the upload is not there yet, or the scan already started. If the upload is missing, upload again while the link is valid and retry the call.

### 5. Wait for it

`GET /api/v1/ingest/status/?tenant_id=<tenant_id>&scan_id=<scan_id>`

Poll until `data[0].scan_status` is `COMPLETED`, `FAILED` or `STOPPED`. A real response for a BOM-only image scan, trimmed:

```json
{
  "data": [
    {
      "artifact_type": "image",
      "scan_id": "<scan_id>",
      "scan_type": "bom",
      "scan_status": "COMPLETED",
      "file_name": "eclipse-temurin-21-jre",
      "file_bytes": 115541504,
      "started_at": "2026-11-19T13:36:14.667000Z",
      "completed_at": "2026-11-19T13:37:12.782000Z"
    }
  ]
}
```

### 6. Get the BOMs

`GET /api/v1/ingest/results?tenant_id=<tenant_id>&scan_id=<scan_id>`

`results` maps each stored file to a download link that is valid for 15 minutes. `bom_summary` reports each type. The response for the scan above, trimmed, with the links left out:

```json
{
  "scan_status": "COMPLETED",
  "results": {
    "bom_results": "<link>",
    "bom_sbom_results": "<link>",
    "cbom_results": "<link>"
  },
  "bom_summary": {
    "schema_version": 1,
    "spec_version": "1.7",
    "validation": "passed",
    "types": {
      "sbom": { "status": "generated", "formats": ["cyclonedx-1.7"], "components": 153, "validation": "passed" },
      "cbom": { "status": "generated", "formats": ["cyclonedx-1.7"], "components": 252, "validation": "passed" },
      "all": { "status": "generated", "formats": ["cyclonedx-1.7"], "components": 405, "validation": "passed" }
    },
    "repairs": 0,
    "drops": 0,
    "failed_tools": [],
    "tools": [ { "name": "trivy", "version": "0.75.0" } ]
  }
}
```

- Result keys: `bom_sbom_results`, `aibom_results`, `cbom_results` and `bom_results` (combined) for CycloneDX 1.7. Another format adds a code: `aibom_cdx16_results`, `bom_sbom_spdx23_results`.
- `types.<type>.status` is `generated`, `empty`, `failed`, `too_large` or `not_supported`. Only `generated` and `empty` have a file.
- `failed_tools` lists BOM tools that failed in the scan. A BOM written while a tool failed may be incomplete.

### Example with curl and jq

A BOM-only scan of a repository. The script keeps the client secret, the token, the signed upload fields and the download link off every command line, and removes its working files on exit, error included. It stops with an error on any failed call.

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${BASE:-https://moose.armis.com}   # EU tenants: https://eu.moose.armis.com
SRC=${SRC:-./my-app}                    # the folder to build BOMs for

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. Get a token and write it to a header file
jq -n '{client_id: env.ARMIS_CLIENT_ID, client_secret: env.ARMIS_CLIENT_SECRET}' \
  | curl -sSf -X POST "$BASE/api/v1/auth/token" -H 'Content-Type: application/json' --data @- \
  | jq -er '.token | strings | select(length > 0) | "Authorization: Bearer " + .' > "$work/auth.hdr"

# 2. Pack the folder and reserve an upload
tar -czf "$work/app.tar.gz" --exclude .git --exclude node_modules --exclude .armis -C "$SRC" .
curl -sSf -X POST "$BASE/api/v1/ingest/presigned-url" -H @"$work/auth.hdr" \
  -H 'Content-Type: application/json' \
  -d '{"artifact_type": "repo", "filename": "app.tar.gz"}' > "$work/presigned.json"
scan_id=$(jq -er .scan_id "$work/presigned.json")
tenant_id=$(jq -er .tenant_id "$work/presigned.json")

# 3. Upload; the signed form fields go in a curl config file
jq -er '(.fields | to_entries[]
          | "form-string = \"\(.key)=\(.value | gsub("\\\\"; "\\\\") | gsub("\""; "\\\""))\""),
        "url = \"\(.presigned_url)\""' "$work/presigned.json" > "$work/upload.cfg"
curl -sSf -o /dev/null -K "$work/upload.cfg" -F "file=@$work/app.tar.gz"

# 4. Start the BOM build
jq -n --arg id "$scan_id" \
    '{scan_id: $id, scan_type: "bom", bom_types: ["aibom", "cbom"], bom_format: "cyclonedx-1.7"}' \
  | curl -sSf -X POST "$BASE/api/v1/ingest/scan" -H @"$work/auth.hdr" \
      -H 'Content-Type: application/json' --data @- > /dev/null

# 5. Wait up to 20 minutes (120 tries, 10 seconds apart)
status=""
for _ in $(seq 120); do
  status=$(curl -sSf -H @"$work/auth.hdr" \
      "$BASE/api/v1/ingest/status/?tenant_id=$tenant_id&scan_id=$scan_id" \
    | jq -er '.data[0].scan_status')
  case "$status" in COMPLETED|FAILED|STOPPED) break ;; esac
  sleep 10
done
if [ "$status" != COMPLETED ]; then
  echo "error: scan $scan_id did not complete (last status: ${status:-none})" >&2
  exit 1
fi

# 6. Read the summary and download the AI-BOM; the link goes through curl's stdin
curl -sSf -H @"$work/auth.hdr" \
  "$BASE/api/v1/ingest/results?tenant_id=$tenant_id&scan_id=$scan_id" > "$work/results.json"
jq '.bom_summary.types' "$work/results.json"
jq -er '"url = \"\(.results.aibom_results)\""' "$work/results.json" | curl -sSf -o aibom.json -K -
```

Run it with `ARMIS_CLIENT_ID` and `ARMIS_CLIENT_SECRET` set. It needs bash, curl 7.55 or later (for `-H @file`) and jq 1.6 or later.

The API reference also lists `GET /api/v1/tenant/{tenant_id}/artifact/bom`. It is off by default and answers 404 while it is off for your tenant.

## Limits

- **No AI-BOM for container images** unless Armis turns on image AI-BOMs for your tenant (off by default). `scan image --bom aibom` prints `AI-BOM is not supported for this scan`, writes no AI-BOM, and keeps its exit code. `bom image --type aibom` alone writes nothing and exits 2. The SBOM and CBOM of an image work.
- **SPDX 3.0.1 is not offered yet.** The CBOM and the combined BOM have no SPDX form.
- **What is detected in code.** Source code rules find models and MCP servers in Python and TypeScript/JavaScript, and algorithms in Python, TypeScript/JavaScript and Java. AI and MCP packages are matched against a catalogue of 173 packages in 9 package ecosystems, including npm, PyPI, Maven Central, NuGet and Go modules. MCP servers are read from source; they are never started.
- **Known gaps.** Model IDs built from parts at run time (f-strings, template literals, string joins), algorithm names built at run time, protocols, and private keys. The AI-BOM does not record datasets or agent definitions.
- **Upload size.** An upload can be up to 2 GiB, for repositories and images alike. The CLI also limits a repository to 2 GiB of files after exclusions. It checks both before it uploads.
- **BOM size.** A BOM larger than 50 MB is not stored. `scan --bom` prints `<type> was too large to store` and keeps its exit code. `bom` exits 2 if that type was the only one requested. The 50 MB check applies to the CycloneDX 1.7 document; a converted format over 50 MB is dropped, and the CLI prints `<type> is not available in <format>`. The CLI downloads files of up to 100 MiB.
- **Time.** The CLI waits up to 60 minutes by default. Change it with `--scan-timeout <minutes>`.
- **Older servers.** If the server does not support BOM-only scans, `armis-cli bom` exits 1 after the upload and prints `this Armis server does not support BOM-only scans yet; run: armis-cli scan repo|image <target> ... --bom <types> ...`. The printed command runs a security scan with `--bom`. It keeps the target and the `--tenant-id`, `--region`, timeout, include and pull flags you typed, and leaves out credentials, so run it in a shell where they are set. It is quoted for sh, bash and zsh, or for PowerShell on Windows; cmd.exe is not supported.

## Data handling

### What is uploaded

- **Repository:** a `.tar.gz` of the folder, or only the files named with `--include-files` (`bom repo`, `scan repo`) or found by `--changed` (`scan repo`).
- **Image:** the output of `docker save` (or `podman save`) of the image, or the file you pass with `--tarball`.

### What is left out of a whole-folder upload

Files named with `--include-files` or found by `--changed` are uploaded as listed: only symlinks are skipped, and the folder, test and `.armisignore` rules below do not apply.

- Version control folders: `.git`, `.svn`, `.hg`.
- Dependency and build folders: `node_modules`, `vendor`, `venv`, `.venv`, `__pycache__`, `.pytest_cache`, `target`, `build`, `dist`, `.next`.
- Editor folders: `.idea`, `.vscode`.
- Test folders (`tests`, `test`, `__tests__`, `spec`, `specs`) and test files (such as `*_test.go`, `test_*.py`, `*.test.ts`, `*.spec.js`), unless you pass `--include-tests`.
- Symlinks.
- Anything matched by `.armisignore`. It uses gitignore syntax, and nested `.armisignore` files apply relative to their folder. See [Ignoring Files and Suppressing Findings](../README.md#ignoring-files-and-suppressing-findings).

The CLI does not leave out an `.armis` folder. BOM files that an earlier run left in the scanned folder are uploaded with the next scan. Delete `.armis` before a scan if you don't want old outputs uploaded, or add `.armis/` to `.armisignore`.

### How it is uploaded and stored

- The file goes over HTTPS to an upload link that is valid for 30 minutes and accepts up to 2 GiB.
- The uploaded file and the generated BOMs are stored in the Armis region that serves your tenant: the EU (Frankfurt) for EU tenants and the US for all others. They are encrypted at rest with AES-256 and kept under paths specific to your tenant.
- A summary of each scan's BOMs (status, counts and tool names) is kept with the scan record.

### Retention

The uploaded file and the BOMs expire 30 days after they are written and are then removed by the storage service. Nothing deletes them earlier. To get a BOM after that, run a new scan.

### What a BOM contains

- Component names, versions and package URLs.
- File paths, relative to the scanned folder or image, for CBOM items, for AI-BOM items found in code or files, and for AI and MCP packages in the SBOM. AI and MCP packages carry no file path in the AI-BOM.
- Line numbers for items found in code.
- In a repository SBOM, packages link through the dependency tree to the lock file or manifest that lists them; in an image SBOM, to the operating system or binary that holds them.
- Strings from the code, such as model IDs and MCP tool descriptions.
- Public certificate and key data, such as subject, issuer, validity dates and fingerprints.

A BOM does not contain source code files, private keys or prompt text. Agent-instruction and prompt files are listed by path only. URLs taken from MCP configuration files are stored without login details or query strings.

### Access

With API credentials, the token is tied to your tenant: the API returns status, results and download links only for your tenant's scans. Download links expire 15 minutes after the results call. A link works for whoever holds it until it expires, so treat it as a secret.

## Troubleshooting

| Message or symptom | Cause | What to do |
|--------------------|-------|------------|
| `the server refused the BOM request (...): BOM generation is not enabled for this tenant (bom_generation_disabled)` | Armis turned BOM generation off for your tenant. It is on by default. | Ask your Armis contact to turn it back on. |
| `AI-BOM was requested but not available in results` | BOM generation is off, the server's BOM step failed, or the server builds no BOMs. The scan itself completed. | Check BOM generation for your tenant, then rerun. |
| `AI-BOM is not supported for this scan` | An AI-BOM was requested for an image. | Request the AI-BOM for the repository the image is built from. |
| `--format spdx-2.3 is not available for --type cbom: the CBOM has no SPDX form` | The type has no form in that format. Nothing was uploaded. | Use CycloneDX, or `--type sbom` for SPDX. |
| `The BOM type is not offered in this format (export_format_unavailable)` | The server does not offer the format yet, such as SPDX 3.0.1. | Use `cyclonedx-1.7`, `cyclonedx-1.6`, or `spdx-2.3` for the SBOM. |
| `this Armis server does not support BOM-only scans yet; run: ...` | The server predates `armis-cli bom`. | Run the printed `scan ... --bom` command. |
| `--output - takes one BOM type, got 2: ...` | stdout takes one BOM. | Request one type, or use a directory. |
| `.armis is not a plain directory` | `.armis` is a symlink or not a directory. | Remove it, or pass `--bom-output` / `--output` with another directory. |
| `No crypto components found in .` | The CBOM is empty for this input. The file is still written. | None needed. |
| `upload size ... exceeds server limit ...` (image), or `directory size (...) exceeds maximum allowed size (...)` (repository) | The upload, or the repository after exclusions, is over 2 GiB. | Narrow it with `.armisignore` or `--include-files`. |
| `container runtime not found or not running` | `bom image <name>` needs Docker or Podman. | Start Docker or Podman, or save the image and pass `--tarball`. |
| A BOM lists files from an earlier run | An old `.armis` folder was uploaded. | Delete `.armis` before the scan, or add `.armis/` to `.armisignore`. |
