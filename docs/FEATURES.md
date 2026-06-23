# Armis CLI Features

## 🎯 Enhanced Output Features

### Interactive Summary Dashboard

The CLI now displays scan results in a clean, box-drawn dashboard format:

```text
┌─────────────────────────────────────────────────────────────┐
│  📊 SCAN SUMMARY                                            │
├─────────────────────────────────────────────────────────────┤
│  Total Findings: 15                                         │
│  Filtered (Non-Exploitable): 3                              │
│                                                             │
│  🔴 CRITICAL: 2                                             │
│  🟠 HIGH: 5                                                 │
│  🟡 MEDIUM: 6                                               │
│  🔵 LOW: 2                                                  │
└─────────────────────────────────────────────────────────────┘
```

### Progress Indicators with Context

The CLI shows detailed progress during scans:

- **Creating a compressed archive...** - While packaging your code
- **Uploading archive to Armis Cloud...** - During upload
- **Analyzing code for vulnerabilities...** - While scanning
- **Fetching scan results...** - When retrieving findings

Each stage includes an elapsed timer showing real-time progress.

### Grouping Findings

Group findings by different criteria using the `--group-by` flag:

```bash
# Group by CWE (Common Weakness Enumeration)
armis-cli scan repo . --group-by cwe

# Group by severity level
armis-cli scan repo . --group-by severity

# Group by file
armis-cli scan repo . --group-by file

# No grouping (default)
armis-cli scan repo . --group-by none
```

Example grouped output:

```text
┌─────────────────────────────────────────────────────────────┐
│ CWE: CWE-89                                                 │
│ Count: 3                                                    │
└─────────────────────────────────────────────────────────────┘

🔴 CRITICAL

SQL Injection vulnerability detected...
```

### Git Blame Integration

When scanning a git repository, the CLI automatically shows who introduced each vulnerability:

```text
Location:    internal/api/client.go:45
Git Blame:   John Doe <j***@e***.com> (2024-11-15, abc1234)
```

Features:

- Automatically detects if directory is a git repository
- Shows author, partially masked email, date, and commit SHA
- Gracefully handles non-git directories
- Caches results to avoid redundant git calls

## 🛡️ Supply Chain Enforcement

Armis CLI can enforce a **minimum package release age** on the packages your
builds install, defending against supply-chain attacks (typosquatting,
compromised maintainer accounts, dependency confusion) where a malicious version
is published and pulled in before anyone notices. The default policy withholds
any release younger than **72 hours**.

Enforcement is wired into your package managers by `armis-cli supply-chain init`,
which installs thin shell wrappers. From then on, `npm install`, `pip install`,
etc. transparently run through the age policy.

### Two enforcement modes

The mechanism differs by package manager, because they resolve dependencies
differently:

| Mode | Package managers | How it works |
|------|------------------|--------------|
| **Proxy** | `npm`, `npx`, `pnpm`, `bun`, `yarn`, `pip`, `uv`, `uvx` | A local, in-process HTTP proxy intercepts every registry metadata request — direct **and** transitive — strips versions younger than the policy, and repoints `dist-tags.latest` to the newest *older* version. |
| **Pre-install block** | `poetry`, `pipenv`, `pdm`, `mvn`, `gradle` | The lockfile is audited up front; the build is hard-blocked **before** it runs if any package is too new. |

### The transitive-incompatibility limitation

The proxy is a **stateless per-request filter** — it has no model of your
dependency graph. This creates a real, bounded limitation worth understanding:

> If `express` requires `debug@^4.4.0`, and `debug@4.4.0` was published 12 hours
> ago, the proxy removes `4.4.0` (too new) and repoints `latest` to `4.3.9`. But
> `4.3.9` does **not** satisfy `^4.4.0`, so **npm rejects it and the install
> fails.** The block is correct — a brand-new version really was withheld — but
> the failure can look opaque.

When this happens, Armis names the culprit at block time. On the **npm family**
(`npm`/`pnpm`/`bun`/`yarn`), a one-hop constraint check reports exactly which
dependency became unsatisfiable and which package required it:

```text
[armis supply-chain] the install did not complete. This tool withheld brand-new
releases on purpose — a common supply-chain attack vector...
  → scheduler has no version older than the 3-day policy that satisfies ^0.24.0
    (required by react-dom) — this is the likely cause.
```

For **pip/uv**, the PyPI Simple API does not expose per-package dependency
ranges, so the one-hop attribution is not available there — Armis names the
blocked package and points you at `uv tree` / `pipdeptree` to find the requiring
package. See [Out of scope](#supply-chain-scope-notes) below.

<a name="supply-chain-escape-hatches"></a>

### Escape hatches (most surgical → most blunt)

When a young package is blocking you, four knobs unblock the build. They are
ordered here **least-permissive first** — reach for the lower-numbered, more
reviewable option before the blunt instruments:

1. **Allow one package, this invocation/environment** — exempts a single package:

   ```bash
   ARMIS_SUPPLY_CHAIN_SKIP=scheduler npm install
   ```

   ⚠️ This persists in whatever environment you set it in and exempts **all
   future versions** of that package, including potentially-malicious ones
   (skip-list rot). Prefer a reviewed exception (below) for anything permanent.

2. **Permanent, reviewed team exception** — add the package to `exclusions:` in
   `.armis-supply-chain.yaml` (committed, reviewed, team-wide):

   ```yaml
   exclusions:
     - scheduler
     - "@myorg/*"
   ```

3. **Relax the policy window for all packages** — edit `min-age:` in
   `.armis-supply-chain.yaml`:

   ```yaml
   min-age: 24h   # weakens the check for EVERY package
   ```

   > Note: the `wrap` path reads policy only from `.armis-supply-chain.yaml`.
   > There is **no `--min-age` flag** on the wrapped install — that flag exists
   > only on `armis-cli supply-chain check`.

4. **Emergency kill switch** — disable enforcement entirely for one command:

   ```bash
   ARMIS_SUPPLY_CHAIN=off npm install
   ```

   This turns the control off completely. Use it only as a last resort.

<a name="supply-chain-warn-transitive"></a>

### Warn-on-transitive policy (opt-in)

Rather than failing a build that a young transitive dependency would break, you
can let young **transitive** dependencies through with a warning while still
hard-blocking young **direct** dependencies. This is **off by default** (the
secure posture is `block`).

```yaml
# .armis-supply-chain.yaml
transitive-policy: warn   # default: block
```

Or per-invocation for the wrapped path (which can't take flags):

```bash
ARMIS_SUPPLY_CHAIN_TRANSITIVE=warn npm install
```

Under `warn`:

- A young **transitive** dependency (one *not* declared in your root manifest)
  is allowed through. The build succeeds; each allowed-through package is printed
  as a warning and marked in the compliance report.
- A young **direct** dependency (declared in your `package.json`
  `dependencies`/`devDependencies`/`peerDependencies`/`optionalDependencies`) is
  **still blocked** — that is where you have control and where typosquat/
  dependency-confusion risk concentrates.
- If the direct-dependency set **cannot be determined** (e.g. no readable
  `package.json`, or a non-npm ecosystem), Armis **fails safe**: every package is
  treated as direct and young versions are blocked, exactly as under `block`.

**Residual risk (read before enabling):** `warn` permits a freshly-published
*transitive* package into your build. A malicious indirect dependency could
therefore land before its release has aged. The control still blocks direct
deps, fails safe on an undeterminable direct set, and records every
warned-through package in the `--report` audit so security teams can review what
entered the build. Direct/transitive classification is **npm-family only**; pip/
uv and the pre-install ecosystems cannot determine a direct set and therefore
never warn-through (they stay at `block`).

<a name="supply-chain-report"></a>

### Compliance report (audit trail)

To prove no young package entered a build, emit a machine-readable JSON report:

```bash
# Wrapped install (wrap can't take flags — use the env var; "-" writes to stderr):
ARMIS_SUPPLY_CHAIN_REPORT=supply-chain-report.json npm install

# The check subcommand parses flags, so a flag is fine there:
armis-cli supply-chain check --report supply-chain-report.json
```

The report carries the effective `policy`, the enforcement `mode`, and the
`checked` / `blocked` / `resolved` / `warned_through` / `conflicts` sets plus an
`install_status`. CI can gate on it with `jq`:

```bash
jq -e '.install_status == "ok" and (.warned_through | length) == 0' supply-chain-report.json
```

<a name="supply-chain-scope-notes"></a>

### Scope and known limitations

- **One-hop, npm-family only.** The constraint conflict check is a single hop
  (a dependent's declared range vs. the dependency's surviving versions) on
  metadata the proxy already fetched — it is **not** a full resolver and does not
  backtrack multi-hop chains. It runs for the npm family only; PyPI's Simple API
  lacks per-package dependency ranges.
- **pip/uv get culprit-naming but no attribution.** Run `uv tree` or
  `pipdeptree` to find which package requires a blocked dependency.
- **Maven `pom.xml` covers direct dependencies only.** Maven resolves transitives
  at build time, so they are not audited. For full coverage, generate a lockfile
  (e.g. `mvn dependency:tree`, or a lockfile plugin) — Armis ships no Maven
  transitive parser.

## 📦 SBOM and VEX Generation

Generate industry-standard Software Bill of Materials (SBOM) and Vulnerability Exploitability eXchange (VEX) documents alongside your security scans.

### What are SBOM and VEX?

- **SBOM (Software Bill of Materials)**: A comprehensive inventory of all software components, dependencies, and libraries in your project. Essential for supply chain security, license compliance, and vulnerability management.

- **VEX (Vulnerability Exploitability eXchange)**: A document that communicates the exploitability status of vulnerabilities in your specific context. Helps reduce alert fatigue by indicating which vulnerabilities actually affect your deployment.

Both documents are generated in [CycloneDX](https://cyclonedx.org/) format, an OWASP standard widely supported by security tools.

### Basic Usage

```bash
# ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET set via env (JWT auto-extracts the tenant ID)

# Generate SBOM for a repository scan
armis-cli scan repo . --sbom

# Generate both SBOM and VEX
armis-cli scan repo . --sbom --vex

# Specify custom output paths
armis-cli scan repo . \
  --sbom --sbom-output ./reports/sbom.json \
  --vex --vex-output ./reports/vex.json

# Generate SBOM for container image scan
armis-cli scan image nginx:latest --sbom --vex
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--sbom` | Generate Software Bill of Materials | `false` |
| `--vex` | Generate VEX document | `false` |
| `--sbom-output` | Custom output path for SBOM | `.armis/<artifact>-sbom.json` |
| `--vex-output` | Custom output path for VEX | `.armis/<artifact>-vex.json` |

### Output Location

By default, SBOM and VEX files are saved to the `.armis/` directory:

```text
.armis/
├── my-project-sbom.json
└── my-project-vex.json
```

### CI/CD Example

Generate SBOM and VEX as part of your CI pipeline:

```yaml
# GitHub Actions example
- name: Security Scan with SBOM
  env:
    ARMIS_CLIENT_ID: ${{ secrets.ARMIS_CLIENT_ID }}
    ARMIS_CLIENT_SECRET: ${{ secrets.ARMIS_CLIENT_SECRET }}
  run: |
    armis-cli scan repo . \
      --sbom --vex \
      --sbom-output ./artifacts/sbom.json \
      --vex-output ./artifacts/vex.json

- name: Upload SBOM Artifact
  uses: actions/upload-artifact@v4
  with:
    name: sbom-vex
    path: ./artifacts/
```

### Use Cases

1. **Compliance**: Many regulations (Executive Order 14028, EU Cyber Resilience Act) require SBOM generation
2. **Supply Chain Security**: Track all dependencies and detect supply chain attacks
3. **License Management**: Identify all licenses in your software stack
4. **Vulnerability Prioritization**: Use VEX to focus on actually exploitable vulnerabilities
5. **Incident Response**: Quickly identify if vulnerable components are in your software

### Notes

- SBOM/VEX generation is performed server-side by Armis Cloud
- Download failures are logged as warnings but do not fail the scan
- Files are protected against path traversal attacks
- Maximum download size is 100MB per file

---

## 🚫 .armisignore Support

Exclude files and directories from scans using `.armisignore` files.

### Usage

Create a `.armisignore` file in your repository root:

```text
# Exclude build outputs
dist/
build/
*.o

# Exclude dependencies
node_modules/
vendor/

# Exclude logs
*.log

# Include specific files (negation)
!important.log
```

### Features

- **Gitignore-compatible syntax** - Uses the same pattern matching as `.gitignore`
- **Nested support** - Place `.armisignore` files in subdirectories
- **Glob patterns** - Support for wildcards (`*.log`, `test_*.py`)
- **Directory exclusions** - Exclude entire directories (`node_modules/`)
- **Negation patterns** - Include files that would otherwise be excluded (`!important.log`)
- **Comments** - Lines starting with `#` are ignored

### How It Works

Files matching `.armisignore` patterns are excluded **before** creating the upload archive, reducing:

- Upload time
- Scan time
- Bandwidth usage
- False positives from generated code

## 📝 Improved Help Text

All CLI flags now include detailed descriptions and examples:

```bash
armis-cli scan repo --help
```

Flags include:

- Clear descriptions of what each flag does
- Default values
- Valid options and ranges
- Environment variable alternatives

## 🧪 Testing

All new features include comprehensive unit tests:

```bash
# Run all tests
go test ./...

# Run specific test suites
go test ./internal/scan/repo/...
go test ./internal/output/...
```

## 🎨 Cross-Platform Compatibility

- Uses simple ASCII box characters (┌─┐│└┘) for maximum compatibility
- Works across all operating systems and CI/CD environments
- Gracefully handles terminals without emoji support
- Respects `NO_COLOR` and `TERM=dumb` environment variables

## 📊 Example Workflows

### Basic Scan with Grouping

```bash
armis-cli scan repo . \
  --group-by cwe \
  --format human
```

### Scan with Custom Exclusions

```bash
# Create .armisignore
echo "test/" > .armisignore
echo "*.generated.go" >> .armisignore

# Run scan
armis-cli scan repo .
```

### CI/CD Integration

```bash
# Fail on HIGH or CRITICAL findings
armis-cli scan repo . \
  --fail-on HIGH,CRITICAL \
  --no-progress \
  --format sarif > results.sarif
```

### Development Workflow

```bash
# Include test files and non-exploitable findings
armis-cli scan repo . \
  --include-tests \
  --include-non-exploitable \
  --group-by file
```

## 🔧 Configuration

### Environment Variables

**Authentication:**

JWT authentication is recommended. Obtain JWT credentials from the VIPR external API screen in the Armis platform.

| Variable | Description |
|----------|-------------|
| `ARMIS_CLIENT_ID` | Client ID for JWT authentication (recommended) |
| `ARMIS_CLIENT_SECRET` | Client secret for JWT authentication (recommended) |
| `ARMIS_API_TOKEN` | API token for Basic authentication (legacy) |
| `ARMIS_TENANT_ID` | Tenant identifier (legacy, not needed with JWT) |
| `ARMIS_API_URL` | Override base URL for Armis API and authentication (advanced) |
| `ARMIS_REGION` | Authentication region override (advanced; corresponds to `--region` flag) |

**General:**

| Variable | Description |
|----------|-------------|
| `ARMIS_FORMAT` | Default output format |
| `ARMIS_PAGE_LIMIT` | Results pagination size |

**Supply Chain Enforcement:**

| Variable | Description |
|----------|-------------|
| `ARMIS_SUPPLY_CHAIN` | Set to `off` to disable enforcement for one command (kill switch) |
| `ARMIS_SUPPLY_CHAIN_SKIP` | Comma/space-separated package names to exempt from the age check (persists in the env; exempts future versions) |
| `ARMIS_SUPPLY_CHAIN_TRANSITIVE` | Set to `warn` to let young *transitive* deps through with a warning (direct deps still blocked); default `block` |
| `ARMIS_SUPPLY_CHAIN_REPORT` | Path to write the JSON compliance report for a wrapped install (`-` for stderr) |

### Default Behavior

- Test files are **excluded** by default (use `--include-tests` to include)
- Non-exploitable findings are **filtered** by default (use `--include-non-exploitable` to include)
- Progress indicators are **enabled** by default (use `--no-progress` to disable)
- Grouping is **disabled** by default (use `--group-by` to enable)

## 🚀 Performance Tips

1. **Use .armisignore** - Exclude unnecessary files to speed up uploads
2. **Adjust timeout** - Increase `--timeout` for large repositories
3. **Optimize page limit** - Adjust `--page-limit` based on finding count
4. **Disable progress** - Use `--no-progress` in CI/CD for cleaner logs

## 📖 Additional Resources

- See `.armisignore.example` for a comprehensive ignore file template
- Check `docs/ci-examples/` for CI/CD integration examples
- Run `armis-cli --help` for full command reference
