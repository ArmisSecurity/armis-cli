# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

- Command help is no longer cluttered with scan-only flags. The output flags `--format`, `--no-progress`, `--fail-on`, `--exit-code`, and `--page-limit` were registered as root persistent flags, so they appeared in the `--help` of every command — including non-scan commands like `hook`, `supply-chain`, `install`, and `agent-detection`, where they have no effect. They are now scoped to the `scan` command subtree where they belong. `supply-chain check`, a sibling of `scan` that does use `--format`/`--fail-on`/`--exit-code`, re-registers exactly those three locally (mirroring its existing `--output` handling), so its behavior is unchanged. (PPSC-1009)

### Deprecated

### Removed

### Fixed

- `hook init` no longer refuses to install a pre-commit hook when the Armis MCP plugin is absent. It previously hard-errored with "Armis MCP server not installed — run 'armis-cli install' first", even though the hook installer already falls back to a direct `armis-cli scan repo . --changed=staged --no-progress --fail-on HIGH` hook when the plugin's own pre-commit script is missing. The redundant gate is removed, so `hook init` installs the direct-scan hook and prints a one-line advisory ("Armis MCP plugin not found; installing direct-scan hook…") instead of blocking. (PPSC-1009)

### Security

---

## [1.16.0] - 2026-06-25

### Added

- Shell completion now suggests values for enumerated flags: `--format`, `--fail-on`, `--color`, `--theme`, and `--group-by` offer their accepted values (with descriptions in zsh/fish) instead of falling back to file-path completion. The candidate lists reuse the same slices the flag validators read, so completions cannot drift from what is actually accepted. The README documents the per-shell setup for `armis-cli completion <shell>` (bash/zsh/fish/PowerShell). (#245)

### Changed

- Update notification now links to the release notes for the available version, so breaking changes can be reviewed before upgrading. (#243)
- Documentation now covers previously-undocumented surface area: the `--changed` flag (all three modes, with a CI-INTEGRATION cross-link), the `.armisignore` file, and the `agent-detection`, `hook init`, and `completion` commands. CI setup examples use the correct binary name (`armis-cli`) and explain `.armisignore` instead of a stale `--exclude` snippet, and the SBOM/VEX examples drop `--tenant-id` (JWT auto-extracts it). (#242)
- Contributor first-run experience is cleaner: `make test` no longer reports 8 phantom failures (the upload spinner's ANSI frames and the `[y/N]` confirm prompt were corrupting gotestsum's JSON parser), a new `make lint-clean` target clears the golangci-lint cache that bleeds across sibling worktrees, and the README Go-version badge matches `go.mod` (1.25+). (#244)

### Deprecated

- Legacy Basic auth `--token` / `-t` (env: `ARMIS_API_TOKEN`) now emits a runtime deprecation warning and is hidden from `--help`; use JWT auth (`--client-id` / `--client-secret`, env: `ARMIS_CLIENT_ID` / `ARMIS_CLIENT_SECRET`) instead. The flag still functions — auth behavior is unchanged. (#243)

### Fixed

- `auth`/`scan`: the CLI now honors the operating system's proxy configuration instead of only the `HTTP_PROXY`/`HTTPS_PROXY` environment variables. On Windows this resolves the WinINET settings — including a PAC script referenced by `AutoConfigURL` (e.g. Zscaler) — that browsers and PowerShell already use. Previously the binary attempted a direct connection that a corporate proxy silently dropped, so authentication failed on the first request with an opaque `Post "https://…/api/v1/auth/token": EOF` even though the same machine could reach the endpoint in a browser. macOS and Linux behavior is unchanged (the release binaries are built with `CGO_ENABLED=0` and continue to read proxy settings from the environment). The `EOF` failure also now carries actionable guidance pointing at the proxy/`HTTPS_PROXY`, and `--debug` logs transport-level errors (DNS/connect/TLS/EOF), not just non-2xx HTTP responses. (#247)
- `scan`: invalid flags now fail fast as flag errors instead of hiding behind an auth failure. `--fail-on`, `--pull`, and SBOM/VEX flag misuse are validated and normalized *before* authentication and any network call, so a typo no longer surfaces as an opaque auth error (or silently defaults once auth succeeds). `scan repo` also accepts zero arguments again (path defaults to `.`), and `--pull` validation is skipped when `--tarball` is set, matching the flag's documented "ignored with `--tarball`" contract. (#240)
- `scan`/`auth`: error messages now follow a problem → cause → fix structure. Auth failures list the `--client-id`/`--client-secret` flags alongside the env vars; unknown-flag errors append a `Run <cmd> --help` hint; `scan image` checks for a missing container runtime *before* authenticating and points to the `--tarball` escape hatch (with Docker/Podman install URLs); and the agent-detection output suggests `armis-cli install` when an agent is missing MCP configuration. (#238)

### Security

---

## [1.15.0] - 2026-06-23

### Changed

- First-run onboarding now reaches a working command faster. The README leads with a "Try it without credentials" Quick Start that runs `supply-chain check` against public registries with no Armis account, and the Quick Start section now precedes the release-verification material (the SLSA/cosign/SBOM steps are collapsed into an expandable block) so an install-to-scan reader is no longer interrupted by 96 lines of signature verification. The credential-setup steps now link to where the VIPR client credentials live, and the auth `401` error message points to the same place ("get credentials from the VIPR external API screen in the Armis Platform") instead of saying only "invalid credentials". The README "General Flags" table and environment-variable table now document the previously-missing `--color`, `--theme`, `--no-update-check`, and `--dev` flags and the `ARMIS_THEME` / `ARMIS_NO_UPDATE_CHECK` variables. (#236)
- `auth`: the Armis cloud region is now auto-detected from your credentials, so non-US customers no longer need to pass `--region` on every scan. The token exchange already discovers the region server-side and returns it in the JWT (with a response-body fallback for older tokens); the CLI now reads that region and routes the region-pinned data plane (upload, status polling, results) to the matching host automatically. Explicit configuration still wins — `ARMIS_API_URL`, `--dev`, and `--region`/`ARMIS_REGION` are honored ahead of the discovered region, and legacy Basic auth or tokens without a region claim fall back to the primary host. (PPSC-1018)

### Fixed

- `scan`: the `--include-non-exploitable` filter now correctly hides low/medium exploitability findings. The backend's exploitability label schema changed from a boolean (`Exploitable: true/false`) to a graded one (`Exploitability Level: low/medium/high`), which left the old filter matching nothing — the flag was effectively a no-op. Findings graded low or medium are now hidden by default, while high-exploitability and ungraded findings (SCA, container CVEs, false positives) are always shown. Pass `--include-non-exploitable` to restore the previous behavior of showing every finding (PPSC-1015)

---

## [1.14.0] - 2026-06-21

### Added

- `supply-chain status` now leads with a one-line protection verdict answering the only question the command exists to answer — "is protection on right now?". The headline is computed from the same gate the wrapper uses: `ARMIS_SUPPLY_CHAIN=off` reads as **Disabled**, no installed wrappers reads as **Not active** (with the `init` command to fix it), and otherwise **Protected** with a count and the wrapped commands named (green ✓ when protected, ⚠ otherwise). Ecosystem detection now walks upward to find lockfiles the way enforcement does, so running `status` from a project subdirectory no longer reports `(none detected)` when a parent-directory lockfile would in fact be enforced; the empty-lockfile state now explains its scope rather than reading as "nothing is protected". Each active shell also reports which package managers it actually wraps (`wraps: npm, pip, …`), with the dozen `pip3.x` variants collapsed to `pip (+N variants)` in the human view. `--json` gains a `verdict` object (`{state, headline, wrapped_count}`) and per-shell `wraps` arrays so CI can gate with `jq -e '.verdict.state == "protected"'`. (#231)
- `supply-chain check` now accepts `-o`/`--output` to write results to a file, reusing the same pipeline as `scan repo`/`scan image` with extension-based format auto-detection (`.json`, `.sarif`, `.xml`). As a sibling of `scan` in the command tree, `supply-chain check` did not inherit `scan`'s persistent `--output` flag, so the flag is now registered locally on the subcommand. (#229)

### Fixed

- `auth`: region-pinned uploads now reach the correct data plane. The data plane (`/api/v1/ingest/*`) is physically region-pinned, but only the token exchange was region-aware — a region-scoped JWT was being presented to the primary host on upload and rejected with a 401 (the `eu1` upload bug). A new explicit region→host allowlist feeds the upload endpoint so it matches the JWT's region; this also replaces the old string-interpolated host in `install/validate.go`, which produced the wrong `eu1` URL format and built a host from unvalidated input (CWE-918). (#228)
- PR scan comments: the alert count in the PR comment now matches the inline Code Scanning annotations. Findings are filtered against the PR diff so a finding outside the changed lines is no longer counted in the comment summary while being absent from the inline annotations. Diff parsing also skips `\ No newline at end of file` sentinel lines to prevent line-number misalignment, uses a null-prototype map to avoid prototype pollution from adversarial filenames, and passes findings through unfiltered for files whose patch is missing (large or binary diffs) to avoid silent under-reporting. (#221)
- `supply-chain`: the filter summary for PyPI installs no longer mislabels withheld stable releases as prereleases. A PyPI package filename (e.g. `filelock-3.29.2.tar.gz`) was being split on the first `-` and read as a prerelease, which printed the misleading `withheld N prereleases; a default install was unaffected` line for stable versions the proxy actually downgraded. Classification now runs on a normalized version (semver/PEP 440 parsed from the filename) and recognizes dash-less PEP 440 markers (`1.0.0rc1`, `1.0.0b2`, `1.0.0.dev1`); the SemVer `-` branch now requires a numeric dotted core so hyphenated project names like `4ti2-1.0.tar.gz` are not misread. The per-line summary now leads with the installed safe version and its age, with the skipped version as a trailing clause, and omits a false age for undatable files. (#222)

### Security

---

## [1.13.0] - 2026-06-16

### Added

- `supply-chain`: `uvx` (uv's on-demand tool runner) is now wrapped alongside `uv`, the PyPI analogue of how `npx` is paired with `npm`. `uvx <tool>` fetches a tool from PyPI and runs it — exactly the supply-chain vector the proxy guards — so wherever `uv` is enforced, `uvx` is too. It shares uv's resolver and config, so it routes through the same transparent PyPI proxy (`UV_INDEX_URL`) and inherits uv's `ecosystems`-scope decision. Enforcement applies to tools `uvx` fetches from the registry; a tool already in the uv tool cache runs without a registry round-trip and is not re-checked. Re-run `armis-cli supply-chain init` to wrap `uvx` on machines where it is installed. (#219)
  > **Action required:** Re-run `armis-cli supply-chain init` to wrap `uvx` on machines where it is installed.
- `supply-chain check` now warns when the audited lockfile references a loopback registry (`127.0.0.1`, `localhost`, `[::1]`). The wrap's residue sweep can only remove the proxy origin of the run that just finished — a wrapper killed mid-install leaves a stale port behind, and versions before the sweep existed left residue routinely — so this gives CI a way to catch a corrupted lockfile before it breaks builds that resolve outside the wrapper. The warning is advisory: a deliberate local registry (e.g. Verdaccio) also matches. (#226)

### Fixed

- `supply-chain`: wrapped `uv` commands that write `uv.lock` (`uv sync`, `uv lock`, `uv add`, `uv run`, …) no longer corrupt the lockfile. uv records the configured index URL as each package's `source.registry` in `uv.lock`, and an index differing from the recorded one triggers a full re-lock — so routing these commands through the transparent proxy stamped the ephemeral `http://127.0.0.1:<port>/simple/` proxy address into every package entry, breaking any subsequent sync outside the wrapper (Docker builds, CI, teammates). Lockfile-writing `uv` invocations now use the same pre-install lockfile audit as poetry/pipenv/pdm: `uv.lock` is checked for too-young packages and the build is blocked before it runs, while uv itself resolves against the real index so the lockfile stays pristine. `uv pip …` and `uv tool …` (which never touch `uv.lock`) and `uvx` keep the transparent proxy. A lockfile already corrupted by an earlier version can be repaired by re-running `uv lock` outside the wrapper (or with `ARMIS_SUPPLY_CHAIN=off`). (#226)
  > **Action required:** A `uv.lock` corrupted by an earlier version is repaired by re-running `uv lock` outside the wrapper (or with `ARMIS_SUPPLY_CHAIN=off`).
- `supply-chain`: a wrapped `bun update` no longer leaves the ephemeral proxy address in `bun.lock`. bun records the full tarball URL it fetched from when re-resolving, so the proxy's `http://127.0.0.1:<port>/…` origin was persisted into the lockfile (verified on bun 1.3; `bun add`/`bun install` are unaffected — they record registry-relative entries). After every proxied run the wrapper now sweeps the project's lockfiles and rewrites any occurrence of the proxy origin back to the real upstream registry; the rewrite is atomic and produces exactly the URLs an unwrapped run would have recorded (the proxy forwards tarball paths to the upstream 1:1). The sweep also covers `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` defensively — current npm/yarn/pnpm record upstream URLs (verified on npm 10, yarn 1.22, pnpm 10), but older releases recorded the configured registry. A legacy binary `bun.lockb` cannot be rewritten in place; if proxy residue is detected there, a warning explains how to repair (`ARMIS_SUPPLY_CHAIN=off bun install --save-text-lockfile`). (#226)
  > **Action required:** A legacy binary `bun.lockb` with proxy residue is repaired with `ARMIS_SUPPLY_CHAIN=off bun install --save-text-lockfile`.
- `supply-chain`: a wrapped `uv tool install` no longer breaks subsequent `uv tool upgrade` runs. uv records the index it was invoked with as `index-url` in the tool's `uv-receipt.toml`, so upgrades would target the dead ephemeral proxy address; the post-run sweep now restores `https://pypi.org/simple/` in tool receipts. Receipts already poisoned by an earlier version can be repaired by re-running `uv tool install <tool> --force` through the wrapper, or editing the receipt's `index-url` by hand. (#226)
  > **Action required:** A poisoned `uv-receipt.toml` is repaired by re-running `uv tool install <tool> --force` through the wrapper, or editing the receipt's `index-url` by hand.
- `supply-chain`: a wrapped `uv pip compile --emit-index-url -o FILE` no longer writes the ephemeral proxy URL as the `--index-url` of the generated requirements file; the post-run sweep restores `https://pypi.org/simple/` in the output file. Output redirected to stdout by the shell happens outside the wrapper and cannot be intercepted — the new `supply-chain check` loopback warning covers that case. (#226)
- `supply-chain`: wrapped Yarn Berry (2+) installs no longer fail with `YN0081: Unsafe http requests must be explicitly whitelisted`. Berry honors the wrap's registry override but refuses plain-http registries — and the filtering proxy is necessarily plain http on loopback — so every wrapped Berry install errored out with no mention of the wrapper. The wrap now sets `YARN_UNSAFE_HTTP_WHITELIST=127.0.0.1` alongside the registry override (Yarn classic ignores the variable). Verified on Berry 4.16: wrapped installs are filtered by the age policy and Berry's registry-agnostic `yarn.lock` stays clean. (#226)
- `supply-chain`: the residue sweep also covers `npm-shrinkwrap.json` (package-lock.json's publishable twin), and rewrites symlinked lockfiles through to their target instead of replacing the link with a regular file. (#226)

### Security

---

## [1.12.0] - 2026-06-10

### Added

- Release pipeline now maintains floating major (`v1`) and minor (`v1.12`) version tags, so the GitHub Action can be consumed via `uses: ArmisSecurity/armis-cli@v1` and receive non-breaking updates automatically (#213)
- Documented the one-time GitHub Marketplace publishing steps for the Armis CLI Action in `docs/DISTRIBUTION-SETUP.md` (#213)

### Changed

- CI/CD documentation and example workflows now recommend pinning the GitHub Action to `@v1` instead of `@main` (#213)
- Marketplace sample workflow now references the repository's own `ArmisSecurity/armis-cli@v1` action with structured inputs (#213)

### Deprecated

- The local composite action at `.github/actions/armis-cli-action/` is deprecated in favor of the top-level `action.yml` (`ArmisSecurity/armis-cli@v1`) (#213)

---

## [1.11.1] - 2026-06-08

### Fixed

- `supply-chain init`: the injected shell wrappers no longer break after an `armis-cli` upgrade. The wrapper now references `armis-cli` by bare name (resolved from `PATH` on every call) when it is on `PATH`, falling back to the stable symlink path otherwise — previously it embedded the fully symlink-resolved binary path, which on Homebrew was the version-pinned Cellar directory (e.g. `…/Cellar/armis-cli/1.11.0/…`). After `brew upgrade armis-cli` deleted that directory, every wrapped package manager (npm, pnpm, bun, pip, uv, poetry, npx) failed to run in new shells. The wrappers are also now fail-closed: if `armis-cli` cannot be found at invocation time, the wrapper prints a loud warning to stderr that enforcement has lapsed and runs the real package manager un-wrapped, so installs never silently break. The fish guard now uses fish-native `command -q` (POSIX `command -v` errored under fish and silently disabled enforcement), and the guard adds an executable-path check so an absolute fallback path is detected reliably across shells. Wrappers injected before this fix must be refreshed by re-running `armis-cli supply-chain init` once. (#216)
  > **Action required:** Re-run `armis-cli supply-chain init` once to refresh shell wrappers injected before v1.11.1.

---

## [1.11.0] - 2026-06-08

### Added

- `supply-chain` command for enforcing package release-age policies, defending against supply-chain attacks (typosquatting, compromised maintainers, dependency confusion) by flagging or blocking packages published more recently than a configurable threshold (default 72h). No Armis Cloud authentication required — queries public registries directly. (#206, #210, #211)
  - Supports 12 package managers across three ecosystems: npm, npx, pnpm, bun, yarn (Node); pip, uv, poetry, pipenv, pdm (Python); Maven, Gradle (Java).
  - Node package managers and pip/uv use a transparent registry proxy that filters out too-young versions during install; poetry, pipenv, pdm, Maven, and Gradle use a pre-install lockfile audit that blocks the build before execution.
  - `npx` is wrapped alongside `npm` (it ships with npm and resolves from the same registry), so ad-hoc `npx <pkg>` runs are filtered through the same proxy. Enforcement applies to packages npx fetches from the registry; a package already in the npx cache or a binary already in `node_modules/.bin` runs without a registry round-trip and is not re-checked. The sibling runners `pnpm dlx` and `yarn dlx` are already covered as subcommands of the existing pnpm/yarn wrappers; `bunx` (a separate binary) is not yet wrapped.
  - `supply-chain check` audits lockfiles in CI; `supply-chain init`/`uninit` set up local shell enforcement; `supply-chain status` reports the active policy and detected ecosystems.
  - Configurable via `.armis-supply-chain.yaml` (`min-age`, `exclusions`, `ecosystems`, `fail-open`); per-invocation bypass via `ARMIS_SUPPLY_CHAIN_SKIP`; master kill switch via `ARMIS_SUPPLY_CHAIN=off`.
  - Gradle lockfile staleness detection (warns when `build.gradle` is newer than `gradle.lockfile`), Maven `pom.xml` partial-coverage notice (direct dependencies only), and a warning for unrecognized ecosystem names in the config.
  - The `ecosystems` config field accepts both `pipenv` (the tool name shown in `--help`) and `pipfile` (the internal name) so either spelling works.
  - The install summary reports each filtered package on one line showing the too-new version, its age, and the older version installed in its place (e.g. `axios 1.17.0 (1 day old) → 1.16.1 installed`). When every package resolves to a safe version it reads as a success; packages with no older safe version are called out individually. If the package manager itself does not complete (for example a dependency pins a version that only the filtered release satisfies), the summary reports the safe version as "available" rather than claiming it was installed, and explains how to relax or exclude the constraint. A one-time explanation of why fresh releases are withheld is shown on the first filtered install in an interactive terminal (suppressed thereafter and in CI).

### Changed

- `supply-chain init`: now wraps every supported package manager found on your `PATH` instead of only the ones with a lockfile in the current directory. The injected shell functions are global (they apply in every directory), so detecting from the current project's lockfiles left gaps — e.g. running `init` in a Go repo wrapped only `npm`/`npx`, so a later `pip install` in a Python project ran unenforced. Detection is now machine-wide; per-project enforcement is still decided dynamically at install time from the nearest `.armis-supply-chain.yaml` (the `ecosystems` scope and policy are re-read on each install), so wrapping a package manager never forces enforcement where the project hasn't opted in. When no supported package manager is on `PATH`, `init` still falls back to wrapping `npm`/`npx`.

### Fixed

- `supply-chain check`: `--fail-on` now accepts lowercase severities (e.g. `--fail-on medium`) and validates the value, matching `scan repo`/`scan image`. Previously a lowercase or invalid value was silently ignored, so the CI gate never fired and a real violation exited 0.
- `supply-chain`: an unknown subcommand (e.g. a typo like `chekc`) now exits non-zero with a "Did you mean" suggestion instead of printing help and exiting 0.
- `supply-chain check`: `--min-age` parse errors no longer print the duration twice; the message now suggests valid formats (`72h`, `3d`, `1w`). Output reads "1 package" (not "1 packages"), and the empty "Scan ID:" line is omitted for the local audit.
- `supply-chain check`: base-lockfile auto-detection now bounds its `git` subprocesses with a timeout (and honors cancellation), so a wedged or misconfigured `git` invocation can no longer hang the command indefinitely.
- `supply-chain`: the config `ecosystems` field now actually scopes enforcement. Previously it was parsed and typo-checked but ignored, so `ecosystems: [npm]` still enforced every ecosystem. `check` now skips an out-of-scope lockfile, `wrap` passes an out-of-scope package manager straight through, and `init` only wraps in-scope package managers. The gate fails safe: an empty list (or a list of only unrecognized names) enforces everything, so a typo cannot silently disable the control.

### Security

- `supply-chain wrap` (pip/uv): age enforcement now actually filters. The local-enforcement proxy previously only understood the npm registry format, so pip and uv installs were pointed at the proxy but their PyPI Simple API requests passed through unfiltered — young packages installed silently. The proxy now speaks the PyPI Simple API (PEP 691/700 JSON), removing distribution files published more recently than the policy threshold; a file with no upload timestamp is removed (fail-closed) rather than allowed.

---

## [1.10.2] - 2026-05-28

### Fixed

- Gemini CLI hook now uses the correct timeout unit (seconds instead of milliseconds) preventing premature request timeouts (#204)

---

## [1.10.1] - 2026-05-27

### Fixed

- Copilot CLI hook now installs to the correct path (`~/.copilot/settings.json`) instead of the VS Code extension directory (#202)
- Separated Copilot CLI hook target from VS Code extension target to prevent cross-contamination during install (#201)

---

## [1.10.0] - 2026-05-27

### Added

- Interactive MCP install wizard with hook-based integration for seamless plugin setup (#199)

### Fixed

- Added inline suppression directives for remaining CI findings (#198)

---

## [1.9.4] - 2026-05-25

### Fixed

- Added inline suppression directives for remaining CI findings (#194)

---

## [1.9.3] - 2026-05-25

### Fixed

- Suppression directives updated for compatibility with the new inline matching engine (#192)

### Changed

- Added comprehensive unit tests for install, uninstall, scan, and inline suppression flows (#191)

---

## [1.9.2] - 2026-05-25

### Fixed

- Inline suppression now matches directives by applicability (CWE, category, rule) before accepting, preventing false suppressions from stacked comments and ensuring fall-through to the correct directive (#189)

---

## [1.9.1] - 2026-05-24

### Fixed

- Inline suppression now correctly sees through function signatures, matching findings inside annotated functions regardless of signature length (#187)

### Changed

- Updated go-git/go-git to v5.19.1 (#183)
- Updated golang.org/x/sys to v0.44.0, golang.org/x/term to v0.43.0 (#167, #168)
- Updated alecthomas/chroma to v2.24.1 (#156)
- Updated mattn/go-runewidth to v0.0.23 (#139)
- Updated sigstore/cosign-installer to v4.1.2 (#165)

---

## [1.9.0] - 2026-05-21

### Added

- `uninstall` command for cleanly removing installed plugins, with manifest tracking and upgrade detection (#182)

### Fixed

- Suppressed findings are now excluded from SARIF output, allowing GitHub Code Scanning alerts to auto-close when findings are suppressed via `.armisignore` or inline directives (#185)
- Python binary discovery now probes versioned names (`python3.11`, `python3.12`, etc.) in addition to `python3` and `python`, resolving install failures on systems without a generic `python3` symlink (#184)

---

## [1.8.4] - 2026-05-18

### Added

- Claude Desktop app as an install target for the `install` command (#179)

### Fixed

- Secrets no longer leak in `--help` output when default values contain credentials (#180)

---

## [1.8.3] - 2026-05-13

### Changed

- Inline suppression now matches findings within a 5-line window around the directive, improving coverage for multi-line code patterns (#175)

---

## [1.8.2] - 2026-05-13

### Added

- Inline `armis:ignore` comment suppression — suppress findings directly in source code with parameterized matching by category, rule, CWE, or severity; supports all major comment syntaxes with security-hardened parsing (#170)

### Fixed

- Recurring findings no longer reopen on the GitHub Code Scanning tab — separated PR and scheduled scan SARIF categories (#171)
- `PrintWarning` now masks secrets consistently with `PrintError` (#172)
- HTTP client disallows redirects to strengthen SSRF protection (#172)
- Inline suppression file handle errors properly propagated instead of suppressed (#172)
- Stale Code Scanning alerts now close correctly when findings are suppressed via inline directives (#173)

---

## [1.8.1] - 2026-05-11

### Added

- Client-side finding suppression via `.armisignore` directives — findings matching severity, category, CWE, or rule patterns are excluded from `--fail-on` evaluation and human/JUnit output, with proper suppression metadata in SARIF and JSON (#162)
- `--show-suppressed` flag to include suppressed findings in output (#162)

### Changed

- GitHub Action updated to use JWT authentication as default, removing unused Basic auth secrets from scan workflows (#164)

### Fixed

- `LICENSE_COMPLIANCE_RISK` findings now correctly classified as LICENSE type (#162)

---

## [1.8.0] - 2026-05-11

### Added

- JWT authentication support for the GitHub Action with `client-id`, `client-secret`, and `region` inputs as the recommended auth method (#155)
- Suppression directive parsing in `.armisignore` for finding-level filtering by rule, category, severity, and CWE (#157)

---

## [1.7.0] - 2026-05-05

### Added

- Agent detection `collect` subcommand for reporting detected AI coding agents to Armis Cloud inventory (#153)
- Local AI agent discovery capability for detecting installed coding assistants

### Fixed

- SARIF rule IDs normalized to stable CWE/CVE identifiers, removing unstable fingerprints for consistent GitHub Code Scanning deduplication (#154)
- Install script now surfaces credential write failures instead of silently swallowing errors (#151)
- Release pipeline fixed by upgrading cosign-installer to v4 (v3 bootstrap binary was delisted) (#149)

---

## [1.6.1] - 2026-04-28

### Fixed

- Upgraded go-git to v5.18.0 to remediate CVE-2026-41506 (#148)
- SARIF rule IDs stabilized to prevent recurring false-positive GitHub Code Scanning alerts (#147)

---

## [1.6.0] - 2026-04-22

### Added

- `install claude` command for registering the Armis MCP plugin with Claude (#143)

---

## [1.5.0] - 2026-04-13

### Added

- Graceful degradation when result fetching fails: partial results are surfaced instead of aborting the scan (#141)

### Fixed

- Security hardening from the PPSC-602 code-scanning sweep: `.armisignore` size limit with go-git CVE remediation (#136), upper bounds on scan and upload timeouts to bound resource use (CWE-770, #122), install aborts when checksum-verification tools are unavailable (CWE-494, #124), integer-overflow guard in file-size calculation (CWE-190, #105), and reduced debug-info exposure in auth (CWE-215, #109) (#135)

---

## [1.4.0] - 2026-03-15

### Added

- JWT authentication via `--client-id` / `--client-secret` is now the recommended authentication method, taking priority over `--token` when both are provided (#95)

### Changed

- Removed `--auth-endpoint` flag — JWT endpoint is now derived automatically from the API URL and region (#98)
- Documentation updated to establish JWT as the recommended authentication method over Basic auth (#99)

---

## [1.3.0] - 2026-03-08

### Added

- `--changed` flag for scanning only git-changed files, enabling faster incremental scans (#93)
- `--output` flag for specifying output file path with improved CI detection and progress display (#92)
- Streaming multipart uploads for improved memory efficiency on large repositories (#91)

### Fixed

- Update notification now displays consistently after all commands (#94)

### Changed

- Updated go-git to v5.17.0 (#88)
- Updated GitHub Actions: upload-artifact v7 (#87), download-artifact v8 (#89), sbom-action v0.23.0 (#90)

---

## [1.2.1] - 2026-02-26

### Changed

- Updated golang.org/x/term to v0.40.0 (#76)
- Updated github.com/mattn/go-runewidth to v0.0.20 (#82)
- Updated goreleaser/goreleaser-action to v7 (#83)
- Optimized CI testing workflow (#85)
- Improved GitHub theme-aware markdown for AppSec logo (#84)

---

## [1.2.0] - 2026-02-23

### Added

- Smart local image detection - automatically detects whether an image exists locally (docker/podman) before attempting remote pull, improving scan speed for local images
- AppSec logo branding in CI security scan results

### Fixed

- Support empty `--fail-on` flag for informational-only scans that should never fail the build

### Security

- Defense-in-depth secret masking prevents accidental secret exposure in scan output, proposed fixes, and debug logs

---

## [1.1.0] - 2026-02-16

### Added

- JWT/VIPR token authentication with `--client-id`, `--client-secret`, `--auth-endpoint` flags (or `ARMIS_CLIENT_ID`, `ARMIS_CLIENT_SECRET`, `ARMIS_AUTH_ENDPOINT` env vars)
- Automatic JWT token refresh (5 minutes before expiry) with tenant ID auto-extraction from token
- `auth` command for testing authentication and obtaining raw JWT tokens
- Colored terminal output with `--color` flag (`auto`/`always`/`never`) respecting `NO_COLOR` and TTY detection
- `--theme` flag (`auto`/`dark`/`light`) for terminal background override with `ARMIS_THEME` env var
- Background version update checking with 24-hour cache (disable with `--no-update-check` or `ARMIS_NO_UPDATE_CHECK`)
- `--summary-top` flag to display summary dashboard before findings
- Lipgloss-based styling with ~50 styles using Tailwind CSS color palette and adaptive light/dark themes
- Chroma-based syntax highlighting with language auto-detection and vulnerable line highlighting
- LCS-based inline diff change detection with context limiting (3 lines around changes)
- Unicode severity indicators with colored styling
- Styled help output with colored commands and flags
- Short flag aliases: `-f` for `--format`, `-t` for `--token`
- `ARMIS_API_URL` environment variable for API base URL override

### Changed

- Case-insensitive `--fail-on` values (e.g., `--fail-on high` now works)
- JUnit formatter respects `--fail-on` severities instead of hardcoding CRITICAL/HIGH
- Diff display limited to 25 lines per hunk with "lines omitted" markers
- Summary dashboard only shows severity levels with findings (count > 0)
- Clean Ctrl+C handling with exit code 130 (standard Unix SIGINT)
- `--include-files` flag now repo-only (moved from scan-level)
- JWT authentication flags hidden from `--help` until backend support available

### Fixed

- **CRITICAL**: FAILED scan status now returns error instead of success
- **CRITICAL**: Reject `--exit-code 0` (must be 1-255 to work with `--fail-on`)
- API response limit increased to 50MB for large scan results
- Docker pull/save output redirected to stderr (prevents JSON/SARIF corruption)
- CommitSHA bounds check prevents panic on short commit hashes
- Timeout validation requires >= 1 minute for `--scan-timeout` and `--upload-timeout`
- Unicode text wrapping uses proper visual width calculation
- Rune-based column highlighting for multi-byte characters
- Path/tarball existence validation before network calls
- Warning when both `--tarball` and image name provided
- Warning when `--sbom-output`/`--vex-output` specified without `--sbom`/`--vex`
- SARIF schema URL updated to valid `main` branch location
- Syntax highlighting skipped for redacted code snippets (prevents colored keywords in redaction messages)

### Security

- Secret masking in SARIF output (patches, proposed fixes, patch files)
- Secret masking in proposed fixes and debug output
- Response body limits: 1MB for auth, 50MB for API, 1MB for HTTP errors
- Snippet loading limits: 10KB per line, 100KB total
- LCS token limit (500) prevents memory exhaustion
- Diff size limits: 100KB max, 2000 lines max
- Highlight code size limit: 100KB
- JSON parsing limit in error messages: 4KB
- Symlink detection fix using `os.Lstat` instead of `os.Stat`
- go-git updated to v5.16.5 (CVE-2026-25934 fix)
- HTTPS enforcement for authentication endpoints

---

## [1.0.7] - 2026-02-02

### Added

- SARIF standard `fixes` array for actionable fix suggestions with `ProposedFixes` and `PatchFiles` support
- Enhanced SARIF rule information with `fullDescription`, `helpUri`, and `help` fields
- Improved finding title generation (priority: CVE+package for SCA > OWASP category > secret type > description)

### Changed

- Separated spinner cleanup from result messages for cleaner progress output
- Only include `Help.Markdown` when it differs from `Help.Text` to avoid redundancy
- Added `stripMarkdown()` utility for SARIF `Help.Text` field per SARIF 2.1.0 spec
- Updated `anchore/sbom-action` from 0.21.1 to 0.22.1
- Updated `tj-actions/changed-files` from 46 to 47
- Updated `actions/checkout` from 4 to 6

### Fixed

- CWE URL validation (validate numeric before generating URL, fallback for invalid CWEs)
- SARIF line number validation (prevent invalid `DeletedRegion` with StartLine/EndLine = 0)
- Description truncation edge cases (period handling at position 80, trailing periods)

### Security

- Path traversal protection: skip paths when `util.SanitizePath` fails instead of falling back to original
- Command injection prevention: defense-in-depth image name validation in `exportImage`

---

## [1.0.6] - 2025-02-01

### Added

- SBOM (Software Bill of Materials) generation in CycloneDX format via `--sbom` flag
- VEX (Vulnerability Exploitability eXchange) document generation via `--vex` flag
- Custom output paths for SBOM/VEX via `--sbom-output` and `--vex-output` flags
- Proposed fix support with AI validation for vulnerability remediation
- Hybrid scan summary with brief status at top of output
- Theme-aware logo support for documentation
- Comprehensive CI integration guide
- OSS best practices and developer tooling documentation

### Changed

- Improved test coverage to 81.1%

### Fixed

- Workflow condition handling to avoid duplicated titles in scan output
- Missing permissions in security-scan workflow

---

## [1.0.5] - Initial Public Release

### Added

- Initial public release
- Repository scanning for security vulnerabilities
- Container image scanning
- CI/CD integration support (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps)
- Multiple output formats (JSON, SARIF, table)
- Configurable ignore patterns via .armisignore
- Multi-platform binaries (Linux, macOS, Windows)
- Docker image support
- Cosign signature verification

### Security

- Added SSRF protection for pre-signed URL downloads (only AWS S3 endpoints allowed)
- Added response size limits (100MB for downloads, 5GB for uploads, 1MB for API responses)
- HTTPS enforcement for credential transmission (except localhost for testing)
- Path traversal protection for artifact names and output paths
- Credential exposure prevention in debug output

---

## Release History

<!--
Release notes are automatically generated by GoReleaser.
See: https://github.com/ArmisSecurity/armis-cli/releases

Manual entries for significant releases:
-->

<!-- Example format for future releases:

## [1.0.0] - 2025-01-15

### Added
- Feature description

### Fixed
- Bug fix description

[1.0.0]: https://github.com/ArmisSecurity/armis-cli/compare/v0.9.0...v1.0.0

-->

[Unreleased]: https://github.com/ArmisSecurity/armis-cli/compare/v1.16.0...HEAD
[1.16.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.4...v1.10.0
[1.9.4]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.3...v1.9.4
[1.9.3]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.2...v1.9.3
[1.9.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.4...v1.9.0
[1.8.4]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.3...v1.8.4
[1.8.3]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/ArmisSecurity/armis-cli/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/ArmisSecurity/armis-cli/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/ArmisSecurity/armis-cli/releases/tag/v1.0.5
