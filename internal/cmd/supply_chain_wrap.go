package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/check"
	"github.com/ArmisSecurity/armis-cli/internal/util"
	"github.com/spf13/cobra"
)

const (
	envSCActive        = "ARMIS_SUPPLY_CHAIN_ACTIVE"
	envSCOff           = "ARMIS_SUPPLY_CHAIN"
	envSCSkip          = "ARMIS_SUPPLY_CHAIN_SKIP"
	envSCTransitive    = "ARMIS_SUPPLY_CHAIN_TRANSITIVE"
	scPrefix           = "[armis]"
	scSepLen           = 45
	maxSkipPackages    = 10000
	maxSkipPackagesLen = 100 * 1024 // 100 KB max for env var to prevent unbounded parsing
)

// Supported package-manager names. Centralizing them as constants keeps the
// allowlist, the registry-env switch, and the exec mapping in sync and avoids
// scattering the literals across the file.
const (
	pmNPM    = "npm"
	pmNPX    = "npx"
	pmPNPM   = "pnpm"
	pmBun    = "bun"
	pmYarn   = "yarn"
	pmPip    = "pip"
	pmUV     = "uv"
	pmUVX    = "uvx"
	pmPoetry = "poetry"
	pmPipenv = "pipenv"
	pmPDM    = "pdm"
	pmMaven  = "mvn"
	pmGradle = "gradle"
)

var scWrapCmd = &cobra.Command{
	Use:                "wrap <pm> [args...]",
	Short:              "Run package manager with age enforcement proxy (internal)",
	Hidden:             true,
	Args:               cobra.MinimumNArgs(1),
	RunE:               runSupplyChainWrap,
	DisableFlagParsing: true,
}

func init() {
	supplyChainCmd.AddCommand(scWrapCmd)
}

var allowedPMs = map[string]bool{
	pmNPM: true, pmNPX: true, pmPNPM: true, pmBun: true, pmYarn: true,
	pmPip: true, pmUV: true, pmUVX: true, pmPoetry: true, pmPipenv: true, pmPDM: true,
	pmMaven: true, pmGradle: true,
}

// execPMFunc is the indirection used to run a package manager. Production code
// leaves it pointing at execPM; tests replace it (restoring via t.Cleanup) to
// capture the resolved name/args/env and exit code without spawning a real
// process. Routing every call site through this var is the only seam that makes
// runProxyWrap/runPreInstallBlock unit-testable.
var execPMFunc = execPM

func runSupplyChainWrap(cmd *cobra.Command, args []string) error {
	// pmName is the exact command the user invoked (e.g. "pip3.12"); execName is
	// the binary actually run. canonicalPM collapses pip variants (pip3, pip3.12)
	// to "pip" for every policy decision — the allowlist, pre-install routing, and
	// registry-env all behave identically for any pip — while pmName is preserved
	// for execution so a versioned variant still installs into its own interpreter.
	pmName := args[0]
	pmArgs := args[1:]
	canonical := canonicalPM(pmName)

	if !allowedPMs[canonical] {
		return fmt.Errorf("unsupported package manager: %s (allowed: npm, npx, pnpm, bun, yarn, pip, uv, uvx, poetry, pipenv, pdm, mvn, gradle)", pmName)
	}

	if os.Getenv(envSCActive) == "1" {
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	if strings.EqualFold(os.Getenv(envSCOff), "off") {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain disabled via %s=off\n", envSCOff)
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	// Respect the config's "ecosystems" scope: when it lists ecosystems and this
	// PM's ecosystem is not among them, pass straight through to the real PM
	// without enforcement. The gate fails safe (enforces) on any config error.
	if !wrapEcosystemEnforced(canonical) {
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	// poetry/pipenv/pdm/maven/gradle cannot be enforced via the transparent
	// proxy at all, and uv commands that write uv.lock must not be (uv would
	// persist the ephemeral proxy URL into the lockfile); see
	// requiresPreInstallBlock. Those invocations are enforced by auditing the
	// lockfile and hard-blocking the build before it runs if any package is
	// too young.
	if requiresPreInstallBlock(canonical, pmArgs) {
		return runPreInstallBlock(cmd, pmName, pmArgs)
	}

	return runProxyWrap(cmd, pmName, pmArgs)
}

// canonicalPM maps a user-invoked package-manager name to the name used for
// policy decisions. pip variants (pip3, pip3.11, pip3.12) all resolve to PyPI
// and share one enforcement path, so they collapse to "pip"; every other name
// is returned unchanged.
func canonicalPM(pm string) string {
	if supplychain.IsPipVariant(pm) {
		return pmPip
	}
	return pm
}

func runProxyWrap(cmd *cobra.Command, pmName string, pmArgs []string) error {
	policy := resolveWrapPolicy()

	// Apply the env-var override for the transitive policy. ARMIS_SUPPLY_CHAIN_TRANSITIVE
	// mirrors the config's transitive-policy key for the wrap path (which can't take
	// flags). Only an explicit "warn" opts in; any other value (including unset)
	// leaves the resolved policy untouched, so the secure default and a config
	// "warn" both stand unless deliberately overridden.
	if raw := os.Getenv(envSCTransitive); raw != "" {
		policy.TransitivePolicy = supplychain.ParseTransitivePolicy(raw)
	}

	// pip, uv, and uvx resolve from the PyPI Simple API, a different protocol from
	// the npm registry, so the proxy must run in PyPI mode (PEP 691/700 JSON file
	// filtering). All other proxied PMs (npm/npx/pnpm/bun/yarn) speak the npm registry.
	// uv reaches the proxy only for its lockfile-free `pip`/`tool` subcommands;
	// lockfile-writing uv commands take the audit path (see requiresPreInstallBlock).
	mode := supplychain.ModeNPM
	switch canonicalPM(pmName) {
	case pmPip, pmUV, pmUVX:
		mode = supplychain.ModePyPI
	}

	// Direct-set detection drives the warn-on-transitive policy (WS5). It is only
	// consulted under TransitivePolicyWarn; in the default block mode the proxy
	// never asks "is this transitive?", so skip the manifest read entirely. When
	// warn IS active, an undeterminable direct set (directOK == false) makes the
	// proxy fail safe — every package is treated as direct and blocked.
	var directDeps []string
	if policy.TransitivePolicy == supplychain.TransitivePolicyWarn {
		var directOK bool
		directDeps, directOK = supplychain.DirectDependencies(".", pmToEcosystem(canonicalPM(pmName)))
		if !directOK {
			// Surface the fail-safe: the user opted into warn but we cannot tell
			// direct from transitive here, so enforcement stays at block. directDeps
			// is nil, which the proxy reads as "treat every package as direct".
			fmt.Fprintf(os.Stderr, "%s supply-chain: warn-on-transitive requested but the direct-dependency set could not be determined (%s); blocking young packages (fail-safe)\n",
				scPrefix, pmName)
		}
	}

	cfg := supplychain.ProxyConfig{
		Policy:       policy,
		Mode:         mode,
		SkipPackages: parseSkipPackages(os.Getenv(envSCSkip)),
		// Pass nil when undeterminable so the proxy treats every package as direct
		// (fail-safe block). When warn is off, directDeps is nil too — harmless,
		// since the proxy never consults it under the block policy.
		DirectDeps: directDeps,
	}

	proxy, err := supplychain.NewProxy(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: proxy setup failed, falling through: %v\n", err)
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	addr, err := proxy.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: proxy start failed, falling through: %v\n", err)
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}
	defer proxy.Close() //nolint:errcheck

	registryURL := fmt.Sprintf("http://%s/", addr)
	// Canonicalize so a versioned pip variant (pip3.12) still gets PIP_INDEX_URL
	// rather than falling through to the npm registry env.
	extraEnv := registryEnvForPM(canonicalPM(pmName), registryURL)
	extraEnv = append(extraEnv, fmt.Sprintf("%s=1", envSCActive))

	exitCode, err := execPMFunc(pmName, pmArgs, extraEnv)

	// Some package managers persist the registry origin they were invoked with:
	// bun's `update` records full tarball URLs in bun.lock, `uv tool install`
	// records index-url in its receipt, and older npm/yarn releases recorded the
	// configured registry in resolved fields. The proxy origin dies with this
	// process, so any artifact it leaked into is corrupt for every run outside
	// the wrapper. Sweep those artifacts and rewrite the origin back to the real
	// upstream — even when the PM exited non-zero, since a failed install can
	// still have rewritten the lockfile first.
	normalizeProxyResidue(canonicalPM(pmName), pmArgs, "http://"+addr, proxy.Upstream())

	// installOK reflects what the package manager actually did, not what the proxy
	// offered: proxy.Allowed() only records the version "latest" was repointed to,
	// so without the exit code the summary would claim a package was "installed"
	// even when the PM rejected it (e.g. a pin like ^1.17.0 that only the filtered
	// version satisfies). Report the observed outcome, not the proxy's intent.
	installOK := err == nil && exitCode == 0

	// WS2 one-hop conflict check: a deterministic post-install pass over the two
	// accumulators, run AFTER the PM exits so every metadata document has flowed.
	// npm-family only (npm metadata embeds per-version dependency ranges; PyPI's
	// Simple API does not), and recover()-guarded inside EvaluateConstraints so a
	// semver bug can never affect the already-finished install. Skip it entirely
	// when the install succeeded — there is no failure to explain.
	var conflicts []supplychain.ConstraintConflict
	if !installOK && mode == supplychain.ModeNPM {
		conflicts = proxy.EvaluateConstraints()
	}

	warned := proxy.Warned()
	printWarnThroughSummary(warned, policy)
	printBlockSummary(proxy.Blocked(), proxy.Allowed(), proxy.Checked(), policy, pmName, installOK, pmArgs, conflicts)

	// WS3 compliance report: written post-install when ARMIS_SUPPLY_CHAIN_REPORT
	// is set. Best-effort — a report write never changes the install's exit code.
	if reportPath := os.Getenv(envSCReport); reportPath != "" {
		status := statusOK
		if !installOK {
			status = statusFailed
		}
		rep := buildComplianceReport(reportInput{
			Policy:        policy,
			Mode:          "proxy",
			Ecosystem:     string(pmToEcosystem(canonicalPM(pmName))),
			Checked:       proxy.Checked(),
			Blocked:       proxy.Blocked(),
			Resolved:      proxy.Allowed(),
			Warned:        warned,
			Conflicts:     conflicts,
			InstallStatus: status,
		})
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:reportPath is the operator's own ARMIS_SUPPLY_CHAIN_REPORT env var naming an output file in their own environment (same trust model as scan's --output and the --report flag); a local CLI writing where its operator configured it crosses no trust boundary, and the value is not attacker-controlled network input
		writeComplianceReport(reportPath, rep)
	}

	if err != nil {
		return err
	}
	if exitCode != 0 {
		proxy.Close() //nolint:errcheck,gosec
		cancel()
		os.Exit(exitCode)
	}
	return nil
}

// printWarnThroughSummary reports the young transitive dependencies the proxy
// let through under TransitivePolicyWarn (WS5). It is intentionally a distinct,
// always-visible warning (not gated on installOK or interactivity): a security
// team and the developer both need to know a freshly-published package entered
// the build by policy. Silent under the default block policy (warned is empty).
func printWarnThroughSummary(warned []supplychain.WarnedPackage, policy supplychain.Policy) {
	if len(warned) == 0 {
		return
	}
	s := output.GetStyles()
	sort.Slice(warned, func(i, j int) bool {
		if warned[i].Age != warned[j].Age {
			return warned[i].Age < warned[j].Age
		}
		return warned[i].Name < warned[j].Name
	})

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		s.MutedText.Render(scPrefix),
		s.WarningText.Render(fmt.Sprintf("supply-chain: %s allowed through by transitive-policy: warn (younger than %s)",
			countNoun(len(warned), "young transitive dependency"), formatDurationShort(policy.MinReleaseAge))))

	displayCount := len(warned)
	if displayCount > maxBlockedDisplay {
		displayCount = maxBlockedDisplay
	}
	for _, w := range warned[:displayCount] {
		line := fmt.Sprintf("%s@%s", w.Name, w.Version)
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			s.WarningText.Render("⚠"),
			s.Bold.Render(line),
			s.MutedText.Render(optionalAgeToken(w.Age)))
	}
	if remaining := len(warned) - displayCount; remaining > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n", s.MutedText.Render(fmt.Sprintf("… and %d more", remaining)))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		s.MutedText.Render("Note:"),
		s.MutedText.Render("direct dependencies are still blocked; only indirect (transitive) packages pass with this warning."))
}

func execPM(pm string, args []string, extraEnv []string) (int, error) {
	// Map the validated name to a hardcoded string literal before the PATH
	// lookup. This makes the value flowing into exec.LookPath a compile-time
	// constant rather than the caller's argument, so there is no data-flow path
	// from user input into the lookup. Resolving the user's own package manager
	// from their PATH is the intended behavior of a transparent wrapper; only
	// the known PM names enumerated below can ever reach this point.
	var pmName string
	switch pm {
	case pmNPM:
		pmName = pmNPM
	case pmNPX:
		pmName = pmNPX
	case pmPNPM:
		pmName = pmPNPM
	case pmBun:
		pmName = pmBun
	case pmYarn:
		pmName = pmYarn
	case pmPip:
		pmName = pmPip
	case pmUV:
		pmName = pmUV
	case pmUVX:
		pmName = pmUVX
	case pmPoetry:
		pmName = pmPoetry
	case pmPipenv:
		pmName = pmPipenv
	case pmPDM:
		pmName = pmPDM
	case pmMaven:
		pmName = pmMaven
	case pmGradle:
		pmName = pmGradle
	default:
		// Versioned pip variants (pip3, pip3.11, pip3.12) must execute the exact
		// binary the user invoked so the install lands in that interpreter's
		// environment. CanonicalPipVariant reconstructs the name from its parsed
		// numeric components so no taint flows from pm into pmName.
		canonical, ok := supplychain.CanonicalPipVariant(pm)
		if !ok {
			return 1, fmt.Errorf("unsupported package manager: %s (allowed: npm, npx, pnpm, bun, yarn, pip, uv, uvx, poetry, pipenv, pdm, mvn, gradle)", pm)
		}
		pmName = canonical
	}

	// armis:ignore cwe:426 cwe:427 reason:pmName is one of the hardcoded string literals selected by the switch above, never the user argument; resolving the user's own PM from PATH is the point of a transparent wrapper
	pmPath, err := exec.LookPath(pmName)
	if err != nil {
		return 1, fmt.Errorf("finding %s: %w", pm, err)
	}

	// armis:ignore cwe:78 reason:args are the user's own package-manager arguments forwarded verbatim by a transparent wrapper (e.g. "npm install foo"); pmPath resolves a hardcoded PM name and no shell is invoked (exec.Command, not sh -c)
	cmd := exec.Command(pmPath, args...) //nolint:gosec // user-invoked PM with their own args
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func exitWithCode(code int, err error) error {
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

const maxBlockedDisplay = 5

// pkgFilterResult is the per-package view of the proxy's filtering decision. It
// collapses the possibly-several blocked versions of one package into a single
// line: the youngest blocked version (the one the PM would have installed as
// "latest") paired with the older version the proxy resolved to instead — or an
// empty NewVersion when no safe fallback existed.
type pkgFilterResult struct {
	Name       string
	OldVersion string         // youngest blocked version, normalized version string — SemVer (npm) or PEP 440 (PyPI) (what the PM wanted)
	OldAge     time.Duration  // age of that version at install time
	Severity   model.Severity // severity classification of that age
	NewVersion string         // resolved fallback version, "" if none was available
	NewAge     time.Duration  // age of the resolved version, 0 when unknown
}

func printBlockSummary(blocked []supplychain.BlockedPackage, allowed []supplychain.InstalledPackage, checked int, policy supplychain.Policy, pmName string, installOK bool, pmArgs []string, conflicts []supplychain.ConstraintConflict) {
	s := output.GetStyles()

	if len(blocked) == 0 {
		if checked > 0 {
			fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
				s.MutedText.Render(scPrefix),
				s.SuccessText.Render(output.IconSuccess),
				s.SuccessText.Render(fmt.Sprintf("supply-chain: %s", checkedAllPass(checked))),
				s.MutedText.Render(fmt.Sprintf("(%s policy)", formatPolicyShort(policy.MinReleaseAge))))
		}
		return
	}

	allowedVersions := make(map[string]supplychain.InstalledPackage, len(allowed))
	for _, pkg := range allowed {
		allowedVersions[pkg.Name] = pkg
	}

	results := groupBlockedByPackage(filterRelevantBlocked(blocked), allowedVersions, policy.MinReleaseAge)
	if len(results) == 0 {
		return
	}

	allResolved := true
	for _, r := range results {
		if r.NewVersion == "" {
			allResolved = false
			break
		}
	}

	policyShort := formatPolicyShort(policy.MinReleaseAge)
	verbose := len(results) > maxBlockedDisplay

	// When every displayed package is a prerelease, the filter did not change what
	// a default install would have done: npm/pip/etc. resolve "latest" to the newest
	// *stable* release and never auto-select an alpha/beta/rc. Claiming we "installed
	// a safe version" would overstate the tool's effect — it withheld a prerelease the
	// resolver wouldn't have picked anyway. Frame that case honestly (see header).
	onlyPrerelease := allResultsPrerelease(results)

	// "Installed" wording is only truthful when the package manager actually
	// completed. A repointed "latest" is what the proxy offered, not proof of an
	// install — a pin that only the filtered version satisfies still fails the PM.
	// success drives the green header and the per-line "installed" wording; when
	// the PM exited non-zero we report the filter as a fact and stay neutral.
	success := allResolved && installOK

	// Header. When every filtered package resolved to a safe older version AND the
	// install completed, the user was both protected and unblocked — frame it as
	// success (green). Otherwise stay neutral (muted): either a package had no safe
	// fallback, or the PM did not complete; the per-line glyph and the footnote
	// carry the detail.
	switch {
	case onlyPrerelease && installOK:
		// A bare install would never have selected these prereleases, so don't claim
		// a save. State plainly what the policy did: withheld a prerelease, no effect
		// on the default install. Neutral (muted), not green — nothing was at risk.
		fmt.Fprintf(os.Stderr, "\n%s %s\n",
			s.MutedText.Render(scPrefix),
			s.MutedText.Render(fmt.Sprintf("supply-chain: withheld %s; a default install was unaffected (%s policy)",
				countNoun(len(results), "prerelease"), policyShort)))
	case success:
		versionWord := "version"
		if len(results) > 1 {
			versionWord = "versions"
		}
		fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
			s.MutedText.Render(scPrefix),
			s.SuccessText.Render(output.IconSuccess),
			s.SuccessText.Render(fmt.Sprintf("supply-chain: filtered %s → installed safe %s (%s policy)",
				countNoun(len(results), "too-new release"), versionWord, policyShort)))
	case !installOK:
		fmt.Fprintf(os.Stderr, "\n%s %s\n",
			s.MutedText.Render(scPrefix),
			s.WarningText.Render(fmt.Sprintf("supply-chain: filtered %s; install did not complete (%s policy)",
				countNoun(len(results), "too-new release"), policyShort)))
	default:
		fmt.Fprintf(os.Stderr, "\n%s %s\n",
			s.MutedText.Render(scPrefix),
			s.MutedText.Render(fmt.Sprintf("supply-chain: filtered %s (%s policy)",
				countNoun(len(results), "too-new release"), policyShort)))
	}

	displayCount := len(results)
	if displayCount > maxBlockedDisplay {
		displayCount = maxBlockedDisplay
	}

	// Pad the name, installed-version, and installed-age columns to a common width
	// so the trailing "— skipped …" clauses line up vertically across rows. Widths
	// are computed over the rows actually shown (not the full result set) so a
	// truncated list still aligns.
	var cols colWidths
	for _, r := range results[:displayCount] {
		if n := len(r.Name); n > cols.name {
			cols.name = n
		}
		if n := len(r.NewVersion); n > cols.newVersion {
			cols.newVersion = n
		}
		if n := len(optionalAgeToken(r.NewAge)); n > cols.newAge {
			cols.newAge = n
		}
	}
	for _, r := range results[:displayCount] {
		printPkgFilterLine(s, r, !allResolved, installOK, onlyPrerelease, cols)
	}
	if remaining := len(results) - displayCount; remaining > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n",
			s.MutedText.Render(fmt.Sprintf("… and %d more", remaining)))
	}

	// When the package manager did not complete, name the likely culprit instead
	// of a generic note. The failure could still be unrelated (a typo, a network
	// error), so the language stays hedged — but pointing at a specific package is
	// far more actionable than "if a dependency pins a version…".
	if !installOK {
		printFailureCulprits(s, results, conflicts, policy, pmName, pmArgs)
	}

	// One-time rationale: the first time a user sees a filter on an interactive
	// terminal, explain why brand-new releases are withheld. Suppressed on every
	// subsequent install and in CI/piped output so it never becomes noise.
	if shouldShowRationale() {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n",
			s.MutedText.Render("Why:"),
			s.MutedText.Render("brand-new releases are a common supply-chain attack vector; Armis installs the newest version older than the policy window."))
		markRationaleShown()
	}

	// Footer. The global "off" kill switch is the most-nuclear, least-secure
	// escape hatch, so it is shown only on the SUCCESS path (where the user is
	// merely curious how to opt out), never on a failure. On a failed install
	// printFailureCulprits already laid out the surgical→nuclear remediation
	// ladder; appending "Disable: ...=off" here would invert that ordering and
	// nudge a frustrated developer straight to the blunt instrument.
	if installOK {
		// A long list earns the full divider and copy-paste disable command; the
		// common short case gets a single terse hint instead of heavy chrome.
		if verbose {
			fmt.Fprintf(os.Stderr, "\n  %s\n", s.MutedText.Render(strings.Repeat("─", scSepLen)))
			fmt.Fprintf(os.Stderr, "  %s %s\n\n",
				s.MutedText.Render("Disable:"),
				s.Bold.Render(fmt.Sprintf("%s=off %s install", envSCOff, pmName)))
		} else {
			fmt.Fprintf(os.Stderr, "  %s %s\n",
				s.MutedText.Render("Disable:"),
				s.Bold.Render(fmt.Sprintf("%s=off", envSCOff)))
		}
	}
}

// printFailureCulprits is WS1's core: on a failed install, name the specific
// package(s) the age filter most likely broke and lay out the remediation
// hatches surgical-first, nuclear-last. It composes three signals, strongest to
// weakest:
//
//  1. WS2 conflicts (npm-family): a removed version satisfied a dependent's
//     range and no surviving version does — the canonical transitive break, so
//     it names both the dependency and who required it.
//  2. No-fallback packages (NewVersion == ""): stripped to nothing, so if the
//     install failed they are the overwhelmingly likely cause.
//  3. Otherwise: every filtered package had a fallback, so the cause is less
//     certain — list them as candidates and stay hedged.
//
// Language stays hedged throughout ("likely", "may") because the install could
// have failed for an unrelated reason. The remediation ladder is ordered SKIP →
// exclusions → min-age (surgical/reviewable → broad), and deliberately omits the
// global ARMIS_SUPPLY_CHAIN=off kill switch so a 3am developer does not reach for
// the nuclear option first.
func printFailureCulprits(s *output.Styles, results []pkgFilterResult, conflicts []supplychain.ConstraintConflict, policy supplychain.Policy, pmName string, pmArgs []string) {
	policyShort := formatPolicyShort(policy.MinReleaseAge)

	// Lead with protection, not apology: state the security win first so the
	// developer feels protected, not obstructed. The self-ID prefix makes the
	// source obvious to someone who didn't add armis to their pipeline.
	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		s.Bold.Render("[armis supply-chain]"),
		s.MutedText.Render("the install did not complete. This tool withheld brand-new releases on purpose — a common supply-chain attack vector. The block may be why the install failed (or it could be unrelated, e.g. a typo or network error)."))

	// nuclearShown tracks whether we named at least one specific culprit; it
	// gates the closing "managed by your platform team" pointer.
	named := false

	// (1) WS2 conflicts — the strongest, most specific signal. Each styled span is
	// a separate Fprintf arg (never a Render nested inside another Render, which
	// would terminate the outer color early); the package/range names are bolded.
	for _, c := range conflicts {
		named = true
		fmt.Fprintf(os.Stderr, "  %s %s %s %s %s %s %s\n",
			s.WarningText.Render("→"),
			s.Bold.Render(c.Dep),
			s.MutedText.Render(fmt.Sprintf("has no version older than the %s policy that satisfies", policyShort)),
			s.Bold.Render(c.Range),
			s.MutedText.Render("(required by"),
			s.Bold.Render(c.ByPkg+")"),
			s.MutedText.Render("— this is the likely cause."))
	}

	// (2) No-fallback packages.
	var noFallback, withFallback []pkgFilterResult
	for _, r := range results {
		if r.NewVersion == "" {
			noFallback = append(noFallback, r)
		} else {
			withFallback = append(withFallback, r)
		}
	}
	for _, r := range noFallback {
		named = true
		// The muted clause optionally leads with the blocked version's age token,
		// then the explanation. Kept in one rendered span (separate from the bolded
		// name@version) so colors don't nest.
		explanation := fmt.Sprintf("has no version older than the %s policy — if a dependency requires it, this is why the install failed.", policyShort)
		if tok := optionalAgeToken(r.OldAge); tok != "" {
			explanation = tok + " " + explanation
		}
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			s.WarningText.Render("→"),
			s.Bold.Render(fmt.Sprintf("%s@%s", r.Name, r.OldVersion)),
			s.MutedText.Render(explanation))
	}

	// (3) Fallback-exists case with no confirmed conflict: the canonical
	// transitive break (older version exists but violates a parent's range) is
	// what WS2 catches for npm. When WS2 found nothing (or this is pip/uv, where
	// the one-hop check isn't available), the filtered packages are still the
	// candidates — list them and stay honest about the uncertainty.
	if len(conflicts) == 0 && len(noFallback) == 0 && len(withFallback) > 0 {
		named = true
		names := make([]string, 0, len(withFallback))
		for _, r := range withFallback {
			names = append(names, r.Name)
		}
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			s.WarningText.Render("→"),
			s.MutedText.Render("each filtered package resolved to an older version, but one may not satisfy a dependent's range. Candidates:"),
			s.Bold.Render(strings.Join(names, ", ")+"."))
	}

	// pip/uv attribution gap: the one-hop constraint check is npm-family only, so
	// a pip/uv user gets named no-fallback culprits but no "required by X" line.
	// Say so explicitly to prevent the "why did my colleague's npm failure name a
	// culprit but mine didn't?" confusion, and point at the right local tool.
	if canonicalPM(pmName) == pmPip || canonicalPM(pmName) == pmUV || canonicalPM(pmName) == pmUVX {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			s.MutedText.Render("Note:"),
			s.MutedText.Render("constraint attribution isn't available for pip/uv — run `uv tree` or `pipdeptree` to find which package requires the blocked dependency."))
	}

	// Remediation ladder: surgical/reviewable first, broad last. The global
	// ARMIS_SUPPLY_CHAIN=off kill switch is intentionally absent.
	firstCulprit := firstCulpritName(conflicts, noFallback, withFallback)
	fmt.Fprintf(os.Stderr, "\n  %s\n", s.MutedText.Render("To proceed (most surgical first):"))
	// 1. Allow this one package — full copy-paste command incl. PM + the user's args.
	fmt.Fprintf(os.Stderr, "    %s %s\n",
		s.MutedText.Render("1. Allow one package (persists in this env; exempts its future versions):"),
		s.Bold.Render(skipCommand(firstCulprit, pmName, pmArgs)))
	// 2. Permanent, reviewed team exception.
	fmt.Fprintf(os.Stderr, "    %s %s\n",
		s.MutedText.Render(fmt.Sprintf("2. Permanent team exception: add %s to", quoteOrPlaceholder(firstCulprit))),
		s.Bold.Render("exclusions: in .armis-supply-chain.yaml"))
	// 3. Relax the window for ALL packages (NOT --min-age: wrap reads YAML only).
	fmt.Fprintf(os.Stderr, "    %s %s %s\n",
		s.MutedText.Render("3. Relax the window for all packages: edit"),
		s.Bold.Render("min-age: in .armis-supply-chain.yaml"),
		s.MutedText.Render("(weakens the check for every package)"))

	if named {
		fmt.Fprintf(os.Stderr, "  %s\n",
			s.MutedText.Render("(supply-chain enforcement is managed by your platform team.)"))
	}
}

// skipCommand renders the full copy-paste ARMIS_SUPPLY_CHAIN_SKIP command,
// including the package manager and the user's own arguments, so the developer
// can paste it verbatim. When no specific culprit was identified it uses a
// "<package>" placeholder rather than emitting a broken command.
func skipCommand(pkg, pmName string, pmArgs []string) string {
	name := pkg
	if name == "" {
		name = "<package>"
	}
	cmd := fmt.Sprintf("%s=%s %s", envSCSkip, name, pmName)
	if len(pmArgs) > 0 {
		cmd += " " + strings.Join(pmArgs, " ")
	}
	return cmd
}

// firstCulpritName picks the single best package name to seed the remediation
// commands, preferring (in order) a WS2 conflict's dependency, a no-fallback
// package, then any filtered package. Returns "" when nothing was identified.
func firstCulpritName(conflicts []supplychain.ConstraintConflict, noFallback, withFallback []pkgFilterResult) string {
	if len(conflicts) > 0 {
		return conflicts[0].Dep
	}
	if len(noFallback) > 0 {
		return noFallback[0].Name
	}
	if len(withFallback) > 0 {
		return withFallback[0].Name
	}
	return ""
}

// quoteOrPlaceholder renders a package name in double quotes for the exclusions
// guidance, or a generic placeholder when no culprit was identified.
func quoteOrPlaceholder(pkg string) string {
	if pkg == "" {
		return "the package"
	}
	return fmt.Sprintf("%q", pkg)
}

// colWidths holds the maximum plain-text width of each aligned column. Padding
// is computed on the unstyled strings: len() on a lipgloss-rendered value counts
// invisible ANSI escape bytes, so columns must be padded before .Render().
type colWidths struct {
	name       int
	newVersion int // width of the installed/resolved version column
	newAge     int // width of the installed version's age token column
}

// ageToken formats a version's age as it appears on the line, e.g. "(1 day
// old)". Centralized so the column-width measurement and the rendered output
// cannot drift apart.
func ageToken(age time.Duration) string {
	return fmt.Sprintf("(%s old)", formatDurationShort(age))
}

// optionalAgeToken is ageToken for an age that may be unknown — the resolved
// version's age, or a blocked PyPI file the proxy could not stamp (Age == 0), or
// a non-positive value from clock skew. It returns "" in those cases so the line
// omits the age rather than printing a false "(0 minutes old)".
func optionalAgeToken(age time.Duration) string {
	if age <= 0 {
		return ""
	}
	return ageToken(age)
}

// rightPad appends spaces so s occupies at least width columns. It pads the
// plain string before styling, keeping alignment correct with colors on or off.
func rightPad(s string, width int) string {
	if pad := width - len(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// printPkgFilterLine renders one package's filter outcome on a single line, led
// by what was actually installed and trailed by what was skipped:
//
//	● superdialog  0.2.3 installed (8 days old) — skipped 0.2.5 (6 hours old)
//
// Leading with the resolved version is deliberate: the headline fact is that a
// safe, older version is what the user ended up with, not that a newer one was
// withheld. The skipped version is demoted to a trailing clause for context.
//
// The leading glyph depends on context: when every package resolved
// (mixed == false) the header already signals success, so the line shows the
// severity dot to convey how fresh the *skipped* version was; in the mixed case
// the header is neutral, so a per-line ✓ carries the resolved tone. When the
// blocked versions were all prereleases (prerelease == true) the policy didn't
// change a default install, so the line stays neutral — a muted dot, never a
// colored severity tier that would imply averted risk. The resolved-version
// wording is "installed" only when the PM completed (installOK); otherwise it
// reads "available" — the safe version exists, but we cannot claim it was
// installed. When no safe fallback existed (NewVersion == "") the line inverts:
// it leads with a warning instead of an install. cols pads the columns so the
// skipped clauses line up across rows.
func printPkgFilterLine(s *output.Styles, r pkgFilterResult, mixed, installOK, prerelease bool, cols colWidths) {
	// Omit the age when it is unknown (OldAge == 0 for an undatable PyPI file, or
	// non-positive under clock skew) rather than claiming a precise "(0 minutes
	// old)". The version alone is still actionable.
	skipped := fmt.Sprintf("— skipped %s", r.OldVersion)
	if tok := optionalAgeToken(r.OldAge); tok != "" {
		skipped += " " + tok
	}

	// No safe fallback: there is nothing "installed" to lead with, so invert the
	// line — warn first, then name what was skipped.
	if r.NewVersion == "" {
		fmt.Fprintf(os.Stderr, "  %s %s %s  %s\n",
			s.WarningText.Render("⚠"),
			s.Bold.Render(rightPad(r.Name, cols.name)),
			s.WarningText.Render("no older safe version (install may fail)"),
			s.MutedText.Render(skipped))
		return
	}

	resolvedWord := "installed"
	if !installOK {
		resolvedWord = "available"
	}

	var glyph string
	switch {
	case prerelease:
		// Withheld a prerelease the resolver wouldn't have chosen: no risk tier to
		// convey, so use a neutral muted dot rather than a severity color.
		glyph = s.MutedText.Render(output.SeverityDot)
	case mixed:
		glyph = s.SuccessText.Render(output.IconSuccess)
	default:
		glyph = severityDot(s, r.Severity)
	}

	fmt.Fprintf(os.Stderr, "  %s %s %s %s %s  %s\n",
		glyph,
		s.Bold.Render(rightPad(r.Name, cols.name)),
		s.SuccessText.Render(rightPad(r.NewVersion, cols.newVersion)),
		s.MutedText.Render(resolvedWord),
		s.MutedText.Render(rightPad(optionalAgeToken(r.NewAge), cols.newAge)),
		s.MutedText.Render(skipped))
}

// groupBlockedByPackage collapses blocked versions into one result per package.
// For each package it keeps the youngest blocked version — the one the PM would
// have installed as "latest" — and pairs it with the resolved fallback from
// allowedVersions. Results are sorted youngest-first (ties broken by name) so
// the freshest, riskiest package leads the list and output is deterministic.
func groupBlockedByPackage(blocked []supplychain.BlockedPackage, allowedVersions map[string]supplychain.InstalledPackage, threshold time.Duration) []pkgFilterResult {
	byName := make(map[string]pkgFilterResult, len(blocked))
	for _, b := range blocked {
		if existing, ok := byName[b.Name]; ok && existing.OldAge <= b.Age {
			continue // already holding a younger (or equally young) version
		}
		resolved := allowedVersions[b.Name]
		byName[b.Name] = pkgFilterResult{
			Name:       b.Name,
			OldVersion: blockedDisplayVersion(b),
			OldAge:     b.Age,
			Severity:   supplychain.ClassifySeverity(b.Age, threshold),
			NewVersion: resolved.Version,
			NewAge:     resolved.Age,
		}
	}

	results := make([]pkgFilterResult, 0, len(byName))
	for _, r := range byName {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].OldAge != results[j].OldAge {
			return results[i].OldAge < results[j].OldAge
		}
		return results[i].Name < results[j].Name
	})
	return results
}

// checkedAllPass renders the "N packages checked, all pass" clause with verb
// agreement: countNoun inflects the noun ("1 package" vs "N packages") but not
// the verb, so the singular case collapses "all pass" → "passed" ("all" implies
// plural). Centralized so the proxy and pre-install paths phrase it identically
// and the singular pre-install case never prints "1 packages checked".
func checkedAllPass(n int) string {
	if n == 1 {
		return "1 package checked, passed"
	}
	return fmt.Sprintf("%d packages checked, all pass", n)
}

// formatPolicyShort renders the policy window as a hyphenated adjective for use
// directly before a noun, e.g. "3-day" in "(3-day policy)". It mirrors the unit
// boundaries of formatDurationShort but always uses the singular unit form.
func formatPolicyShort(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d-minute", int(d.Minutes()))
	}
	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%d-hour", hours)
	}
	return fmt.Sprintf("%d-day", hours/24)
}

// rationaleMarkerFile is the cache-dir filename whose presence records that the
// one-time supply-chain "why" explainer has already been shown to this user.
const rationaleMarkerFile = "supply-chain-onboarded"

// shouldShowRationale reports whether to print the one-time "why" explainer. It
// is gated on an interactive terminal (so CI logs and piped output stay terse)
// and on the absence of the marker file (so it appears only once).
func shouldShowRationale() bool {
	return cli.IsInteractive() && !rationaleAlreadyShown()
}

// rationaleAlreadyShown reports whether the onboarding marker file exists. A
// path that cannot be resolved is treated as "already shown" so a broken cache
// directory yields terse output rather than the explainer on every install.
func rationaleAlreadyShown() bool {
	path := util.GetCacheFilePath(rationaleMarkerFile)
	if path == "" {
		return true
	}
	_, err := os.Stat(path)
	return err == nil
}

// markRationaleShown records that the explainer has been shown by creating the
// marker file. It is best-effort: any failure (e.g. an unwritable cache dir) is
// ignored so a marker-write error never blocks an install or surfaces an error.
func markRationaleShown() {
	dir := util.GetCacheDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := util.GetCacheFilePath(rationaleMarkerFile)
	if path == "" {
		return
	}
	_ = os.WriteFile(path, []byte("1"), 0o600)
}

func filterRelevantBlocked(blocked []supplychain.BlockedPackage) []supplychain.BlockedPackage {
	relevant := make([]supplychain.BlockedPackage, 0, len(blocked))
	for _, b := range blocked {
		// Classify on the normalized version, never the raw Version: a PyPI
		// Version is a filename ("filelock-3.29.2.tar.gz") whose first '-' would
		// fool the SemVer check into treating every package as a prerelease.
		if supplychain.IsPrerelease(blockedDisplayVersion(b)) {
			continue
		}
		relevant = append(relevant, b)
	}
	if len(relevant) == 0 {
		return blocked
	}
	return relevant
}

// blockedDisplayVersion returns the normalized semver to show and classify for a
// blocked package: the proxy-supplied DisplayVersion when present, falling back
// to the raw Version (npm semver, or a PyPI filename that could not be parsed).
func blockedDisplayVersion(b supplychain.BlockedPackage) string {
	if b.DisplayVersion != "" {
		return b.DisplayVersion
	}
	return b.Version
}

// allResultsPrerelease reports whether every grouped result is a prerelease. It
// drives the honest "withheld a prerelease" framing: when this holds, the proxy
// only blocked versions a default install would never have selected (resolvers
// pick the newest *stable* release for "latest"), so the summary must not claim
// it installed a safe version in place of one the user was about to get. An empty
// slice returns false — there is nothing to characterize.
func allResultsPrerelease(results []pkgFilterResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if !supplychain.IsPrerelease(r.OldVersion) {
			return false
		}
	}
	return true
}

func severityDot(s *output.Styles, sev model.Severity) string {
	return s.GetSeverityText(sev).Render(output.SeverityDot)
}

func formatDurationShort(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%d hours", hours)
	}
	days := hours / 24
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

func registryEnvForPM(pm, registryURL string) []string {
	switch pm {
	case pmBun:
		return []string{
			fmt.Sprintf("npm_config_registry=%s", registryURL),
			fmt.Sprintf("BUN_CONFIG_REGISTRY=%s", registryURL),
		}
	case pmYarn:
		return []string{
			fmt.Sprintf("npm_config_registry=%s", registryURL),
			fmt.Sprintf("YARN_NPM_REGISTRY_SERVER=%s", registryURL),
			// Yarn Berry (2+) refuses plain-http registries unless the host is
			// whitelisted, failing every wrapped install with YN0081 — and the wrap
			// proxy is necessarily plain http on loopback. Whitelist exactly that
			// host; Yarn classic (1.x) ignores the variable.
			"YARN_UNSAFE_HTTP_WHITELIST=127.0.0.1",
		}
	case pmUV, pmUVX:
		// uvx is uv's on-demand tool runner (`uvx X` ≡ `uv tool run X`); it shares
		// uv's resolver and config, so it honors the same UV_INDEX_URL override.
		// registryURL is built by the caller with a trailing slash, so trim it
		// before appending the PEP 503 "/simple/" path to avoid a "//simple/"
		// double slash. Clients normalize it today, but the PyPI proxy handler
		// (future work) should receive a clean "/simple/..." path.
		return []string{
			fmt.Sprintf("UV_INDEX_URL=%s/simple/", strings.TrimSuffix(registryURL, "/")),
		}
	case pmPip:
		return []string{
			fmt.Sprintf("PIP_INDEX_URL=%s/simple/", strings.TrimSuffix(registryURL, "/")),
		}
	default:
		return []string{
			fmt.Sprintf("npm_config_registry=%s", registryURL),
		}
	}
}

// parseSkipPackages turns the ARMIS_SUPPLY_CHAIN_SKIP env var into a list of
// package names the proxy should pass through without an age check. Entries may
// be separated by commas or any whitespace (so both "a,b" and "a b c" work).
// Input size and result count are bounded to prevent DoS via unbounded allocation.
func parseSkipPackages(raw string) []string {
	if len(raw) > maxSkipPackagesLen {
		raw = raw[:maxSkipPackagesLen]
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	// Pre-allocate a non-nil slice so empty/whitespace input yields []string{}
	// (an empty skip set) rather than nil, matching FieldsFunc's contract.
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(result) >= maxSkipPackages {
			break
		}
		if len(p) > 255 {
			continue
		}
		result = append(result, p)
	}
	return result
}

func resolveWrapPolicy() supplychain.Policy {
	dir := supplychain.FindConfigDir(".")
	if dir == "" {
		return supplychain.DefaultPolicy()
	}
	cfg, err := supplychain.LoadConfig(dir)
	if err == nil && cfg != nil {
		if p, err := cfg.ToPolicy(); err == nil {
			return p
		}
	}
	return supplychain.DefaultPolicy()
}

// wrapEcosystemEnforced reports whether the config (searched upward from the
// current directory) scopes enforcement to include this package manager's
// ecosystem. It uses loadConfigUpward so unknown-ecosystem warnings are emitted
// consistently with check/status. Any load error or absent config means
// "enforce" (fail safe). Pass the canonical PM name so versioned pip variants
// resolve correctly.
func wrapEcosystemEnforced(canonicalPMName string) bool {
	eco := pmToEcosystem(canonicalPMName)
	if eco == "" {
		return true
	}
	cfg, _, err := loadConfigUpward(".")
	if err != nil || cfg == nil {
		return true
	}
	return cfg.EnforcesEcosystem(eco)
}

// requiresPreInstallBlock reports whether an invocation must be enforced via a
// pre-install lockfile audit rather than the transparent registry proxy.
// poetry, pipenv, and pdm resolve from their own lockfiles and do not honor an
// npm-style registry override, so the proxy cannot filter young versions for
// them; instead the build is blocked up front if the lockfile contains a
// too-young package.
//
// uv is the inverse case: it honors an index override (UV_INDEX_URL) but
// persists it — every lockfile-writing command (sync, lock, add, remove,
// run, …) records the configured index as each package's source.registry in
// uv.lock, and an index that differs from the recorded one marks the lock
// outdated and triggers a full re-lock. Proxying those commands therefore
// stamps the ephemeral http://127.0.0.1:<port> proxy address into uv.lock,
// corrupting it for every install that runs outside the wrapper (Docker
// builds, CI, teammates). Only `uv pip` and `uv tool`, which never touch
// uv.lock, are safe to proxy (see uvProxySafe); every other uv invocation
// takes the audit path. uvx (a separate binary with no project lockfile) is
// unaffected and stays on the proxy.
//
// Pass the canonical PM name (canonicalPM) and the PM's arguments.
func requiresPreInstallBlock(pm string, pmArgs []string) bool {
	switch pm {
	case pmPoetry, pmPipenv, pmPDM, pmMaven, pmGradle:
		return true
	case pmUV:
		return !uvProxySafe(pmArgs)
	}
	return false
}

// uvProxySafe reports whether a uv invocation can be routed through the
// transparent proxy without the index URL leaking into uv.lock. Only the
// `uv pip …` (ad-hoc pip interface) and `uv tool …` (tool runner) subcommands
// never write the project lockfile. The subcommand is recognized only when it
// is the first argument: uv's global flags can take values (e.g.
// --directory <dir>), so scanning past flags could mistake a flag value for
// the subcommand and proxy a lock-writing command. Anything unrecognized
// fails safe to the lockfile audit, which can never corrupt the lock.
//
// armis:ignore cwe:628 reason:examining only pmArgs[0] is the deliberate safe design, not a flaw — an unrecognized first arg (e.g. a global flag prepended before a subcommand) returns false, routing the invocation to the lockfile audit that never injects the proxy, so prepended flags make enforcement stricter, not laxer (pinned by TestRequiresPreInstallBlock "uv flag before pip subcommand")
func uvProxySafe(pmArgs []string) bool {
	if len(pmArgs) == 0 {
		return false
	}
	switch pmArgs[0] {
	case "pip", "tool":
		return true
	}
	return false
}

func runPreInstallBlock(cmd *cobra.Command, pmName string, pmArgs []string) error {
	skipPkgs := parseSkipPackages(os.Getenv(envSCSkip))
	policy := resolveWrapPolicy()

	// Walk up from the current directory to find the lockfile. poetry/pdm/pipenv
	// are commonly run from a subdirectory while the lockfile lives at the project
	// root (monorepos, CI steps that cd into a service dir); probing only "." here
	// would silently skip enforcement and run the build unprotected.
	lockfilePath := supplychain.FindEcosystemLockfile(".", pmToEcosystem(pmName))

	if lockfilePath == "" {
		fmt.Fprintf(os.Stderr, "%s no lockfile found for %s, running without enforcement\n", scPrefix, pmName)
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	// Gradle records resolved versions in gradle.lockfile but does not regenerate
	// it automatically: if build.gradle changed since the lock was written, the
	// audit reflects stale versions. Warn so the user knows to re-lock.
	if pmName == pmGradle {
		checkGradleStaleness(lockfilePath)
	}

	// A pom.xml lists only direct dependencies — Maven resolves transitives at
	// build time, so they are not audited here. Flag the gap so the result is not
	// mistaken for full coverage.
	if pmName == pmMaven && strings.HasSuffix(lockfilePath, "pom.xml") {
		fmt.Fprintf(os.Stderr, "%s note: pom.xml only covers direct dependencies. For full transitive\n", scPrefix)
		fmt.Fprintf(os.Stderr, "  coverage, consider a lockfile plugin (e.g., io.github.chains-project:maven-lockfile)\n")
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
	defer cancel()

	result, err := check.RunCheck(ctx, policy, lockfilePath, "")
	if err != nil {
		// Honor the fail-open policy the same way the proxy path does: with
		// FailOpen set, a failed audit (e.g. PyPI unreachable, lockfile parse
		// error) allows the build; otherwise it blocks. poetry/pipenv/pdm have
		// no other enforcement path, so silently running on every audit error
		// would let a transient failure bypass the control entirely.
		if policy.FailOpen {
			fmt.Fprintf(os.Stderr, "%s supply-chain: check failed, allowing (fail-open): %v\n", scPrefix, err)
			return exitWithCode(execPMFunc(pmName, pmArgs, nil))
		}
		fmt.Fprintf(os.Stderr, "%s supply-chain: check failed, blocking (fail-closed): %v\n", scPrefix, err)
		fmt.Fprintf(os.Stderr, "  %s\n", "Set fail-open: true in .armis-supply-chain.yaml to allow installs when the check cannot run.")
		os.Exit(1)
		return nil
	}

	// Drop any violation whose package is in the skip list before deciding
	// whether to block, so ARMIS_SUPPLY_CHAIN_SKIP works for the pre-install
	// path the same way SkipPackages works for the proxy path.
	skip := make(map[string]bool, len(skipPkgs))
	for _, s := range skipPkgs {
		skip[s] = true
	}
	var violations []supplychain.Violation
	for _, v := range result.Violations {
		if !skip[v.Name] {
			violations = append(violations, v)
		}
	}

	if len(violations) == 0 {
		if result.Checked > 0 {
			s := output.GetStyles()
			fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
				s.MutedText.Render(scPrefix),
				s.SuccessText.Render(output.IconSuccess),
				s.SuccessText.Render(fmt.Sprintf("supply-chain: %s", checkedAllPass(result.Checked))),
				s.MutedText.Render(fmt.Sprintf("(%s policy)", formatPolicyShort(policy.MinReleaseAge))))
		}
		// Clean audit: the build is about to run, so report the install as ok. The
		// PM's own exit code is not captured on this path (exec replaces nothing),
		// but a clean audit is the audit-trail fact security teams want recorded.
		writePreInstallReport(policy, pmName, result.Checked, nil, statusOK)
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	writePreInstallReport(policy, pmName, result.Checked, violations, statusFailed)
	printPreInstallBlockSummary(violations, policy, pmName)
	os.Exit(1)
	return nil
}

// writePreInstallReport emits the WS3 compliance report for the pre-install
// (lockfile-audit) path when ARMIS_SUPPLY_CHAIN_REPORT is set. Violations map to
// the report's "blocked" set; the audit path has no proxy-resolved fallbacks or
// one-hop conflicts, so those slices stay empty. Best-effort — never alters the
// build outcome.
func writePreInstallReport(policy supplychain.Policy, pmName string, checked int, violations []supplychain.Violation, status string) {
	reportPath := os.Getenv(envSCReport)
	if reportPath == "" {
		return
	}
	blocked := make([]supplychain.BlockedPackage, 0, len(violations))
	for _, v := range violations {
		blocked = append(blocked, supplychain.BlockedPackage{
			Name:           v.Name,
			Version:        v.Version,
			DisplayVersion: v.Version,
			Age:            v.Age,
		})
	}
	rep := buildComplianceReport(reportInput{
		Policy:        policy,
		Mode:          "pre-install",
		Ecosystem:     string(pmToEcosystem(canonicalPM(pmName))),
		Checked:       checked,
		Blocked:       blocked,
		InstallStatus: status,
	})
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:reportPath is the operator's own ARMIS_SUPPLY_CHAIN_REPORT env var naming an output file in their own environment (same trust model as scan's --output, suppressed at the same sink); a local CLI writing where its operator configured it crosses no trust boundary
	writeComplianceReport(reportPath, rep)
}

func printPreInstallBlockSummary(violations []supplychain.Violation, policy supplychain.Policy, pmName string) {
	s := output.GetStyles()

	sort.Slice(violations, func(i, j int) bool {
		return violations[i].Age < violations[j].Age
	})

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		s.MutedText.Render(scPrefix),
		s.WarningText.Render(fmt.Sprintf("supply-chain: BLOCKED — %s younger than %s", countNoun(len(violations), "package"), formatDurationShort(policy.MinReleaseAge))))

	fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("Build was stopped BEFORE execution to prevent supply chain attacks."))

	displayCount := len(violations)
	if displayCount > maxBlockedDisplay {
		displayCount = maxBlockedDisplay
	}

	fmt.Fprintf(os.Stderr, "\n  %s\n", s.MutedText.Render("Violations:"))
	for _, v := range violations[:displayCount] {
		age := formatDurationShort(v.Age)
		dot := severityDot(s, v.Severity)
		fmt.Fprintf(os.Stderr, "    %s %s %s\n",
			dot,
			s.Bold.Render(fmt.Sprintf("%s@%s", v.Name, v.Version)),
			s.MutedText.Render(fmt.Sprintf("(%s old)", age)))
	}
	if remaining := len(violations) - displayCount; remaining > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n",
			s.MutedText.Render(fmt.Sprintf("… and %d more", remaining)))
	}

	names := blockedViolationNames(violations)

	fmt.Fprintf(os.Stderr, "\n  %s\n", s.MutedText.Render(strings.Repeat("─", scSepLen)))
	if len(names) <= 3 {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			s.MutedText.Render("Bypass:"),
			s.Bold.Render(fmt.Sprintf("%s=%s %s <args>", envSCSkip, strings.Join(names, ","), pmName)))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		s.MutedText.Render("Disable:"),
		s.Bold.Render(fmt.Sprintf("%s=off %s <args>", envSCOff, pmName)))
	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		s.MutedText.Render("Exclude:"),
		s.Bold.Render("add to exclusions in .armis-supply-chain.yaml"))
}

func blockedViolationNames(violations []supplychain.Violation) []string {
	seen := make(map[string]bool)
	names := make([]string, 0, len(violations))
	for _, v := range violations {
		if !seen[v.Name] {
			seen[v.Name] = true
			names = append(names, v.Name)
		}
	}
	return names
}

// normalizeProxyResidue rewrites the ephemeral proxy origin back to the real
// upstream origin in every artifact the just-run package manager may have
// persisted it into. For the Node PMs that is the project lockfile: bun.lock
// is the confirmed offender (`bun update` records full tarball URLs), and the
// other node lockfiles are swept defensively because older npm/yarn releases
// recorded the configured registry in resolved fields — a clean lockfile is a
// no-op read. For uv (whose only proxied subcommands are the lockfile-free
// `pip` and `tool`) it is the per-tool receipts: `uv tool install` records the
// index-url it was invoked with, which would break every later
// `uv tool upgrade` against the dead proxy address. Failures are reported but
// never block: the install itself already completed, and a residue warning the
// user can act on beats failing the build after the fact.
func normalizeProxyResidue(pm string, pmArgs []string, proxyOrigin, upstreamOrigin string) {
	var paths []string
	switch pm {
	case pmNPM, pmNPX, pmPNPM, pmBun, pmYarn:
		for _, eco := range []supplychain.Ecosystem{
			supplychain.EcosystemBun, supplychain.EcosystemNPM,
			supplychain.EcosystemPNPM, supplychain.EcosystemYarn,
		} {
			if p := supplychain.FindEcosystemLockfile(".", eco); p != "" {
				paths = append(paths, p)
			}
		}
		// npm-shrinkwrap.json is package-lock.json's publishable twin: `npm
		// shrinkwrap` converts the lock in place and later installs update it the
		// same way, so it carries the same resolved URLs and deserves the same
		// defensive sweep.
		if p := supplychain.FindUpward(".", "npm-shrinkwrap.json"); p != "" {
			paths = append(paths, p)
		}
		// bun's legacy binary lockfile encodes lengths, so a text substitution
		// would corrupt it. Detect the residue and tell the user how to repair.
		if lockb := supplychain.FindUpward(".", "bun.lockb"); lockb != "" && supplychain.FileContainsString(lockb, proxyOrigin) {
			fmt.Fprintf(os.Stderr, "%s warning: %s contains the ephemeral proxy address and cannot be rewritten in place.\n", scPrefix, lockb)
			fmt.Fprintf(os.Stderr, "  Repair with: ARMIS_SUPPLY_CHAIN=off bun install --save-text-lockfile\n")
		}
	case pmUV, pmUVX:
		paths = uvToolReceipts()
		// `uv pip compile --emit-index-url -o FILE` writes the configured index —
		// here the proxy URL — into the generated requirements file (verified on
		// uv 0.8). Sweep the explicit output file; output redirected to stdout by
		// the user's shell happens outside this process and cannot be intercepted,
		// which is one reason `supply-chain check` also flags loopback registry
		// references in lockfiles.
		if out := uvCompileOutputFile(pmArgs); out != "" {
			paths = append(paths, out)
		}
	}

	for _, p := range paths {
		changed, err := supplychain.NormalizeArtifact(p, proxyOrigin, upstreamOrigin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s supply-chain: could not remove proxy address from %s: %v\n", scPrefix, p, err)
			continue
		}
		if changed {
			s := output.GetStyles()
			fmt.Fprintf(os.Stderr, "%s %s\n",
				s.MutedText.Render(scPrefix),
				s.MutedText.Render(fmt.Sprintf("supply-chain: restored registry address in %s", filepath.Base(p))))
		}
	}
}

// uvCompileOutputFile returns the path passed to a uv invocation's
// -o/--output-file flag (as used by `uv pip compile`), or "" when absent. Both
// the space-separated and =-attached spellings are recognized; an unrecognized
// spelling simply leaves the file to the loopback-residue warning in
// `supply-chain check` rather than risking a wrong-file sweep.
func uvCompileOutputFile(pmArgs []string) string {
	for i := 0; i < len(pmArgs); i++ {
		switch {
		case pmArgs[i] == "-o" || pmArgs[i] == "--output-file":
			if i+1 < len(pmArgs) {
				return pmArgs[i+1]
			}
			return ""
		case strings.HasPrefix(pmArgs[i], "--output-file="):
			return strings.TrimPrefix(pmArgs[i], "--output-file=")
		}
	}
	return ""
}

// uvToolReceipts returns the uv-receipt.toml paths of every installed uv tool.
// The receipts directory resolution mirrors uv's own: $UV_TOOL_DIR, then
// $XDG_DATA_HOME/uv/tools, then ~/.local/share/uv/tools. The glob pattern is
// fixed, so only receipt files of installed tools are ever returned.
func uvToolReceipts() []string {
	dir := os.Getenv("UV_TOOL_DIR")
	if dir == "" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dir = filepath.Join(xdg, "uv", "tools")
		} else if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".local", "share", "uv", "tools")
		} else {
			return nil
		}
	}
	receipts, err := filepath.Glob(filepath.Join(dir, "*", "uv-receipt.toml"))
	if err != nil {
		return nil
	}
	return receipts
}

// pmToEcosystem maps a (canonical) package-manager name to its ecosystem. It
// covers every supported PM — both the pre-install ones (used by
// runPreInstallBlock to locate the lockfile) and the proxied ones (used by the
// ecosystems-config scoping gate). Pass the canonical name (canonicalPM) so a
// versioned pip variant resolves to EcosystemPip.
func pmToEcosystem(pm string) supplychain.Ecosystem {
	switch pm {
	case pmNPM:
		return supplychain.EcosystemNPM
	case pmNPX:
		// npx is the npm package runner, not a distinct ecosystem: it resolves from
		// the npm registry and has no lockfile of its own. Mapping it to
		// EcosystemNPM lets the config "ecosystems" scoping gate treat npx exactly
		// like npm — `ecosystems: [npm]` enforces both, and scoping npm out
		// (e.g. `ecosystems: [pip]`) passes npx through too, so the two never diverge.
		return supplychain.EcosystemNPM
	case pmPNPM:
		return supplychain.EcosystemPNPM
	case pmBun:
		return supplychain.EcosystemBun
	case pmYarn:
		return supplychain.EcosystemYarn
	case pmPip:
		return supplychain.EcosystemPip
	case pmUV:
		return supplychain.EcosystemUV
	case pmUVX:
		// uvx is uv's package runner, not a distinct ecosystem: it resolves from
		// PyPI and has no lockfile of its own. Mapping it to EcosystemUV lets the
		// config "ecosystems" scoping gate treat uvx exactly like uv — `ecosystems:
		// [uv]` enforces both, and scoping uv out (e.g. `ecosystems: [npm]`) passes
		// uvx through too, so the two never diverge. Mirrors npx → EcosystemNPM.
		return supplychain.EcosystemUV
	case pmPoetry:
		return supplychain.EcosystemPoetry
	case pmPipenv:
		return supplychain.EcosystemPipfile
	case pmPDM:
		return supplychain.EcosystemPDM
	case pmMaven:
		return supplychain.EcosystemMaven
	case pmGradle:
		return supplychain.EcosystemGradle
	default:
		return ""
	}
}

// checkGradleStaleness warns when build.gradle (or build.gradle.kts) has been
// modified more recently than gradle.lockfile, which means the lock — and the
// audit derived from it — may not reflect the current dependency declarations.
// It is advisory only: a stale lock is a correctness gap the user should resolve
// with "gradle dependencies --write-locks", not a reason to block the build.
func checkGradleStaleness(lockfilePath string) {
	lockInfo, err := os.Stat(lockfilePath)
	if err != nil {
		return
	}

	// gradle.lockfile sits beside build.gradle (or the Kotlin DSL build.gradle.kts);
	// trimming the lockfile leaf yields the directory prefix to probe.
	prefix := strings.TrimSuffix(lockfilePath, "gradle.lockfile")
	buildInfo, err := os.Stat(prefix + "build.gradle")
	if err != nil {
		buildInfo, err = os.Stat(prefix + "build.gradle.kts")
		if err != nil {
			return
		}
	}

	if buildInfo.ModTime().After(lockInfo.ModTime()) {
		s := output.GetStyles()
		fmt.Fprintf(os.Stderr, "%s %s lockfile may be stale (build.gradle is newer). Run:\n",
			s.MutedText.Render(scPrefix), s.WarningText.Render("⚠"))
		fmt.Fprintf(os.Stderr, "  %s\n\n", s.Bold.Render("gradle dependencies --write-locks"))
	}
}
