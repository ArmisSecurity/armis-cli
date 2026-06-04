package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	pmPNPM   = "pnpm"
	pmBun    = "bun"
	pmYarn   = "yarn"
	pmPip    = "pip"
	pmUV     = "uv"
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
	pmNPM: true, pmPNPM: true, pmBun: true, pmYarn: true,
	pmPip: true, pmUV: true, pmPoetry: true, pmPipenv: true, pmPDM: true,
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
		return fmt.Errorf("unsupported package manager: %s (allowed: npm, pnpm, bun, yarn, pip, uv, poetry, pipenv, pdm, mvn, gradle)", pmName)
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

	// poetry, pipenv, and pdm resolve dependencies through their own lockfiles
	// rather than honoring an npm-style registry override, so they cannot be
	// enforced via the transparent proxy. Instead we audit the lockfile and
	// hard-block the build before it runs if any package is too young.
	if requiresPreInstallBlock(canonical) {
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

	// pip and uv resolve from the PyPI Simple API, a different protocol from the
	// npm registry, so the proxy must run in PyPI mode (PEP 691/700 JSON file
	// filtering). All other proxied PMs (npm/pnpm/bun/yarn) speak the npm registry.
	mode := supplychain.ModeNPM
	switch canonicalPM(pmName) {
	case pmPip, pmUV:
		mode = supplychain.ModePyPI
	}

	cfg := supplychain.ProxyConfig{
		Policy:       policy,
		Mode:         mode,
		SkipPackages: parseSkipPackages(os.Getenv(envSCSkip)),
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

	// installOK reflects what the package manager actually did, not what the proxy
	// offered: proxy.Allowed() only records the version "latest" was repointed to,
	// so without the exit code the summary would claim a package was "installed"
	// even when the PM rejected it (e.g. a pin like ^1.17.0 that only the filtered
	// version satisfies). Report the observed outcome, not the proxy's intent.
	installOK := err == nil && exitCode == 0
	printBlockSummary(proxy.Blocked(), proxy.Allowed(), proxy.Checked(), policy, pmName, installOK)

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
		// environment. IsPipVariant enforces a strict pattern (letters, digits, a
		// single dotted numeric suffix), so the value reaching exec.LookPath is
		// still a bounded, shell-metacharacter-free name rather than arbitrary
		// user input — preserving the CWE-426 guarantee the literal cases provide.
		if supplychain.IsPipVariant(pm) {
			pmName = pm
			break
		}
		return 1, fmt.Errorf("unsupported package manager: %s (allowed: npm, pnpm, bun, yarn, pip, uv, poetry, pipenv, pdm, mvn, gradle)", pm)
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
	OldVersion string         // youngest blocked version (what the PM wanted)
	OldAge     time.Duration  // age of that version at install time
	Severity   model.Severity // severity classification of that age
	NewVersion string         // resolved fallback version, "" if none was available
}

func printBlockSummary(blocked []supplychain.BlockedPackage, allowed []supplychain.InstalledPackage, checked int, policy supplychain.Policy, pmName string, installOK bool) {
	s := output.GetStyles()

	if len(blocked) == 0 {
		if checked > 0 {
			fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
				s.MutedText.Render(scPrefix),
				s.SuccessText.Render(output.IconSuccess),
				s.SuccessText.Render(fmt.Sprintf("supply-chain: %s checked, all pass", countNoun(checked, "package"))),
				s.MutedText.Render(fmt.Sprintf("(%s minimum age)", formatDurationShort(policy.MinReleaseAge))))
		}
		return
	}

	allowedVersions := make(map[string]string, len(allowed))
	for _, pkg := range allowed {
		allowedVersions[pkg.Name] = pkg.Version
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

	// Pad the name, version, and age columns to a common width so the "→ installed"
	// outcomes line up vertically across rows. Widths are computed over the rows
	// actually shown (not the full result set) so a truncated list still aligns.
	var cols colWidths
	for _, r := range results[:displayCount] {
		if n := len(r.Name); n > cols.name {
			cols.name = n
		}
		if n := len(r.OldVersion); n > cols.version {
			cols.version = n
		}
		if n := len(ageToken(r.OldAge)); n > cols.age {
			cols.age = n
		}
	}
	for _, r := range results[:displayCount] {
		printPkgFilterLine(s, r, !allResolved, installOK, cols)
	}
	if remaining := len(results) - displayCount; remaining > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n",
			s.MutedText.Render(fmt.Sprintf("… and %d more", remaining)))
	}

	// When the package manager did not complete, explain the likely link to the
	// filter without asserting it: the failure could be unrelated (a typo, a
	// network error), but a pin that only the filtered version satisfies is the
	// common cause, so point at the actionable fix.
	if !installOK {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n",
			s.MutedText.Render("Note:"),
			s.MutedText.Render("the install did not complete. If a dependency pins a version newer than the policy window, relax the constraint or exclude the package."))
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

	// Footer. A long list earns the full divider and copy-paste disable command;
	// the common short case gets a single terse hint instead of heavy chrome.
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

// colWidths holds the maximum plain-text width of each aligned column. Padding
// is computed on the unstyled strings: len() on a lipgloss-rendered value counts
// invisible ANSI escape bytes, so columns must be padded before .Render().
type colWidths struct {
	name    int
	version int
	age     int
}

// ageToken formats a blocked version's age as it appears on the line, e.g.
// "(1 day old)". Centralized so the column-width measurement and the rendered
// output cannot drift apart.
func ageToken(age time.Duration) string {
	return fmt.Sprintf("(%s old)", formatDurationShort(age))
}

// rightPad appends spaces so s occupies at least width columns. It pads the
// plain string before styling, keeping alignment correct with colors on or off.
func rightPad(s string, width int) string {
	if pad := width - len(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// printPkgFilterLine renders one package's filter outcome on a single line:
// glyph, name, the blocked version and its age, an arrow, and the resolved
// version (or an inline warning when none existed). The leading glyph depends on
// context: when every package resolved (mixed == false) the header already
// signals success, so the line shows the severity dot to convey how fresh the
// blocked version was; in the mixed case the header is neutral, so a per-line
// ✓/⚠ carries the resolved-vs-unresolved tone. The resolved-version wording is
// "installed" only when the PM completed (installOK); otherwise it reads
// "available" — the safe version exists, but we cannot claim it was installed.
// cols pads each column so the arrows and outcomes line up across rows.
func printPkgFilterLine(s *output.Styles, r pkgFilterResult, mixed, installOK bool, cols colWidths) {
	resolvedWord := "installed"
	if !installOK {
		resolvedWord = "available"
	}

	var glyph, outcome string
	switch {
	case r.NewVersion == "":
		glyph = s.WarningText.Render("⚠")
		outcome = s.WarningText.Render("no older safe version (install may fail)")
	case mixed:
		glyph = s.SuccessText.Render(output.IconSuccess)
		outcome = fmt.Sprintf("%s %s", s.SuccessText.Render(r.NewVersion), s.MutedText.Render(resolvedWord))
	default:
		glyph = severityDot(s, r.Severity)
		outcome = fmt.Sprintf("%s %s", s.SuccessText.Render(r.NewVersion), s.MutedText.Render(resolvedWord))
	}

	fmt.Fprintf(os.Stderr, "  %s %s %s %s  %s  %s\n",
		glyph,
		s.Bold.Render(rightPad(r.Name, cols.name)),
		s.MutedText.Render(rightPad(r.OldVersion, cols.version)),
		s.MutedText.Render(rightPad(ageToken(r.OldAge), cols.age)),
		s.MutedText.Render("→"),
		outcome)
}

// groupBlockedByPackage collapses blocked versions into one result per package.
// For each package it keeps the youngest blocked version — the one the PM would
// have installed as "latest" — and pairs it with the resolved fallback from
// allowedVersions. Results are sorted youngest-first (ties broken by name) so
// the freshest, riskiest package leads the list and output is deterministic.
func groupBlockedByPackage(blocked []supplychain.BlockedPackage, allowedVersions map[string]string, threshold time.Duration) []pkgFilterResult {
	byName := make(map[string]pkgFilterResult, len(blocked))
	for _, b := range blocked {
		if existing, ok := byName[b.Name]; ok && existing.OldAge <= b.Age {
			continue // already holding a younger (or equally young) version
		}
		byName[b.Name] = pkgFilterResult{
			Name:       b.Name,
			OldVersion: b.Version,
			OldAge:     b.Age,
			Severity:   supplychain.ClassifySeverity(b.Age, threshold),
			NewVersion: allowedVersions[b.Name],
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
		if isPrerelease(b.Version) {
			continue
		}
		relevant = append(relevant, b)
	}
	if len(relevant) == 0 {
		return blocked
	}
	return relevant
}

func isPrerelease(version string) bool {
	parts := strings.SplitN(version, "-", 2)
	return len(parts) == 2 && parts[0] != ""
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
		}
	case pmUV:
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
// current directory) scopes enforcement to exclude this package manager's
// ecosystem. It loads the config best-effort: any load error or absent config
// means "enforce" (fail safe), matching resolveWrapPolicy's posture. Pass the
// canonical PM name so versioned pip variants resolve correctly.
func wrapEcosystemEnforced(canonicalPMName string) bool {
	eco := pmToEcosystem(canonicalPMName)
	if eco == "" {
		return true
	}
	dir := supplychain.FindConfigDir(".")
	if dir == "" {
		return true
	}
	cfg, err := supplychain.LoadConfig(dir)
	if err != nil || cfg == nil {
		return true
	}
	return cfg.EnforcesEcosystem(eco)
}

// requiresPreInstallBlock reports whether a package manager must be enforced via
// a pre-install lockfile audit rather than the transparent registry proxy.
// poetry, pipenv, and pdm resolve from their own lockfiles and do not honor an
// npm-style registry override, so the proxy cannot filter young versions for
// them; instead the build is blocked up front if the lockfile contains a
// too-young package.
func requiresPreInstallBlock(pm string) bool {
	switch pm {
	case pmPoetry, pmPipenv, pmPDM, pmMaven, pmGradle:
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
				s.SuccessText.Render(fmt.Sprintf("supply-chain: %d packages checked, all pass", result.Checked)),
				s.MutedText.Render(fmt.Sprintf("(%s minimum age)", formatDurationShort(policy.MinReleaseAge))))
		}
		return exitWithCode(execPMFunc(pmName, pmArgs, nil))
	}

	printPreInstallBlockSummary(violations, policy, pmName)
	os.Exit(1)
	return nil
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

// pmToEcosystem maps a (canonical) package-manager name to its ecosystem. It
// covers every supported PM — both the pre-install ones (used by
// runPreInstallBlock to locate the lockfile) and the proxied ones (used by the
// ecosystems-config scoping gate). Pass the canonical name (canonicalPM) so a
// versioned pip variant resolves to EcosystemPip.
func pmToEcosystem(pm string) supplychain.Ecosystem {
	switch pm {
	case pmNPM:
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
