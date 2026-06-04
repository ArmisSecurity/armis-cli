package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain/check"
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
		return exitWithCode(execPM(pmName, pmArgs, nil))
	}

	if strings.EqualFold(os.Getenv(envSCOff), "off") {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain disabled via %s=off\n", envSCOff)
		return exitWithCode(execPM(pmName, pmArgs, nil))
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

	cfg := supplychain.ProxyConfig{
		Policy:       policy,
		SkipPackages: parseSkipPackages(os.Getenv(envSCSkip)),
	}

	proxy, err := supplychain.NewProxy(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: proxy setup failed, falling through: %v\n", err)
		return exitWithCode(execPM(pmName, pmArgs, nil))
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()

	addr, err := proxy.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: proxy start failed, falling through: %v\n", err)
		return exitWithCode(execPM(pmName, pmArgs, nil))
	}
	defer proxy.Close() //nolint:errcheck

	registryURL := fmt.Sprintf("http://%s/", addr)
	// Canonicalize so a versioned pip variant (pip3.12) still gets PIP_INDEX_URL
	// rather than falling through to the npm registry env.
	extraEnv := registryEnvForPM(canonicalPM(pmName), registryURL)
	extraEnv = append(extraEnv, fmt.Sprintf("%s=1", envSCActive))

	exitCode, err := execPM(pmName, pmArgs, extraEnv)

	printBlockSummary(proxy.Blocked(), proxy.Allowed(), proxy.Checked(), policy, pmName)

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

func printBlockSummary(blocked []supplychain.BlockedPackage, allowed []supplychain.InstalledPackage, checked int, policy supplychain.Policy, pmName string) {
	s := output.GetStyles()

	if len(blocked) == 0 {
		if checked > 0 {
			fmt.Fprintf(os.Stderr, "%s %s %s %s\n",
				s.MutedText.Render(scPrefix),
				s.SuccessText.Render(output.IconSuccess),
				s.SuccessText.Render(fmt.Sprintf("supply-chain: %d packages checked, all pass", checked)),
				s.MutedText.Render(fmt.Sprintf("(%s minimum age)", formatDurationShort(policy.MinReleaseAge))))
		}
		return
	}

	allowedVersions := make(map[string]string, len(allowed))
	for _, pkg := range allowed {
		allowedVersions[pkg.Name] = pkg.Version
	}

	relevant := filterRelevantBlocked(blocked)

	sort.Slice(relevant, func(i, j int) bool {
		return relevant[i].Age < relevant[j].Age
	})

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		s.MutedText.Render(scPrefix),
		s.WarningText.Render(fmt.Sprintf("supply-chain: filtered %d version(s) younger than %s", len(relevant), formatDurationShort(policy.MinReleaseAge))))

	blockedPkgNames := blockedNamesUnique(relevant)
	resolvedCount := 0
	for _, name := range blockedPkgNames {
		if _, ok := allowedVersions[name]; ok {
			resolvedCount++
		}
	}
	if resolvedCount > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			s.SuccessText.Render(output.IconSuccess),
			s.SuccessText.Render(fmt.Sprintf("resolved %d package(s) to older safe versions", resolvedCount)))
	}

	displayCount := len(relevant)
	if displayCount > maxBlockedDisplay {
		displayCount = maxBlockedDisplay
	}

	fmt.Fprintf(os.Stderr, "  %s\n", s.MutedText.Render("Filtered out:"))
	for _, b := range relevant[:displayCount] {
		age := formatDurationShort(b.Age)
		sev := supplychain.ClassifySeverity(b.Age, policy.MinReleaseAge)
		dot := severityDot(s, sev)
		fmt.Fprintf(os.Stderr, "    %s %s %s\n",
			dot,
			s.Bold.Render(fmt.Sprintf("%s@%s", b.Name, b.Version)),
			s.MutedText.Render(fmt.Sprintf("(published %s ago)", age)))
	}
	if remaining := len(relevant) - displayCount; remaining > 0 {
		fmt.Fprintf(os.Stderr, "    %s\n",
			s.MutedText.Render(fmt.Sprintf("… and %d more", remaining)))
	}

	fmt.Fprintf(os.Stderr, "\n  %s\n", s.MutedText.Render(strings.Repeat("─", scSepLen)))
	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		s.MutedText.Render("Disable:"),
		s.Bold.Render(fmt.Sprintf("%s=off %s install", envSCOff, pmName)))
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

func blockedNamesUnique(blocked []supplychain.BlockedPackage) []string {
	seen := make(map[string]bool)
	var names []string
	for _, b := range blocked {
		if !seen[b.Name] {
			seen[b.Name] = true
			names = append(names, b.Name)
		}
	}
	return names
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
		return exitWithCode(execPM(pmName, pmArgs, nil))
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
			return exitWithCode(execPM(pmName, pmArgs, nil))
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
		return exitWithCode(execPM(pmName, pmArgs, nil))
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
		s.WarningText.Render(fmt.Sprintf("supply-chain: BLOCKED — %d package(s) younger than %s", len(violations), formatDurationShort(policy.MinReleaseAge))))

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
			s.MutedText.Render(fmt.Sprintf("(published %s ago)", age)))
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

func pmToEcosystem(pm string) supplychain.Ecosystem {
	switch pm {
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
