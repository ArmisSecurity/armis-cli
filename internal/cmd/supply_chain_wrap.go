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
	"github.com/spf13/cobra"
)

const (
	envSCActive = "ARMIS_SUPPLY_CHAIN_ACTIVE"
	envSCOff    = "ARMIS_SUPPLY_CHAIN"
	envSCSkip   = "ARMIS_SUPPLY_CHAIN_SKIP"
	scPrefix    = "[armis]"
	scSepLen    = 45
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

func runSupplyChainWrap(cmd *cobra.Command, args []string) error {
	pmName := args[0]
	pmArgs := args[1:]

	if os.Getenv(envSCActive) == "1" {
		return exitWithCode(execPM(pmName, pmArgs, nil))
	}

	if strings.EqualFold(os.Getenv(envSCOff), "off") {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain disabled via %s=off\n", envSCOff)
		return exitWithCode(execPM(pmName, pmArgs, nil))
	}

	skipPkgs := parseSkipPackages(os.Getenv(envSCSkip))

	policy := resolveWrapPolicy()

	cfg := supplychain.ProxyConfig{
		Policy:       policy,
		SkipPackages: skipPkgs,
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
	extraEnv := registryEnvForPM(pmName, registryURL)
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
	pmPath, err := exec.LookPath(pm)
	if err != nil {
		return 1, fmt.Errorf("finding %s: %w", pm, err)
	}

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

	relevant := filterRelevantBlocked(blocked, allowedVersions)

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
	if len(blockedPkgNames) <= 3 {
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			s.MutedText.Render("Bypass:"),
			s.Bold.Render(fmt.Sprintf("%s=%s %s install", envSCSkip, blockedNames(relevant), pmName)))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n\n",
		s.MutedText.Render("Disable:"),
		s.Bold.Render(fmt.Sprintf("%s=off %s install", envSCOff, pmName)))
}

func filterRelevantBlocked(blocked []supplychain.BlockedPackage, _ map[string]string) []supplychain.BlockedPackage {
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

func blockedNames(blocked []supplychain.BlockedPackage) string {
	return strings.Join(blockedNamesUnique(blocked), ",")
}

func registryEnvForPM(pm, registryURL string) []string {
	switch pm {
	case "bun":
		return []string{
			fmt.Sprintf("npm_config_registry=%s", registryURL),
			fmt.Sprintf("BUN_CONFIG_REGISTRY=%s", registryURL),
		}
	default:
		return []string{
			fmt.Sprintf("npm_config_registry=%s", registryURL),
		}
	}
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

func parseSkipPackages(env string) []string {
	if env == "" {
		return nil
	}
	parts := strings.Split(env, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
