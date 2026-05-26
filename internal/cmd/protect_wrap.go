package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/protect"
	"github.com/spf13/cobra"
)

const (
	envProtectActive = "ARMIS_PROTECT_ACTIVE"
	envProtectOff    = "ARMIS_PROTECT"
	envProtectSkip   = "ARMIS_PROTECT_SKIP"
)

var protectWrapCmd = &cobra.Command{
	Use:                "wrap <pm> [args...]",
	Short:              "Run package manager with age enforcement proxy (internal)",
	Hidden:             true,
	Args:               cobra.MinimumNArgs(1),
	RunE:               runProtectWrap,
	DisableFlagParsing: true,
}

func init() {
	protectCmd.AddCommand(protectWrapCmd)
}

func runProtectWrap(_ *cobra.Command, args []string) error {
	pm := args[0]
	pmArgs := args[1:]

	if os.Getenv(envProtectActive) == "1" {
		return execPM(pm, pmArgs, nil)
	}

	if strings.EqualFold(os.Getenv(envProtectOff), "off") {
		fmt.Fprintf(os.Stderr, "[armis-cli] protect disabled via %s=off\n", envProtectOff)
		return execPM(pm, pmArgs, nil)
	}

	skipPkgs := parseSkipPackages(os.Getenv(envProtectSkip))

	policy := protect.DefaultPolicy()

	cfg := protect.ProxyConfig{
		Policy:       policy,
		SkipPackages: skipPkgs,
	}

	proxy, err := protect.NewProxy(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis-cli] protect: proxy setup failed, falling through: %v\n", err)
		return execPM(pm, pmArgs, nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	addr, err := proxy.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis-cli] protect: proxy start failed, falling through: %v\n", err)
		return execPM(pm, pmArgs, nil)
	}
	defer proxy.Close() //nolint:errcheck

	registryURL := fmt.Sprintf("http://%s/", addr)
	extraEnv := []string{
		fmt.Sprintf("npm_config_registry=%s", registryURL),
		fmt.Sprintf("%s=1", envProtectActive),
	}

	exitErr := execPM(pm, pmArgs, extraEnv)

	printBlockSummary(proxy.Blocked(), proxy.Checked(), policy)

	return exitErr
}

func execPM(pm string, args []string, extraEnv []string) error {
	pmPath, err := exec.LookPath(pm)
	if err != nil {
		return fmt.Errorf("finding %s: %w", pm, err)
	}

	cmd := exec.Command(pmPath, args...) //nolint:gosec // user-invoked PM with their own args
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func printBlockSummary(blocked []protect.BlockedPackage, checked int, policy protect.Policy) {
	if len(blocked) == 0 {
		if checked > 0 {
			fmt.Fprintf(os.Stderr, "[armis-cli] protect: %d packages checked, all pass policy (%s minimum age)\n", checked, policy.MinReleaseAge)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "\n[armis-cli] ⚠ BLOCKED %d version(s) younger than %s:\n", len(blocked), policy.MinReleaseAge)
	for _, b := range blocked {
		age := formatDurationShort(b.Age)
		fmt.Fprintf(os.Stderr, "  • %s@%s (published %s ago)\n", b.Name, b.Version, age)
	}
	fmt.Fprintf(os.Stderr, "\n  Bypass: %s=%s %s install\n", envProtectSkip, blockedNames(blocked), pm(blocked))
	fmt.Fprintf(os.Stderr, "  Disable: %s=off %s install\n\n", envProtectOff, pm(blocked))
}

func formatDurationShort(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	if hours < 24 {
		return fmt.Sprintf("%dh", hours)
	}
	days := hours / 24
	remainingHours := hours % 24
	if remainingHours == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, remainingHours)
}

func blockedNames(blocked []protect.BlockedPackage) string {
	seen := make(map[string]bool)
	var names []string
	for _, b := range blocked {
		if !seen[b.Name] {
			seen[b.Name] = true
			names = append(names, b.Name)
		}
	}
	return strings.Join(names, ",")
}

func pm(_ []protect.BlockedPackage) string {
	return "npm"
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
