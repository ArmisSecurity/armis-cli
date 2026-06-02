package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/spf13/cobra"
)

// newResolvePolicyCmd builds a throwaway command with the same flags resolvePolicy
// inspects, bound to the package-level vars. The bool return reports whether
// --fail-open was marked as explicitly set.
func newResolvePolicyCmd(failOpenSet bool) *cobra.Command {
	cmd := &cobra.Command{Use: "check"}
	cmd.Flags().StringVar(&scMinAge, "min-age", "72h", "")
	cmd.Flags().StringSliceVar(&scExclude, "exclude", nil, "")
	cmd.Flags().BoolVar(&scFailOpen, "fail-open", false, "")
	if failOpenSet {
		_ = cmd.Flags().Set("fail-open", "true")
	}
	return cmd
}

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	path := filepath.Join(dir, supplychain.ConfigFileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestResolvePolicy_FailOpenFromConfig(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "version: 1\nfail-open: true\n")

	// Reset package var to its default so a prior test can't leak state in.
	scFailOpen = false
	cmd := newResolvePolicyCmd(false) // user did NOT pass --fail-open

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if !policy.FailOpen {
		t.Error("config fail-open: true should propagate to policy.FailOpen")
	}
	// The package var must remain untouched — the old code mutated it as a side
	// effect, which leaked across invocations within the same process.
	if scFailOpen {
		t.Error("resolvePolicy must not mutate the package-level scFailOpen var")
	}
}

func TestResolvePolicy_FlagOverridesConfigFalse(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "version: 1\nfail-open: false\n")

	scFailOpen = true                // simulate --fail-open=true on the CLI
	cmd := newResolvePolicyCmd(true) // explicitly set

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if !policy.FailOpen {
		t.Error("explicit --fail-open should override config fail-open: false")
	}
}

func TestResolvePolicy_DefaultNoFailOpen(t *testing.T) {
	dir := t.TempDir() // no config file present

	scFailOpen = false
	cmd := newResolvePolicyCmd(false)

	policy, err := resolvePolicy(cmd, dir)
	if err != nil {
		t.Fatalf("resolvePolicy: %v", err)
	}
	if policy.FailOpen {
		t.Error("policy.FailOpen should default to false with no config and no flag")
	}
}
