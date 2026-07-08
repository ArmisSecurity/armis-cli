package cmd

import (
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/cmd/cmdutil"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/output"
)

// TestSupplyChainUnknownSubcommand guards the parent command's RunE: an unknown
// subcommand must error (non-zero exit) instead of silently printing help and
// exiting 0, which would let a typo like `supply-chain chekc` "pass" in CI.
func TestSupplyChainUnknownSubcommand(t *testing.T) {
	t.Run("unknown subcommand returns an error", func(t *testing.T) {
		err := supplyChainCmd.RunE(supplyChainCmd, []string{"chekc"})
		if err == nil {
			t.Fatal("expected an error for an unknown subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "unknown subcommand") {
			t.Errorf("error should mention the unknown subcommand, got: %v", err)
		}
	})

	t.Run("close typo offers a suggestion", func(t *testing.T) {
		err := supplyChainCmd.RunE(supplyChainCmd, []string{"chekc"})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "Did you mean") || !strings.Contains(err.Error(), "check") {
			t.Errorf("expected a 'Did you mean ... check' suggestion, got: %v", err)
		}
	})

	t.Run("no args falls back to help without error", func(t *testing.T) {
		if err := supplyChainCmd.RunE(supplyChainCmd, []string{}); err != nil {
			t.Errorf("no-arg invocation should print help and return nil, got: %v", err)
		}
	})
}

// TestSupplyChainCheckFailOnCaseInsensitive is the regression test for the
// CI-gate bypass: `supply-chain check` routes --fail-on through
// cmdutil.GetFailOn, which uppercases and validates it. A lowercase "medium"
// must therefore trip the gate on a MEDIUM finding (ShouldFail matches
// severities exactly), and an invalid value must be rejected rather than
// silently ignored. It feeds scFailOn (the check-local flag value that
// runSupplyChainCheck actually reads) through the same call the command makes,
// end-to-end into output.ShouldFail. Using scFailOn here — not the root failOn
// global — keeps the test exercising the variable the command depends on.
func TestSupplyChainCheckFailOnCaseInsensitive(t *testing.T) {
	medium := &model.ScanResult{
		Findings: []model.Finding{{Severity: model.SeverityMedium}},
	}

	// Restore the check-local default so this test can't leak state into others.
	orig := scFailOn
	t.Cleanup(func() { scFailOn = orig })

	t.Run("lowercase fail-on still fails the gate", func(t *testing.T) {
		scFailOn = []string{"medium"}
		normalized, err := cmdutil.GetFailOn(scFailOn)
		if err != nil {
			t.Fatalf("GetFailOn rejected a valid lowercase severity: %v", err)
		}
		if !output.ShouldFail(medium, normalized) {
			t.Error("lowercase --fail-on medium should fail on a MEDIUM finding after normalization")
		}
	})

	t.Run("invalid fail-on is rejected", func(t *testing.T) {
		scFailOn = []string{"banana"}
		if _, err := cmdutil.GetFailOn(scFailOn); err == nil {
			t.Error("GetFailOn should reject an invalid severity, not silently ignore it")
		}
	})
}
