package cmd

import (
	"strings"
	"testing"

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
// CI-gate bypass: `supply-chain check` routes --fail-on through getFailOn(),
// which uppercases and validates it. A lowercase "medium" must therefore trip
// the gate on a MEDIUM finding (ShouldFail matches severities exactly), and an
// invalid value must be rejected rather than silently ignored.
func TestSupplyChainCheckFailOnCaseInsensitive(t *testing.T) {
	medium := &model.ScanResult{
		Findings: []model.Finding{{Severity: model.SeverityMedium}},
	}

	t.Run("lowercase fail-on still fails the gate", func(t *testing.T) {
		failOn = []string{"medium"}
		normalized, err := getFailOn()
		if err != nil {
			t.Fatalf("getFailOn rejected a valid lowercase severity: %v", err)
		}
		if !output.ShouldFail(medium, normalized) {
			t.Error("lowercase --fail-on medium should fail on a MEDIUM finding after normalization")
		}
	})

	t.Run("invalid fail-on is rejected", func(t *testing.T) {
		failOn = []string{"banana"}
		if _, err := getFailOn(); err == nil {
			t.Error("getFailOn should reject an invalid severity, not silently ignore it")
		}
	})

	// Reset the shared package global so this test can't leak state into others.
	failOn = []string{"CRITICAL"}
}
