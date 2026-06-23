package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

func TestBuildComplianceReport_ShapeAndContent(t *testing.T) {
	in := reportInput{
		Policy: supplychain.Policy{
			MinReleaseAge:    72 * time.Hour,
			Exclusions:       []string{"@myorg/*"},
			FailOpen:         false,
			TransitivePolicy: supplychain.TransitivePolicyWarn,
		},
		Mode:      "proxy",
		Ecosystem: "npm",
		Checked:   42,
		Blocked: []supplychain.BlockedPackage{
			{Name: "axios", Version: "1.17.0", DisplayVersion: "1.17.0", Age: 24 * time.Hour},
			// Duplicate of the same (name, version) must collapse to one row.
			{Name: "axios", Version: "1.17.0", DisplayVersion: "1.17.0", Age: 24 * time.Hour},
		},
		Resolved: []supplychain.InstalledPackage{
			{Name: "axios", Version: "1.16.1", Age: 240 * time.Hour},
		},
		Warned: []supplychain.WarnedPackage{
			{Name: "debug", Version: "4.4.0", Age: time.Hour},
		},
		Conflicts: []supplychain.ConstraintConflict{
			{Dep: "scheduler", Range: "^0.24.0", ByPkg: "react-dom"},
		},
		InstallStatus: "failed",
	}

	rep := buildComplianceReport(in)

	if rep.Mode != "proxy" || rep.Ecosystem != "npm" || rep.Checked != 42 {
		t.Errorf("header fields wrong: %+v", rep)
	}
	if rep.Policy.MinAge != "72h0m0s" {
		t.Errorf("MinAge = %q", rep.Policy.MinAge)
	}
	if rep.Policy.TransitivePolicy != "warn" {
		t.Errorf("TransitivePolicy = %q, want warn", rep.Policy.TransitivePolicy)
	}
	if len(rep.Blocked) != 1 {
		t.Errorf("duplicate blocked rows must collapse; got %d: %#v", len(rep.Blocked), rep.Blocked)
	}
	if len(rep.WarnedThrough) != 1 || rep.WarnedThrough[0].Name != "debug" {
		t.Errorf("warned-through not recorded: %#v", rep.WarnedThrough)
	}
	if len(rep.Conflicts) != 1 || rep.Conflicts[0].Dep != "scheduler" {
		t.Errorf("conflict not recorded: %#v", rep.Conflicts)
	}
	if rep.InstallStatus != "failed" {
		t.Errorf("InstallStatus = %q", rep.InstallStatus)
	}

	// Must marshal to valid JSON with array (never null) slices for jq gating.
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	for _, key := range []string{"blocked", "resolved", "warned_through", "conflicts"} {
		if _, ok := generic[key].([]any); !ok {
			t.Errorf("%q must be a JSON array (never null); got %T", key, generic[key])
		}
	}
}

func TestBuildComplianceReport_DefaultTransitivePolicyNormalized(t *testing.T) {
	// The zero-value transitive policy ("") must render as the secure "block"
	// default, never an empty string.
	rep := buildComplianceReport(reportInput{
		Policy: supplychain.Policy{MinReleaseAge: 72 * time.Hour},
		Mode:   "proxy",
	})
	if rep.Policy.TransitivePolicy != "block" {
		t.Errorf("empty transitive policy must normalize to block; got %q", rep.Policy.TransitivePolicy)
	}
	// Exclusions must be an empty array, not null.
	if rep.Policy.Exclusions == nil {
		t.Error("exclusions must be a non-nil empty slice")
	}
}

func TestWriteComplianceReport_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	rep := buildComplianceReport(reportInput{
		Policy:        supplychain.Policy{MinReleaseAge: 72 * time.Hour},
		Mode:          "proxy",
		Ecosystem:     "npm",
		InstallStatus: "ok",
	})
	writeComplianceReport(path, rep)

	data, err := os.ReadFile(path) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	var parsed complianceReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("written report is not valid JSON: %v", err)
	}
	if parsed.InstallStatus != "ok" {
		t.Errorf("round-trip InstallStatus = %q", parsed.InstallStatus)
	}
}
