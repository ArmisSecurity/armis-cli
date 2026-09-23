package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func TestPrintMCPDoctorPlain(t *testing.T) {
	report := &install.DoctorReport{Checks: []install.DoctorCheck{
		{Component: "scanner", Name: "python venv", Status: install.StatusOK, Detail: "/venv/python", Remediation: "not shown for ok"},
		{Component: "scanner", Name: "VS Code live handshake", Status: install.StatusFail, Detail: "exited",
			Remediation: "line one\nline two", Fix: install.FixReinstall},
		{Component: "vscode", Name: "Copilot", Status: install.StatusInfo, Detail: "manual"},
	}}

	var out bytes.Buffer
	printMCPDoctorPlain(&out, report, true, true)
	got := out.String()

	for _, want := range []string{
		"scanner:\n",
		"vscode:\n",
		"      → line one\n        line two\n",
		"1 passed, 0 warnings, 1 failed",
		"armis-cli mcp doctor --fix",
		"armis-cli mcp doctor --bundle",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "not shown for ok") {
		t.Error("remediation printed for a passing check")
	}
	// Names longer than the default column still line up.
	if !strings.Contains(got, "python venv            /venv/python") {
		t.Errorf("columns not aligned to the longest name:\n%s", got)
	}

	if strings.Contains(got, "--verbose") {
		t.Error("--verbose suggested in verbose output")
	}

	out.Reset()
	printMCPDoctorPlain(&out, report, false, true)
	if strings.Contains(out.String(), "--fix") {
		t.Error("--fix suggested after --fix already ran")
	}
}

func TestPrintMCPDoctorPlainCompact(t *testing.T) {
	healthy := []install.DoctorCheck{
		{Component: "scanner", Name: "plugin version", Status: install.StatusOK, Detail: "v1.2.2", Summary: "v1.2.2"},
		{Component: "scanner", Name: "python venv", Status: install.StatusOK, Detail: "/venv/python"},
		{Component: "scanner", Name: "tools", Status: install.StatusOK, Detail: "5 tools: a, b", Summary: "5 tools"},
		{Component: "scanner", Name: "Cursor", Editor: "Cursor", Status: install.StatusOK, Detail: "/cursor/mcp.json"},
		{Component: "scanner", Name: "Cursor launch", Editor: "Cursor", Status: install.StatusOK, Detail: "same launch command"},
		{Component: "scanner", Name: "Antigravity", Editor: "Antigravity", Status: install.StatusOK, Detail: "/ag/mcp_config.json"},
		{Component: "vscode", Name: "VS Code settings", Status: install.StatusOK, Detail: "MCP and Agent mode not disabled"},
		{Component: "vscode", Name: "Copilot", Status: install.StatusInfo, Detail: "can't be verified", Remediation: "1. Switch to Agent mode"},
	}

	t.Run("all passing", func(t *testing.T) {
		var out bytes.Buffer
		printMCPDoctorPlain(&out, &install.DoctorReport{Checks: healthy}, true, false)
		got := out.String()
		for _, want := range []string{
			"scanner  v1.2.2 · 5 tools\n",
			"editors  Antigravity, Cursor\n",
			"vscode   MCP and Agent mode not disabled\n",
			"7 passed, 0 warnings, 0 failed",
			"notes on Copilot: armis-cli mcp doctor --verbose",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
		for _, hidden := range []string{"/venv/python", "same launch command", "Agent mode\n", "--bundle"} {
			if strings.Contains(got, hidden) {
				t.Errorf("compact output shows %q:\n%s", hidden, got)
			}
		}
	})

	t.Run("problems expand", func(t *testing.T) {
		checks := append([]install.DoctorCheck(nil), healthy...)
		checks[1] = install.DoctorCheck{Component: "scanner", Name: "python venv", Status: install.StatusFail,
			Detail: "missing", Remediation: "Rebuild the venv"}
		checks[4] = install.DoctorCheck{Component: "scanner", Name: "Cursor launch", Editor: "Cursor", Status: install.StatusFail,
			Detail: "exited", Remediation: "Check Cursor"}
		var out bytes.Buffer
		printMCPDoctorPlain(&out, &install.DoctorReport{Checks: checks}, true, false)
		got := out.String()
		for _, want := range []string{
			"scanner  python venv: missing\n      → Rebuild the venv\n",
			"editors  Antigravity\n",
			"editors  Cursor launch: exited\n      → Check Cursor\n",
			"--bundle",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("output missing %q:\n%s", want, got)
			}
		}
		// A failing component shows its problems, not its summary.
		if strings.Contains(got, "v1.2.2 · 5 tools") {
			t.Errorf("summary shown for a failing component:\n%s", got)
		}
	})
}

func stubDoctorUpdate(t *testing.T) *[]bool {
	t.Helper()
	var calls []bool
	orig := mcpDoctorUpdate
	mcpDoctorUpdate = func(force, _ bool) error {
		calls = append(calls, force)
		return nil
	}
	t.Cleanup(func() { mcpDoctorUpdate = orig })
	return &calls
}

func TestApplyDoctorFixes(t *testing.T) {
	tests := []struct {
		name      string
		checks    []install.DoctorCheck
		wantFixed bool
		wantCalls []bool // force flag per update call
		wantOut   string
	}{
		{
			name:      "nothing installed",
			checks:    []install.DoctorCheck{{Component: install.ComponentInstall, Name: "manifest", Status: install.StatusFail}},
			wantOut:   "armis-cli install",
			wantCalls: nil,
		},
		{
			name:    "not fixable",
			checks:  []install.DoctorCheck{{Component: "vscode", Name: "settings", Status: install.StatusFail}},
			wantOut: "can be fixed automatically",
		},
		{
			name:      "reregister",
			checks:    []install.DoctorCheck{{Component: "scanner", Name: "Cursor", Status: install.StatusWarn, Fix: install.FixReregister}},
			wantFixed: true,
			wantCalls: []bool{false},
			wantOut:   "Re-registering",
		},
		{
			name: "reinstall subsumes reregister",
			checks: []install.DoctorCheck{
				{Component: "scanner", Name: "Cursor", Status: install.StatusWarn, Fix: install.FixReregister},
				{Component: "scanner", Name: "python venv", Status: install.StatusFail, Fix: install.FixReinstall},
			},
			wantFixed: true,
			wantCalls: []bool{true},
			wantOut:   "Reinstalling",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := stubDoctorUpdate(t)
			var out bytes.Buffer
			fixed, err := applyDoctorFixes(&out, &install.DoctorReport{Checks: tt.checks})
			if err != nil {
				t.Fatalf("applyDoctorFixes() error = %v", err)
			}
			if fixed != tt.wantFixed {
				t.Errorf("fixed = %v, want %v", fixed, tt.wantFixed)
			}
			if len(*calls) != len(tt.wantCalls) || (len(tt.wantCalls) > 0 && (*calls)[0] != tt.wantCalls[0]) {
				t.Errorf("update calls = %v, want %v", *calls, tt.wantCalls)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output = %q, want it to mention %q", out.String(), tt.wantOut)
			}
		})
	}
}

func TestApplyDoctorFixesReportsUpdateError(t *testing.T) {
	orig := mcpDoctorUpdate
	mcpDoctorUpdate = func(bool, bool) error { return errors.New("download failed") }
	t.Cleanup(func() { mcpDoctorUpdate = orig })

	report := &install.DoctorReport{Checks: []install.DoctorCheck{{Component: "scanner", Name: "x", Status: install.StatusFail, Fix: install.FixReinstall}}}
	if _, err := applyDoctorFixes(&bytes.Buffer{}, report); err == nil || !strings.Contains(err.Error(), "download failed") {
		t.Errorf("applyDoctorFixes() error = %v, want the update error", err)
	}
}

// TestRunMCPDoctorWritesBundle runs the command end to end with nothing
// installed: it must still fail (no manifest) but write the bundle to
// --bundle-path.
func TestRunMCPDoctorWritesBundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	bundle := filepath.Join(t.TempDir(), "support.zip")
	defer func(f, p string, h, fix, b bool) {
		mcpDoctorFormat, mcpDoctorBundlePath, mcpDoctorNoHandshake, mcpDoctorFix, mcpDoctorBundle = f, p, h, fix, b
	}(mcpDoctorFormat, mcpDoctorBundlePath, mcpDoctorNoHandshake, mcpDoctorFix, mcpDoctorBundle)
	mcpDoctorFormat, mcpDoctorBundlePath, mcpDoctorNoHandshake, mcpDoctorFix, mcpDoctorBundle = agentFormatPlain, bundle, true, false, false

	var stderr bytes.Buffer
	mcpDoctorCmd.SetErr(&stderr)
	t.Cleanup(func() { mcpDoctorCmd.SetErr(nil) })

	if err := runMCPDoctor(mcpDoctorCmd, nil); err == nil {
		t.Error("runMCPDoctor() error = nil, want failure when nothing is installed")
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle not written to --bundle-path: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Support bundle written to "+bundle) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestMCPDoctorFlags(t *testing.T) {
	for name, def := range map[string]string{"fix": "false", "bundle": "false", "bundle-path": "", "no-handshake": "false", "verbose": "false"} {
		f := mcpDoctorCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("mcp doctor is missing --%s", name)
			continue
		}
		if f.DefValue != def {
			t.Errorf("--%s default = %q, want %q", name, f.DefValue, def)
		}
	}
}
