package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
)

// captureStderr swaps os.Stderr for a pipe, runs fn, and returns everything fn
// wrote to stderr. A goroutine drains the pipe so output larger than the pipe
// buffer cannot deadlock. The original stderr is always restored.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// forceNoColor pins styles to the plain (no-ANSI) set so output assertions can
// match literal substrings without escape codes. It restores nothing because
// every test that renders output calls it first.
func forceNoColor(t *testing.T) {
	t.Helper()
	cli.InitColors(cli.ColorModeNever)
	output.SyncStylesWithColorMode()
}

// testPolicy returns a policy with the default 3-day window for output tests.
func testPolicy() supplychain.Policy {
	return supplychain.Policy{MinReleaseAge: 72 * time.Hour}
}

func TestPrintBlockSummary_AllPass(t *testing.T) {
	// Tier A: nothing filtered but packages were checked → single green line that
	// uses countNoun (no "(s)").
	forceNoColor(t)
	out := captureStderr(t, func() {
		printBlockSummary(nil, nil, 12, testPolicy(), pmNPM, true)
	})
	if !strings.Contains(out, "12 packages checked, all pass") {
		t.Errorf("missing all-pass line; got:\n%s", out)
	}
	if strings.Contains(out, "package(s)") {
		t.Errorf("output still uses package(s); got:\n%s", out)
	}
}

func TestPrintBlockSummary_AllPassZeroChecked(t *testing.T) {
	// Nothing checked → nothing printed (e.g. a fully cached install).
	forceNoColor(t)
	out := captureStderr(t, func() {
		printBlockSummary(nil, nil, 0, testPolicy(), pmNPM, true)
	})
	if out != "" {
		t.Errorf("expected no output when nothing was checked; got:\n%s", out)
	}
}

func TestPrintBlockSummary_SingleResolved(t *testing.T) {
	// Tier B: one package filtered and resolved → success header, old→new line,
	// terse Disable hint, and NO divider/heavy chrome.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "axios", Version: "1.17.0", Age: 24 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, true)
	})

	wantSubstrings := []string{
		"filtered 1 too-new release → installed safe version (3-day policy)",
		"axios",
		"1.17.0",
		"(1 day old)",
		"→",
		"1.16.1 installed",
		"Disable: ARMIS_SUPPLY_CHAIN=off",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q; got:\n%s", want, out)
		}
	}
	// Short list must not draw the divider or the full copy-paste incantation.
	if strings.Contains(out, strings.Repeat("─", scSepLen)) {
		t.Errorf("short list should not draw a divider; got:\n%s", out)
	}
	if strings.Contains(out, "ARMIS_SUPPLY_CHAIN=off npm install") {
		t.Errorf("short list should use the terse disable hint; got:\n%s", out)
	}
}

func TestPrintBlockSummary_MixedUnresolved(t *testing.T) {
	// Tier C: one package resolved, one with no safe fallback → neutral header
	// (no "installed safe"), per-line warning for the unresolved package.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{
		{Name: "axios", Version: "1.17.0", Age: 24 * time.Hour},
		{Name: "leftpad", Version: "2.0.0", Age: 2 * time.Hour},
	}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 7, testPolicy(), pmNPM, true)
	})

	if !strings.Contains(out, "filtered 2 too-new releases (3-day policy)") {
		t.Errorf("missing neutral mixed header; got:\n%s", out)
	}
	if strings.Contains(out, "installed safe") {
		t.Errorf("mixed header must not claim success; got:\n%s", out)
	}
	if !strings.Contains(out, "no older safe version (install may fail)") {
		t.Errorf("missing unresolved warning; got:\n%s", out)
	}
	if !strings.Contains(out, "1.16.1 installed") {
		t.Errorf("missing resolved line for axios; got:\n%s", out)
	}
}

func TestPrintBlockSummary_InstallFailed(t *testing.T) {
	// The proxy resolved a safe version (so allowed is populated) but the package
	// manager exited non-zero — e.g. a pin like ^1.17.0 that only the filtered
	// version satisfies. The summary must NOT claim the package was "installed":
	// the header warns the install did not complete, the per-line wording reads
	// "available" (the version exists) not "installed", and a remediation Note is
	// shown.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "axios", Version: "1.17.0", Age: 24 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, false)
	})

	if !strings.Contains(out, "install did not complete") {
		t.Errorf("missing failure header; got:\n%s", out)
	}
	if strings.Contains(out, "installed safe") {
		t.Errorf("must not claim a successful install; got:\n%s", out)
	}
	if !strings.Contains(out, "1.16.1 available") {
		t.Errorf("resolved line should read 'available' on a failed install; got:\n%s", out)
	}
	if strings.Contains(out, "1.16.1 installed") {
		t.Errorf("must not say 'installed' when the PM did not complete; got:\n%s", out)
	}
	if !strings.Contains(out, "Note:") || !strings.Contains(out, "relax the constraint or exclude the package") {
		t.Errorf("missing remediation note; got:\n%s", out)
	}
}

func TestPrintBlockSummary_LongListVerbose(t *testing.T) {
	// Tier D: more than maxBlockedDisplay packages → capped list with "… and N
	// more", the full divider, and the complete copy-paste disable command.
	forceNoColor(t)
	var blocked []supplychain.BlockedPackage
	var allowed []supplychain.InstalledPackage
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}
	for i, n := range names {
		blocked = append(blocked, supplychain.BlockedPackage{
			Name:    n,
			Version: "2.0.0",
			Age:     time.Duration(i+1) * time.Hour,
		})
		allowed = append(allowed, supplychain.InstalledPackage{Name: n, Version: "1.9.0"})
	}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, len(names), testPolicy(), pmNPM, true)
	})

	if !strings.Contains(out, "… and 1 more") {
		t.Errorf("missing overflow line; got:\n%s", out)
	}
	if !strings.Contains(out, strings.Repeat("─", scSepLen)) {
		t.Errorf("long list should draw the divider; got:\n%s", out)
	}
	if !strings.Contains(out, "ARMIS_SUPPLY_CHAIN=off npm install") {
		t.Errorf("long list should show the full disable command; got:\n%s", out)
	}
}

func TestGroupBlockedByPackage_CollapsesToYoungest(t *testing.T) {
	// Two blocked versions of one package collapse to a single result keyed on the
	// youngest version — that is the one the PM would have installed as "latest".
	blocked := []supplychain.BlockedPackage{
		{Name: "axios", Version: "1.17.0", Age: 48 * time.Hour},
		{Name: "axios", Version: "1.18.0", Age: 2 * time.Hour},
	}
	allowed := map[string]string{"axios": "1.16.1"}

	got := groupBlockedByPackage(blocked, allowed, 72*time.Hour)
	if len(got) != 1 {
		t.Fatalf("expected 1 grouped result, got %d: %#v", len(got), got)
	}
	if got[0].OldVersion != "1.18.0" {
		t.Errorf("OldVersion = %q, want the youngest 1.18.0", got[0].OldVersion)
	}
	if got[0].OldAge != 2*time.Hour {
		t.Errorf("OldAge = %v, want 2h", got[0].OldAge)
	}
	if got[0].NewVersion != "1.16.1" {
		t.Errorf("NewVersion = %q, want 1.16.1", got[0].NewVersion)
	}
}

func TestGroupBlockedByPackage_SortYoungestFirst(t *testing.T) {
	// Results are ordered youngest-first so the freshest (riskiest) package leads.
	blocked := []supplychain.BlockedPackage{
		{Name: "old", Version: "1.0.0", Age: 60 * time.Hour},
		{Name: "fresh", Version: "1.0.0", Age: 1 * time.Hour},
		{Name: "mid", Version: "1.0.0", Age: 12 * time.Hour},
	}
	got := groupBlockedByPackage(blocked, map[string]string{}, 72*time.Hour)
	wantOrder := []string{"fresh", "mid", "old"}
	for i, w := range wantOrder {
		if got[i].Name != w {
			t.Errorf("position %d = %q, want %q (full: %#v)", i, got[i].Name, w, got)
		}
	}
}

func TestFormatPolicyShort(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"days", 72 * time.Hour, "3-day"},
		{"one day", 24 * time.Hour, "1-day"},
		{"hours", 6 * time.Hour, "6-hour"},
		{"minutes", 30 * time.Minute, "30-minute"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatPolicyShort(tt.d); got != tt.want {
				t.Errorf("formatPolicyShort(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestRationaleMarker(t *testing.T) {
	// Redirect the cache dir to a temp location. os.UserCacheDir honors HOME on
	// darwin and XDG_CACHE_HOME on linux, so set both for portability.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	if rationaleAlreadyShown() {
		t.Fatal("marker should be absent in a fresh cache dir")
	}
	markRationaleShown()
	if !rationaleAlreadyShown() {
		t.Error("marker should be present after markRationaleShown")
	}
	// Idempotent: a second mark must not error or change the result.
	markRationaleShown()
	if !rationaleAlreadyShown() {
		t.Error("marker should remain present after a second mark")
	}
}

func TestShouldShowRationale_SuppressedWhenNonInteractive(t *testing.T) {
	// Under `go test` stdin/stderr are pipes, so cli.IsInteractive() is false and
	// the rationale must stay suppressed even with no marker present — this is the
	// CI / piped-output guarantee.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", tmp)

	if cli.IsInteractive() {
		t.Skip("test stderr/stdin are a TTY; cannot assert the non-interactive path")
	}
	if shouldShowRationale() {
		t.Error("rationale must be suppressed on a non-interactive terminal")
	}
}
