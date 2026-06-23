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
		printBlockSummary(nil, nil, 12, testPolicy(), pmNPM, true, nil, nil)
	})
	if !strings.Contains(out, "12 packages checked, all pass") {
		t.Errorf("missing all-pass line; got:\n%s", out)
	}
	// Policy phrasing must match the filter path's "(3-day policy)" wording so the
	// two code paths never drift back to "minimum age" vs "policy".
	if !strings.Contains(out, "(3-day policy)") {
		t.Errorf("all-pass line should use unified \"(3-day policy)\" phrasing; got:\n%s", out)
	}
	if strings.Contains(out, "package(s)") {
		t.Errorf("output still uses package(s); got:\n%s", out)
	}
}

func TestPrintBlockSummary_AllPassSingular(t *testing.T) {
	// One package checked → verb agreement: "passed", not the plural "all pass"
	// ("all" implies more than one).
	forceNoColor(t)
	out := captureStderr(t, func() {
		printBlockSummary(nil, nil, 1, testPolicy(), pmNPM, true, nil, nil)
	})
	if !strings.Contains(out, "1 package checked, passed") {
		t.Errorf("singular all-pass line should read \"1 package checked, passed\"; got:\n%s", out)
	}
	if strings.Contains(out, "all pass") {
		t.Errorf("singular case must not use plural \"all pass\"; got:\n%s", out)
	}
}

func TestPrintBlockSummary_AllPassZeroChecked(t *testing.T) {
	// Nothing checked → nothing printed (e.g. a fully cached install).
	forceNoColor(t)
	out := captureStderr(t, func() {
		printBlockSummary(nil, nil, 0, testPolicy(), pmNPM, true, nil, nil)
	})
	if out != "" {
		t.Errorf("expected no output when nothing was checked; got:\n%s", out)
	}
}

func TestPrintBlockSummary_SingleResolved(t *testing.T) {
	// Tier B: one package filtered and resolved → success header, an
	// installed-leads/skipped-trails line, terse Disable hint, and NO
	// divider/heavy chrome.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "axios", Version: "1.17.0", DisplayVersion: "1.17.0", Age: 24 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1", Age: 10 * 24 * time.Hour}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, true, nil, nil)
	})

	wantSubstrings := []string{
		"filtered 1 too-new release → installed safe version (3-day policy)",
		"axios",
		// The line leads with what was installed and its age...
		"1.16.1 installed (10 days old)",
		// ...and trails with the skipped version and its age.
		"— skipped 1.17.0 (1 day old)",
		"Disable: ARMIS_SUPPLY_CHAIN=off",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q; got:\n%s", want, out)
		}
	}
	// The installed (resolved) version must appear before the skipped one on the
	// line — the flip is the whole point of the layout.
	if i, j := strings.Index(out, "1.16.1 installed"), strings.Index(out, "skipped 1.17.0"); i < 0 || j < 0 || i > j {
		t.Errorf("installed version should lead the skipped version; got:\n%s", out)
	}
	// Short list must not draw the divider or the full copy-paste incantation.
	if strings.Contains(out, strings.Repeat("─", scSepLen)) {
		t.Errorf("short list should not draw a divider; got:\n%s", out)
	}
	if strings.Contains(out, "ARMIS_SUPPLY_CHAIN=off npm install") {
		t.Errorf("short list should use the terse disable hint; got:\n%s", out)
	}
}

func TestPrintBlockSummary_PyPIFilenameNotPrerelease(t *testing.T) {
	// Regression: a PyPI BlockedPackage carries a *filename* in Version
	// ("filelock-3.29.2.tar.gz"). The summary must classify on DisplayVersion, not
	// the filename — splitting the filename on its first '-' would otherwise read
	// every PyPI package as a "filelock" prerelease and wrongly print "withheld N
	// prereleases; a default install was unaffected". These are real stable
	// releases the proxy downgraded, so the honest framing is a successful filter.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{
		{Name: "filelock", Version: "filelock-3.29.2.tar.gz", DisplayVersion: "3.29.2", Age: 11 * time.Minute},
		{Name: "superdialog", Version: "superdialog-0.2.5.tar.gz", DisplayVersion: "0.2.5", Age: 6 * time.Hour},
	}
	allowed := []supplychain.InstalledPackage{
		{Name: "filelock", Version: "3.29.1", Age: 9 * 24 * time.Hour},
		{Name: "superdialog", Version: "0.2.3", Age: 8 * 24 * time.Hour},
	}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 2, testPolicy(), pmUV, true, nil, nil)
	})

	if strings.Contains(out, "withheld") || strings.Contains(out, "a default install was unaffected") {
		t.Errorf("PyPI filenames must not be misread as prereleases; got:\n%s", out)
	}
	if !strings.Contains(out, "filtered 2 too-new releases → installed safe versions (3-day policy)") {
		t.Errorf("expected a genuine-filter success header; got:\n%s", out)
	}
	// Clean parsed versions on the line, never the raw filename.
	if strings.Contains(out, ".tar.gz") {
		t.Errorf("line should show the parsed version, not the filename; got:\n%s", out)
	}
	// Collapse runs of spaces so column-alignment padding does not break the
	// substring match (versions are right-padded to a common width).
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "0.2.3 installed (8 days old) — skipped 0.2.5 (6 hours old)") {
		t.Errorf("expected installed-leads/skipped-trails layout with parsed versions; got:\n%s", out)
	}
}

func TestPrintBlockSummary_UnparseableFilenameNotPrerelease(t *testing.T) {
	// Regression for the IsPrerelease fix: when pypiVersionFromFilename cannot
	// parse a filename, DisplayVersion is empty and blockedDisplayVersion falls
	// back to the raw Version (the filename itself). The old SemVer branch flagged
	// any '-' after the first byte, so "filelock-3.29.2.tar.gz" (head "filelock")
	// was read as a prerelease — driving the wrong "withheld a prerelease; a
	// default install was unaffected" framing for a real stable release the proxy
	// downgraded. With the digit-before-'-' guard it must be framed as a genuine
	// filter. This is the one path that exercises the empty-DisplayVersion
	// fallback through the full summary, not the IsPrerelease helper in isolation.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{
		{Name: "filelock", Version: "filelock-3.29.2.tar.gz", DisplayVersion: "", Age: 11 * time.Minute},
	}
	allowed := []supplychain.InstalledPackage{{Name: "filelock", Version: "3.29.1", Age: 9 * 24 * time.Hour}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 1, testPolicy(), pmUV, true, nil, nil)
	})

	if strings.Contains(out, "withheld") || strings.Contains(out, "a default install was unaffected") {
		t.Errorf("an unparseable PyPI filename must not be misread as a prerelease; got:\n%s", out)
	}
	if !strings.Contains(out, "filtered 1 too-new release → installed safe version (3-day policy)") {
		t.Errorf("expected a genuine-filter success header; got:\n%s", out)
	}
}

func TestPrintBlockSummary_UndatableSkippedOmitsAge(t *testing.T) {
	// A PyPI file the proxy could not date is blocked with Age == 0 (fail-closed).
	// The skipped clause must NOT claim a precise "(0 minutes old)" — it should
	// name the version and omit the age entirely.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{
		{Name: "mystery", Version: "mystery-1.0.0.tar.gz", DisplayVersion: "1.0.0", Age: 0},
	}
	allowed := []supplychain.InstalledPackage{{Name: "mystery", Version: "0.9.0", Age: 30 * 24 * time.Hour}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 1, testPolicy(), pmUV, true, nil, nil)
	})

	if strings.Contains(out, "0 minutes old") {
		t.Errorf("undatable skipped version must not claim a precise age; got:\n%s", out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "— skipped 1.0.0") {
		t.Errorf("expected the skipped version named without an age; got:\n%s", out)
	}
	if strings.Contains(flat, "skipped 1.0.0 (") {
		t.Errorf("skipped clause should carry no age token for an undatable file; got:\n%s", out)
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
		printBlockSummary(blocked, allowed, 7, testPolicy(), pmNPM, true, nil, nil)
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
	// "available" (the version exists) not "installed", and the WS1 culprit/
	// remediation block is shown.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "axios", Version: "1.17.0", Age: 24 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, false, []string{"install"}, nil)
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
	// WS1: a fallback existed and there was no confirmed conflict, so axios is
	// listed as a candidate culprit, and the surgical-first remediation ladder is
	// shown with the full copy-paste SKIP command.
	if !strings.Contains(out, "Candidates: axios") {
		t.Errorf("expected axios named as a candidate culprit; got:\n%s", out)
	}
	if !strings.Contains(out, "ARMIS_SUPPLY_CHAIN_SKIP=axios npm install") {
		t.Errorf("expected full copy-paste SKIP command incl. PM + args; got:\n%s", out)
	}
	// The global kill switch must NOT appear on the failure path.
	if strings.Contains(out, "ARMIS_SUPPLY_CHAIN=off") {
		t.Errorf("global off kill switch must not be surfaced on a failed install; got:\n%s", out)
	}
	// Remediation ordering: SKIP (surgical) before min-age (broad).
	if i, j := strings.Index(out, "Allow one package"), strings.Index(out, "Relax the window"); i < 0 || j < 0 || i > j {
		t.Errorf("remediation must be ordered surgical→broad; got:\n%s", out)
	}
}

func TestPrintBlockSummary_NoFallbackNamesCulprit(t *testing.T) {
	// A package stripped to nothing (NewVersion == "") on a failed install is the
	// strongest no-conflict signal: WS1 must name it explicitly as the why.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "leftpad", Version: "2.0.0", DisplayVersion: "2.0.0", Age: 3 * time.Hour}}
	// No allowed entry → no safe fallback.
	out := captureStderr(t, func() {
		printBlockSummary(blocked, nil, 5, testPolicy(), pmNPM, false, []string{"install"}, nil)
	})

	if !strings.Contains(out, "leftpad@2.0.0") {
		t.Errorf("expected the no-fallback package named; got:\n%s", out)
	}
	if !strings.Contains(out, "no version older than the 3-day policy") {
		t.Errorf("expected the no-older-version explanation; got:\n%s", out)
	}
	if !strings.Contains(out, "ARMIS_SUPPLY_CHAIN_SKIP=leftpad npm install") {
		t.Errorf("expected SKIP command seeded with the culprit; got:\n%s", out)
	}
}

func TestPrintBlockSummary_ConflictNamesDependentAndRange(t *testing.T) {
	// WS2 conflict surfaced through WS1: a removed version satisfied a dependent's
	// range and no surviving version does. The note names the dependency, the
	// range, and who required it — the canonical transitive-incompatibility case.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "scheduler", Version: "0.24.0", DisplayVersion: "0.24.0", Age: 2 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "scheduler", Version: "0.23.0", Age: 30 * 24 * time.Hour}}
	conflicts := []supplychain.ConstraintConflict{{Dep: "scheduler", Range: "^0.24.0", ByPkg: "react-dom"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, false, []string{"install"}, conflicts)
	})

	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "scheduler has no version older than the 3-day policy that satisfies ^0.24.0 (required by react-dom)") {
		t.Errorf("expected conflict to name dep, range, and dependent; got:\n%s", out)
	}
	if !strings.Contains(out, "ARMIS_SUPPLY_CHAIN_SKIP=scheduler npm install") {
		t.Errorf("expected SKIP command seeded with the conflicting dependency; got:\n%s", out)
	}
}

func TestPrintFailureCulprits_PipAttributionGap(t *testing.T) {
	// pip/uv get no WS2 attribution (npm-family only), so the failure note must
	// say so and point at uv tree / pipdeptree — preventing "why did my
	// colleague's npm failure name a culprit but mine didn't?" confusion.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "requests", Version: "requests-2.99.0.tar.gz", DisplayVersion: "2.99.0", Age: 2 * time.Hour}}
	out := captureStderr(t, func() {
		printBlockSummary(blocked, nil, 5, testPolicy(), pmPip, false, []string{"install", "requests"}, nil)
	})

	if !strings.Contains(out, "constraint attribution isn't available for pip/uv") {
		t.Errorf("expected the pip/uv attribution-gap note; got:\n%s", out)
	}
	if !strings.Contains(out, "uv tree") || !strings.Contains(out, "pipdeptree") {
		t.Errorf("expected pointer to uv tree / pipdeptree; got:\n%s", out)
	}
}

func TestPrintBlockSummary_OnlyPrerelease(t *testing.T) {
	// The only blocked version is a prerelease (alpha). A bare `npm install` resolves
	// "latest" to the newest stable release and never auto-selects an alpha, so the
	// filter did not change what the user would have gotten. The summary must NOT
	// claim it "filtered a too-new release → installed safe version" — that overstates
	// the tool's effect. It should state honestly that a prerelease was withheld and
	// the default install was unaffected.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{{Name: "axios", Version: "2.0.0-alpha.1", Age: 24 * time.Hour}}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, true, nil, nil)
	})

	if !strings.Contains(out, "withheld 1 prerelease") {
		t.Errorf("expected honest prerelease framing; got:\n%s", out)
	}
	if !strings.Contains(out, "a default install was unaffected") {
		t.Errorf("expected 'default install unaffected' clause; got:\n%s", out)
	}
	if strings.Contains(out, "installed safe version") {
		t.Errorf("must not claim a protective filter for a prerelease-only block; got:\n%s", out)
	}
	if strings.Contains(out, "too-new release") {
		t.Errorf("prerelease block must not be framed as a too-new release; got:\n%s", out)
	}
}

func TestPrintBlockSummary_StableStillClaimsFilter(t *testing.T) {
	// A blocked stable release alongside a blocked prerelease must still read as a
	// genuine filter: filterRelevantBlocked drops the prerelease, leaving a stable
	// version a default install WOULD have selected, so the success framing is honest.
	forceNoColor(t)
	blocked := []supplychain.BlockedPackage{
		{Name: "axios", Version: "1.17.0", Age: 24 * time.Hour},
		{Name: "axios", Version: "2.0.0-alpha.1", Age: 2 * time.Hour},
	}
	allowed := []supplychain.InstalledPackage{{Name: "axios", Version: "1.16.1"}}

	out := captureStderr(t, func() {
		printBlockSummary(blocked, allowed, 5, testPolicy(), pmNPM, true, nil, nil)
	})

	if !strings.Contains(out, "installed safe version") {
		t.Errorf("a blocked stable release should still read as a genuine filter; got:\n%s", out)
	}
	if strings.Contains(out, "withheld") {
		t.Errorf("must not use prerelease framing when a stable release was filtered; got:\n%s", out)
	}
}

func TestAllResultsPrerelease(t *testing.T) {
	tests := []struct {
		name    string
		results []pkgFilterResult
		want    bool
	}{
		{"empty", nil, false},
		{"single prerelease", []pkgFilterResult{{OldVersion: testVersion + "-rc.1"}}, true},
		{"single stable", []pkgFilterResult{{OldVersion: testVersion}}, false},
		{"mixed", []pkgFilterResult{{OldVersion: testVersion + "-beta"}, {OldVersion: "2.0.0"}}, false},
		{"all prerelease", []pkgFilterResult{{OldVersion: testVersion + "-alpha"}, {OldVersion: "2.0.0-rc.1"}}, true},
		// PEP 440 prereleases (no SemVer dash) must count as prereleases too.
		{"pep440 rc", []pkgFilterResult{{OldVersion: "1.0.0rc1"}}, true},
		{"pep440 mixed with stable", []pkgFilterResult{{OldVersion: "1.0.0b2"}, {OldVersion: "2.0.0"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allResultsPrerelease(tt.results); got != tt.want {
				t.Errorf("allResultsPrerelease(%#v) = %v, want %v", tt.results, got, tt.want)
			}
		})
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
		printBlockSummary(blocked, allowed, len(names), testPolicy(), pmNPM, true, nil, nil)
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
	allowed := map[string]supplychain.InstalledPackage{
		"axios": {Name: "axios", Version: "1.16.1", Age: 10 * 24 * time.Hour},
	}

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
	// The resolved version's age must flow through so the line can show
	// "1.16.1 installed (10 days old)".
	if got[0].NewAge != 10*24*time.Hour {
		t.Errorf("NewAge = %v, want 240h", got[0].NewAge)
	}
}

func TestGroupBlockedByPackage_SortYoungestFirst(t *testing.T) {
	// Results are ordered youngest-first so the freshest (riskiest) package leads.
	blocked := []supplychain.BlockedPackage{
		{Name: "old", Version: "1.0.0", Age: 60 * time.Hour},
		{Name: "fresh", Version: "1.0.0", Age: 1 * time.Hour},
		{Name: "mid", Version: "1.0.0", Age: 12 * time.Hour},
	}
	got := groupBlockedByPackage(blocked, map[string]supplychain.InstalledPackage{}, 72*time.Hour)
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
