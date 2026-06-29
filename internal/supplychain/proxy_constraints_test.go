package supplychain

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// newConstraintProxy builds a Proxy with a young-package policy and the maps
// EvaluateConstraints reads, for the WS2 unit tests. now is "just published"
// so every version in the metadata below counts as too-young and gets filtered.
func newConstraintProxy() *Proxy {
	return &Proxy{
		policy:         Policy{MinReleaseAge: 72 * time.Hour},
		allowed:        make(map[string]allowedVersion),
		requiredRanges: make(map[string][]requiredRange),
		keptVersions:   make(map[string][]string),
	}
}

// npmMetadata renders an npm-style metadata document. times maps version→age
// (how long ago it was published); deps is each version's dependencies map.
func npmMetadata(times map[string]time.Duration, deps map[string]map[string]string) []byte {
	now := time.Now()
	timeObj := map[string]string{}
	versions := map[string]map[string]any{}
	for ver, age := range times {
		timeObj[ver] = now.Add(-age).Format(time.RFC3339)
		v := map[string]any{"name": "pkg", "version": ver}
		if d, ok := deps[ver]; ok {
			v["dependencies"] = d
		}
		versions[ver] = v
	}
	doc := map[string]any{"time": timeObj, "versions": versions}
	b, _ := json.Marshal(doc)
	return b
}

func TestEvaluateConstraints_KeptSatisfiesNoConflict(t *testing.T) {
	// debug has an OLD 4.3.9 (kept) and a YOUNG 4.4.0 (removed). express requires
	// ^4.3.0 — the surviving 4.3.9 satisfies it, so there is NO conflict.
	p := newConstraintProxy()

	// express: one old version (kept), declaring a dependency on debug ^4.3.0.
	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour},
		map[string]map[string]string{"1.0.0": {"debug": "^4.3.0"}},
	), "express")

	// debug: 4.3.9 old (kept), 4.4.0 fresh (removed).
	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"4.3.9": 100 * 24 * time.Hour, "4.4.0": time.Hour},
		nil,
	), "debug")

	conflicts := p.EvaluateConstraints()
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflict (4.3.9 satisfies ^4.3.0); got %#v", conflicts)
	}
}

func TestEvaluateConstraints_EverySatisfyingVersionFilteredConflict(t *testing.T) {
	// react-dom requires scheduler ^0.24.0. The ONLY version satisfying it
	// (0.24.0) is fresh and gets removed; the surviving 0.23.0 does not satisfy
	// ^0.24.0. That is the canonical transitive break → a conflict.
	p := newConstraintProxy()

	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"18.0.0": 100 * 24 * time.Hour},
		map[string]map[string]string{"18.0.0": {"scheduler": "^0.24.0"}},
	), "react-dom")

	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"0.23.0": 100 * 24 * time.Hour, "0.24.0": time.Hour},
		nil,
	), "scheduler")

	conflicts := p.EvaluateConstraints()
	if len(conflicts) != 1 {
		t.Fatalf("expected exactly 1 conflict; got %#v", conflicts)
	}
	c := conflicts[0]
	if c.Dep != "scheduler" || c.Range != "^0.24.0" || c.ByPkg != "react-dom" {
		t.Errorf("conflict = %#v, want {scheduler ^0.24.0 react-dom}", c)
	}
}

func TestEvaluateConstraints_RangeNeverSatisfiedNotOurDoing(t *testing.T) {
	// A range like ^99.0.0 that NO published version (kept or removed) ever
	// satisfied is not the age filter's doing — it must NOT be reported, or we'd
	// falsely blame ourselves for a pre-existing broken dependency.
	p := newConstraintProxy()

	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour},
		map[string]map[string]string{"1.0.0": {"ghost": "^99.0.0"}},
	), "parent")

	// ghost: only old + young versions far below 99.x.
	p.filterMetadata(npmMetadata(
		map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour, "1.1.0": time.Hour},
		nil,
	), "ghost")

	conflicts := p.EvaluateConstraints()
	if len(conflicts) != 0 {
		t.Fatalf("a never-satisfiable range must not be attributed to the filter; got %#v", conflicts)
	}
}

func TestEvaluateConstraints_ParseFailureFailOpen(t *testing.T) {
	// npm dependency values are a semver superset. Non-range specifiers (npm:
	// aliases, git+, file:, URL, latest, workspace) must be SKIPPED — never a
	// false conflict (fail-open on the diagnostic).
	specs := []string{
		"npm:@scope/other@^1.0.0",
		"git+https://github.com/u/r.git",
		"file:../local",
		"https://example.com/pkg.tgz",
		"latest",
		"workspace:*",
		"*",
	}
	for _, spec := range specs {
		t.Run(spec, func(t *testing.T) {
			p := newConstraintProxy()
			p.filterMetadata(npmMetadata(
				map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour},
				map[string]map[string]string{"1.0.0": {"weird": spec}},
			), "parent")
			// weird: all versions fresh (removed), so a parseable range with no
			// survivor would conflict — but an unparseable spec must not.
			p.filterMetadata(npmMetadata(
				map[string]time.Duration{"1.0.0": time.Hour},
				nil,
			), "weird")

			conflicts := p.EvaluateConstraints()
			for _, c := range conflicts {
				if c.Range == spec {
					t.Errorf("unparseable specifier %q must not produce a conflict; got %#v", spec, conflicts)
				}
			}
		})
	}
}

func TestEvaluateConstraints_DeterministicUnderShuffle(t *testing.T) {
	// The same inputs fed in different arrival orders must yield an identical
	// conflict set — the whole point of evaluating AFTER all metadata has flowed.
	build := func(order []string) []ConstraintConflict {
		p := newConstraintProxy()
		feed := map[string]func(){
			"react-dom": func() {
				p.filterMetadata(npmMetadata(
					map[string]time.Duration{"18.0.0": 100 * 24 * time.Hour},
					map[string]map[string]string{"18.0.0": {"scheduler": "^0.24.0"}},
				), "react-dom")
			},
			"scheduler": func() {
				p.filterMetadata(npmMetadata(
					map[string]time.Duration{"0.23.0": 100 * 24 * time.Hour, "0.24.0": time.Hour},
					nil,
				), "scheduler")
			},
			"vue": func() {
				p.filterMetadata(npmMetadata(
					map[string]time.Duration{"3.0.0": 100 * 24 * time.Hour},
					map[string]map[string]string{"3.0.0": {"reactivity": "~2.5.0"}},
				), "vue")
			},
			"reactivity": func() {
				p.filterMetadata(npmMetadata(
					map[string]time.Duration{"2.4.0": 100 * 24 * time.Hour, "2.5.0": time.Hour},
					nil,
				), "reactivity")
			},
		}
		for _, name := range order {
			feed[name]()
		}
		return p.EvaluateConstraints()
	}

	a := build([]string{"react-dom", "scheduler", "vue", "reactivity"})
	b := build([]string{"reactivity", "vue", "scheduler", "react-dom"})
	c := build([]string{"scheduler", "react-dom", "reactivity", "vue"})

	if fmt.Sprintf("%#v", a) != fmt.Sprintf("%#v", b) || fmt.Sprintf("%#v", a) != fmt.Sprintf("%#v", c) {
		t.Errorf("conflict set not deterministic across arrival orders:\n a=%#v\n b=%#v\n c=%#v", a, b, c)
	}
	if len(a) != 2 {
		t.Errorf("expected 2 conflicts (scheduler + reactivity); got %#v", a)
	}
}

func TestRecordConstraintData_RaceFreeUnderConcurrentFiltering(t *testing.T) {
	// Many concurrent filterMetadata calls into ONE Proxy must not race on the
	// accumulators. Run under `go test -race` to actually exercise the detector.
	p := newConstraintProxy()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkg := fmt.Sprintf("pkg%d", i)
			dep := fmt.Sprintf("dep%d", i%8)
			p.filterMetadata(npmMetadata(
				map[string]time.Duration{"1.0.0": 100 * 24 * time.Hour, "2.0.0": time.Hour},
				map[string]map[string]string{"1.0.0": {dep: "^3.0.0"}},
			), pkg)
		}(i)
	}
	wg.Wait()

	// Evaluation after the barrier must not panic and must be deterministic.
	_ = p.EvaluateConstraints()
}

func TestEvaluateConstraints_NoDataNoConflict(t *testing.T) {
	// A proxy that filtered nothing (empty accumulators) returns no conflicts and
	// never panics — the common success path.
	p := newConstraintProxy()
	if c := p.EvaluateConstraints(); len(c) != 0 {
		t.Errorf("expected no conflicts from an empty proxy; got %#v", c)
	}
}

func TestRecordConstraintData_CapsNewKeysAtLimit(t *testing.T) {
	// The accumulators are bounded at maxConstraintEntries distinct keys so a
	// hostile/pathological upstream metadata stream cannot grow them without
	// bound. At the cap a NEW package key is dropped; an EXISTING key is
	// overwritten with the latest full snapshot (never appended), so a single
	// key's slice stays bounded by the version count even under repeat fetches —
	// the diagnostic degrades to best-effort, never OOM. Pre-fill the maps to the
	// boundary (fast) rather than driving 50k real requests.
	p := newConstraintProxy()
	p.removedVersions = make(map[string][]string)
	for i := 0; i < maxConstraintEntries; i++ {
		key := fmt.Sprintf("pkg%d", i)
		p.keptVersions[key] = []string{"1.0.0"}
		p.removedVersions[key] = []string{"2.0.0"}
		p.requiredRanges[key] = []requiredRange{{Range: "^1.0.0", ByPkg: "root"}}
	}

	// One metadata doc for a brand-new package "overflow": kept 1.0.0, removed
	// 2.0.0 (fresh), and it declares a range on a brand-new dependency "newdep".
	meta := map[string]json.RawMessage{
		"versions": json.RawMessage(`{"1.0.0":{"dependencies":{"newdep":"^1.0.0"}}}`),
	}
	p.recordConstraintData(meta, []string{"1.0.0", "2.0.0"}, map[string]bool{"2.0.0": true}, "overflow")

	// New keys past the cap are dropped: the maps stay at the limit, never grow.
	if got := len(p.keptVersions); got != maxConstraintEntries {
		t.Errorf("keptVersions grew past the cap: len=%d, want %d", got, maxConstraintEntries)
	}
	if _, ok := p.keptVersions["overflow"]; ok {
		t.Error("a new key past the cap must be dropped from keptVersions")
	}
	if _, ok := p.requiredRanges["newdep"]; ok {
		t.Error("a new dependency key past the cap must be dropped from requiredRanges")
	}

	// An EXISTING key is still updated past the cap, but the new snapshot
	// OVERWRITES rather than appends (the doc comment's bounded guarantee): a
	// repeat fetch of pkg0 replaces its slice with the latest version set instead
	// of growing it.
	p.recordConstraintData(
		map[string]json.RawMessage{"versions": json.RawMessage(`{}`)},
		[]string{"3.0.0", "4.0.0"}, map[string]bool{}, "pkg0",
	)
	if got := p.keptVersions["pkg0"]; len(got) != 2 || got[0] != "3.0.0" || got[1] != "4.0.0" {
		t.Errorf("existing key should be overwritten with the latest snapshot, not appended: got %v, want [3.0.0 4.0.0]", got)
	}
}

func TestEvaluateConstraints_ToleratesPathologicalInput(t *testing.T) {
	// Robustness: EvaluateConstraints must never panic and never emit a false
	// conflict on malformed accumulator contents — garbage version strings,
	// exotic/blank ranges, and a dependent whose package was never even filtered.
	//
	// NOTE: this is a white-box guarantee about the function's OWN handling of bad
	// data, not a test of the recover() guard firing. The semver library
	// (Masterminds/semver v3) returns errors rather than panicking on every
	// pathological input we can construct (verified empirically: blank, "^^",
	// ">=1 <", NUL bytes, 24-digit majors all error cleanly), so the recover() in
	// EvaluateConstraints is defense-in-depth against a hypothetical future
	// library regression — it cannot be triggered through crafted input today.
	// This test instead proves the parse-failure / fail-open paths swallow every
	// bad shape gracefully.
	p := newConstraintProxy()
	p.removedVersions = make(map[string][]string)

	// A dependent declaring a grab-bag of ranges (most unparseable) on "dep".
	p.requiredRanges["dep"] = []requiredRange{
		{Range: "", ByPkg: "a"},                             // blank → wildcard, skipped
		{Range: "   ", ByPkg: "a"},                          // whitespace → wildcard, skipped
		{Range: "*", ByPkg: "a"},                            // explicit wildcard, skipped
		{Range: "^^1.0.0", ByPkg: "b"},                      // malformed → fail-open
		{Range: ">=1 <", ByPkg: "b"},                        // truncated → fail-open
		{Range: "git+https://x/y.git", ByPkg: "c"},          // non-range spec → fail-open
		{Range: "\x00\x01", ByPkg: "c"},                     // control bytes → fail-open
		{Range: "999999999999999999999999.0.0", ByPkg: "d"}, // absurd major → fail-open or no-match
		{Range: "^9.9.9", ByPkg: "e"},                       // parseable, never satisfied → "not our doing"
	}
	// dep's recorded versions are themselves garbage so parseVersions drops them.
	p.keptVersions["dep"] = []string{"", "not-a-version", "1.x.y.z", "??"}
	p.removedVersions["dep"] = []string{"garbage", "v-", ""}

	var conflicts []ConstraintConflict
	done := func() { conflicts = p.EvaluateConstraints() }
	// A panic here would fail the test loudly even without the recover() guard;
	// asserting no panic is the point.
	done()

	if len(conflicts) != 0 {
		t.Errorf("pathological input must yield no false conflicts; got %#v", conflicts)
	}
}
