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
