package supplychain

import (
	"encoding/json"
	"testing"
	"time"
)

// pypiDocNoTimestamps renders a PEP 691 Simple API doc whose single file has NO
// upload-time — the "artifactory stripped timestamps" case.
func pypiDocNoTimestamps(filename string) []byte {
	doc := map[string]any{
		"name":  "requests",
		"files": []map[string]any{{"filename": filename, "url": "https://x/" + filename}},
	}
	b, _ := json.Marshal(doc)
	return b
}

// TestDegradeOnMissingTimestampsPyPI is test-plan case #8 (PyPI): with the flag
// set (configured artifactory), an undatable file PASSES THROUGH rather than
// being removed, and the file is kept in the filtered body.
func TestDegradeOnMissingTimestampsPyPI(t *testing.T) {
	p := &Proxy{
		policy:                     Policy{MinReleaseAge: 72 * time.Hour},
		mode:                       ModePyPI,
		allowed:                    make(map[string]allowedVersion),
		degradeOnMissingTimestamps: true,
		upstreamURL:                mustParseURL(t, "https://nexus.corp/repository/pypi-group/simple/"),
		customUpstream:             true,
	}
	body := pypiDocNoTimestamps("requests-2.30.0-py3-none-any.whl")
	filtered, blocked := p.filterPyPISimple(body, "requests")
	if len(blocked) != 0 {
		t.Fatalf("degrade-on: undatable file should NOT be blocked, got %d blocked", len(blocked))
	}
	// The file must still be present in the passed-through body.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(filtered, &doc); err != nil {
		t.Fatalf("filtered body is not valid JSON: %v", err)
	}
	var files []map[string]json.RawMessage
	json.Unmarshal(doc["files"], &files) //nolint:errcheck,gosec
	if len(files) != 1 {
		t.Errorf("expected the undatable file to pass through, got %d files", len(files))
	}
}

// TestFailClosedOnMissingTimestampsPyPI is test-plan case #9 — the MANDATORY
// regression guard. With the flag UNSET (the default public path), an undatable
// PyPI file is still REMOVED (fail-closed). This proves the new degrade flag did
// not weaken the default behavior for existing users.
func TestFailClosedOnMissingTimestampsPyPI(t *testing.T) {
	p := &Proxy{
		policy:  Policy{MinReleaseAge: 72 * time.Hour},
		mode:    ModePyPI,
		allowed: make(map[string]allowedVersion),
		// degradeOnMissingTimestamps: false (default)
	}
	body := pypiDocNoTimestamps("requests-2.30.0-py3-none-any.whl")
	filtered, blocked := p.filterPyPISimple(body, "requests")
	if len(blocked) != 1 {
		t.Fatalf("fail-closed: undatable file MUST be blocked, got %d blocked", len(blocked))
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(filtered, &doc) //nolint:errcheck,gosec
	var files []map[string]json.RawMessage
	json.Unmarshal(doc["files"], &files) //nolint:errcheck,gosec
	if len(files) != 0 {
		t.Errorf("fail-closed: undatable file MUST be removed, got %d files kept", len(files))
	}
}

// TestDegradeDoesNotAffectDatableFiles proves the degrade flag only governs the
// UNDATABLE case: a datable-but-too-young file is still removed even with the
// flag on (the timestamp exists; the file is genuinely too new).
func TestDegradeDoesNotAffectDatableFiles(t *testing.T) {
	recent := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	doc := map[string]any{
		"name": "requests",
		"files": []map[string]any{
			{"filename": "requests-9.9.9-py3-none-any.whl", "url": "https://x/r.whl", "upload-time": recent},
		},
	}
	body, _ := json.Marshal(doc)

	p := &Proxy{
		policy:                     Policy{MinReleaseAge: 72 * time.Hour},
		mode:                       ModePyPI,
		allowed:                    make(map[string]allowedVersion),
		degradeOnMissingTimestamps: true,
		upstreamURL:                mustParseURL(t, "https://nexus.corp/simple/"),
		customUpstream:             true,
	}
	_, blocked := p.filterPyPISimple(body, "requests")
	if len(blocked) != 1 {
		t.Errorf("a datable too-young file must still be blocked even under degrade, got %d", len(blocked))
	}
}

// TestDegradeNPMMissingTimeMap covers the npm side: with the flag set and the
// `time` map absent, the body passes through unchanged (npm already did this)
// and the one-time warning is allowed to fire without panic.
func TestDegradeNPMMissingTimeMap(t *testing.T) {
	doc := map[string]any{
		"name":      "leftpad",
		"dist-tags": map[string]string{"latest": "1.0.0"},
		"versions":  map[string]any{"1.0.0": map[string]any{"name": "leftpad", "version": "1.0.0"}},
		// no "time" key
	}
	body, _ := json.Marshal(doc)

	p := &Proxy{
		policy:                     Policy{MinReleaseAge: 72 * time.Hour},
		mode:                       ModeNPM,
		allowed:                    make(map[string]allowedVersion),
		degradeOnMissingTimestamps: true,
		upstreamURL:                mustParseURL(t, "https://nexus.corp/repository/npm-group/"),
		customUpstream:             true,
	}
	filtered, blocked := p.filterMetadata(body, "leftpad")
	if len(blocked) != 0 {
		t.Errorf("npm missing time map should not block, got %d", len(blocked))
	}
	if string(filtered) != string(body) {
		t.Errorf("npm body should pass through unchanged when time map absent")
	}
	if !p.degradeWarned {
		t.Error("expected the degraded-enforcement warning to have fired")
	}
}
