package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// The scan sbom-cpe command has three failure branches that can be verified
// without hitting the network or auth: path validation, --sbom rejection,
// and --vex rejection. Anything past those requires a mock API server; the
// driver-level tests in internal/scan/sbomcpe cover the packing pipeline.

func TestScanSbomCpeRunE_MissingPath(t *testing.T) {
	// Reset the parent scan command's globals just enough to reach RunE.
	restore := saveScanCmdGlobalsForTest()
	t.Cleanup(restore)

	err := scanSbomCpeCmd.RunE(scanSbomCpeCmd, []string{"/nonexistent/path/does/not/exist"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
	if !containsSubstring(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' in error, got: %v", err)
	}
}

func TestScanSbomCpeRunE_RejectsSbomFlag(t *testing.T) {
	restore := saveScanCmdGlobalsForTest()
	t.Cleanup(restore)

	// A real path so the stat check succeeds and we fall through to
	// the flag-validation branches.
	dir := t.TempDir()
	sbom := filepath.Join(dir, "x.json")
	if err := os.WriteFile(sbom, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	generateSBOM = true
	defer func() { generateSBOM = false }()

	err := scanSbomCpeCmd.RunE(scanSbomCpeCmd, []string{sbom})
	if err == nil {
		t.Fatal("expected error when --sbom is set")
	}
	if !containsSubstring(err.Error(), "--sbom is not supported") {
		t.Errorf("expected '--sbom is not supported' in error, got: %v", err)
	}
}

func TestScanSbomCpeRunE_RejectsVexFlag(t *testing.T) {
	restore := saveScanCmdGlobalsForTest()
	t.Cleanup(restore)

	dir := t.TempDir()
	sbom := filepath.Join(dir, "x.json")
	if err := os.WriteFile(sbom, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	generateVEX = true
	defer func() { generateVEX = false }()

	err := scanSbomCpeCmd.RunE(scanSbomCpeCmd, []string{sbom})
	if err == nil {
		t.Fatal("expected error when --vex is set")
	}
	if !containsSubstring(err.Error(), "--vex is not supported") {
		t.Errorf("expected '--vex is not supported' in error, got: %v", err)
	}
}

func TestScanSbomCpeCmd_RegisteredUnderScan(t *testing.T) {
	// The command must be a child of scanCmd for `armis-cli scan sbom-cpe`
	// to resolve. If the init() function ever drops the AddCommand call,
	// this test catches it.
	for _, c := range scanCmd.Commands() {
		if c == scanSbomCpeCmd {
			return
		}
	}
	t.Error("scanSbomCpeCmd is not registered under scanCmd")
}

// saveScanCmdGlobalsForTest saves the subset of package-level globals the
// scan sbom-cpe RunE touches before returning an error, then returns a
// restore function. The three flag globals (generateSBOM, generateVEX,
// sbomCpeOutput) are the only ones our RunE actually looks at prior to
// path validation and the SBOM/VEX guards.
func saveScanCmdGlobalsForTest() func() {
	origSBOM := generateSBOM
	origVEX := generateVEX
	origOutput := sbomCpeOutput
	return func() {
		generateSBOM = origSBOM
		generateVEX = origVEX
		sbomCpeOutput = origOutput
	}
}

// containsSubstring is a local test helper so we don't depend on strings
// package here — matches the light-touch style of the existing cmd tests.
func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
