package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakePythonScript stands in for python3.13: it answers the version probe,
// "-m venv" (copying itself in as the venv interpreter) and "-m pip". The
// FAKE_* variables select failure modes.
const fakePythonScript = `#!/bin/sh
case "$1" in
  -c) echo True; exit 0;;
  -m)
    case "$2" in
      venv)
        mkdir -p "$3/bin"
        cp "$0" "$3/bin/python"
        [ -n "$FAKE_VENV_WARN" ] && echo "Unable to copy 'venvlauncher.exe' to 'python.exe'" >&2
        [ -n "$FAKE_NO_PY" ] && rm "$3/bin/python"
        exit 0;;
      pip)
        [ -n "$FAKE_PIP_FAIL" ] && { echo "pip failed" >&2; exit 1; }
        exit 0;;
    esac;;
esac
exit 0
`

// setupFakeVenvEnv puts the fake interpreter first on PATH and returns a
// plugin dir holding requirements.txt and a marker file in an existing .venv.
func setupFakeVenvEnv(t *testing.T) (pluginDir, oldMarker string) {
	t.Helper()
	if runtime.GOOS == osWindows {
		t.Skip("fake interpreter is a shell script")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "python3.13"), []byte(fakePythonScript), 0o700); err != nil { //nolint:gosec // test stub
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/bin:/usr/bin")

	pluginDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(pluginDir, "requirements.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldMarker = filepath.Join(pluginDir, ".venv", "old-marker")
	if err := os.MkdirAll(filepath.Dir(oldMarker), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldMarker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return pluginDir, oldMarker
}

func TestCreatePluginVenv_ReplacesExistingVenv(t *testing.T) {
	pluginDir, oldMarker := setupFakeVenvEnv(t)

	if err := createPluginVenv(pluginDir); err != nil {
		t.Fatalf("createPluginVenv: %v", err)
	}
	if _, err := os.Stat(oldMarker); !os.IsNotExist(err) {
		t.Error("old venv contents should be gone after a successful rebuild")
	}
	if !isExecutableFile(venvPython(pluginDir)) {
		t.Error("new venv interpreter missing")
	}
	for _, leftover := range []string{".venv.new", ".venv.old"} {
		if _, err := os.Stat(filepath.Join(pluginDir, leftover)); !os.IsNotExist(err) {
			t.Errorf("%s should not remain", leftover)
		}
	}
}

func TestCreatePluginVenv_FailuresKeepOldVenvAndNameTheStep(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		wantStep string
	}{
		{"venv copy warning", "FAKE_VENV_WARN", "step 1/3"},
		{"interpreter not created", "FAKE_NO_PY", "step 1/3"},
		{"pip failure", "FAKE_PIP_FAIL", "step 3/3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginDir, oldMarker := setupFakeVenvEnv(t)
			t.Setenv(tt.envVar, "1")

			err := createPluginVenv(pluginDir)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.wantStep) {
				t.Errorf("error should name %q, got: %v", tt.wantStep, err)
			}
			if _, statErr := os.Stat(oldMarker); statErr != nil {
				t.Error("the previous venv must be left untouched on failure")
			}
			if _, statErr := os.Stat(filepath.Join(pluginDir, ".venv.new")); !os.IsNotExist(statErr) {
				t.Error("the half-built staging venv must be removed")
			}
		})
	}
}

func TestSwapVenv_RestoresOldWhenStageMissing(t *testing.T) {
	dir := t.TempDir()
	venv := filepath.Join(dir, ".venv")
	if err := os.MkdirAll(venv, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := swapVenv(venv, filepath.Join(dir, ".venv.new")); err == nil {
		t.Fatal("expected error when the staged venv does not exist")
	}
	if _, err := os.Stat(venv); err != nil {
		t.Errorf("the old venv must be restored: %v", err)
	}
}
