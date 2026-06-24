package supplychain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasNpmrcMarker(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{name: "empty", content: "", want: false},
		{name: "plain config", content: "registry=https://registry.npmjs.org/\n", want: false},
		{name: "exact marker", content: NpmrcMarkerComment + "\n", want: true},
		{name: "marker among config", content: "registry=https://example.com/\n" + NpmrcMarkerComment + "\nfoo=bar\n", want: true},
		// A reworded marker still matches: every marker we write leads with the
		// fragment right after the '#', so detection survives a wording change.
		{name: "reworded marker still matches", content: "# armis-cli supply-chain (legacy wording)\n", want: true},
		{name: "indented marker still matches", content: "   #   armis-cli supply-chain: note\n", want: true},
		// False positives the anchored match must NOT fire on: a user comment that
		// merely mentions the phrase in prose, and a config value containing it.
		{name: "user comment mentioning phrase mid-line is not a marker", content: "# managed by armis-cli supply-chain tooling\n", want: false},
		{name: "config value containing fragment is not a marker", content: "_authToken=armis-cli supply-chain-scoped-token\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasNpmrcMarker([]byte(tt.content)); got != tt.want {
				t.Errorf("HasNpmrcMarker(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestRemoveNpmrcMarker(t *testing.T) {
	t.Run("missing file is not an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if changed {
			t.Errorf("changed = true, want false for missing file")
		}
	})

	t.Run("file without marker is left untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		const original = "registry=https://registry.npmjs.org/\nfoo=bar\n"
		writeFileAt(t, path, original)

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if changed {
			t.Errorf("changed = true, want false when no marker present")
		}
		if got := readFile(t, path); got != original {
			t.Errorf("content = %q, want unchanged %q", got, original)
		}
	})

	t.Run("strips marker and preserves surrounding config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		writeFileAt(t, path, "registry=https://example.com/\n"+NpmrcMarkerComment+"\nfoo=bar\n")

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if !changed {
			t.Errorf("changed = false, want true when marker present")
		}
		want := "registry=https://example.com/\nfoo=bar\n"
		if got := readFile(t, path); got != want {
			t.Errorf("content = %q, want %q", got, want)
		}
	})

	t.Run("marker-only file collapses to empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		writeFileAt(t, path, NpmrcMarkerComment+"\n")

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if !changed {
			t.Errorf("changed = false, want true")
		}
		if got := readFile(t, path); got != "" {
			t.Errorf("content = %q, want empty", got)
		}
	})

	t.Run("idempotent: second removal is a no-op", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		writeFileAt(t, path, "registry=https://example.com/\n"+NpmrcMarkerComment+"\n")

		if _, err := RemoveNpmrcMarker(path); err != nil {
			t.Fatalf("first RemoveNpmrcMarker: %v", err)
		}
		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("second RemoveNpmrcMarker: %v", err)
		}
		if changed {
			t.Errorf("changed = true on second pass, want false (idempotent)")
		}
	})

	// Production code reads the original mode via os.Stat and re-applies it on
	// write; a regression that hardcoded the 0o644 fallback would flip this 0o600
	// file and be caught here. Mirrors TestRemoveFunctions_PreservesPermissions.
	t.Run("preserves file permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		writeFileAt(t, path, "foo=bar\n"+NpmrcMarkerComment+"\n") // writeFileAt uses 0o600

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if !changed {
			t.Fatalf("changed = false, want true")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("perm = %o, want 0600 (original mode must be preserved, not the 0644 fallback)", got)
		}
	})

	// runInitNpmrc, when the original .npmrc lacks a trailing newline, writes
	// `original + "\n" + marker + "\n"`. After strip the file normalizes to
	// `original + "\n"` (one trailing newline) — it does not perfectly restore
	// the missing-newline form. Lock that intentional normalization in.
	t.Run("strips marker from no-trailing-NL form written by init", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		const original = "registry=https://example.com/"
		writeFileAt(t, path, original+"\n"+NpmrcMarkerComment+"\n")

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if !changed {
			t.Fatalf("changed = false, want true")
		}
		if got, want := readFile(t, path), original+"\n"; got != want {
			t.Errorf("content = %q, want %q", got, want)
		}
	})

	// The anchored match must not delete a user's own comment that merely
	// mentions the phrase, nor a config value containing it.
	t.Run("leaves user comment and value lines that merely mention the phrase", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".npmrc")
		const original = "# managed by armis-cli supply-chain tooling\n_authToken=armis-cli supply-chain-scoped\n"
		writeFileAt(t, path, original)

		changed, err := RemoveNpmrcMarker(path)
		if err != nil {
			t.Fatalf("RemoveNpmrcMarker: %v", err)
		}
		if changed {
			t.Errorf("changed = true, want false: no real marker present, user content must survive")
		}
		if got := readFile(t, path); got != original {
			t.Errorf("content = %q, want unchanged %q", got, original)
		}
	})
}

func TestNpmrcFileHasMarker(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing", ".npmrc")
	if NpmrcFileHasMarker(missing) {
		t.Errorf("NpmrcFileHasMarker(missing) = true, want false")
	}

	withMarker := filepath.Join(dir, ".npmrc")
	writeFileAt(t, withMarker, "foo=bar\n"+NpmrcMarkerComment+"\n")
	if !NpmrcFileHasMarker(withMarker) {
		t.Errorf("NpmrcFileHasMarker = false, want true for file with marker")
	}

	noMarker := filepath.Join(dir, "plain.npmrc")
	writeFileAt(t, noMarker, "foo=bar\n")
	if NpmrcFileHasMarker(noMarker) {
		t.Errorf("NpmrcFileHasMarker = true, want false for file without marker")
	}
}

// writeFileAt writes content to an explicit file path (0o600). It differs from
// manifest_test.go's writeFile, which takes a (dir, name) pair; these npmrc
// tests build their own paths via filepath.Join, so a path-based helper reads
// more directly.
func writeFileAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
