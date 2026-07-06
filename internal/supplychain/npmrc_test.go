package supplychain

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ─── npmrc marker management tests ───

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
		if runtime.GOOS == "windows" {
			t.Skip("Unix file permissions not supported on Windows")
		}
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

// ─── npmrc auth-token extraction tests (PPSC-994) ───

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

// TestNpmrcAuthToken is test-plan case #6: .npmrc token parsing — embedded "="
// not truncated, host+path-scoped key preferred, missing file/key → no token,
// no crash.
func TestNpmrcAuthToken(t *testing.T) {
	upstream := mustParseURL(t, "https://nexus.corp/repository/npm-group/")

	t.Run("host+path scoped key", func(t *testing.T) {
		npmrc := "//nexus.corp/repository/npm-group/:_authToken=abc123\n"
		tok, ok, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err != nil || !ok {
			t.Fatalf("expected token, got ok=%v err=%v", ok, err)
		}
		if tok != "abc123" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("bare host-scoped key fallback", func(t *testing.T) {
		npmrc := "//nexus.corp/:_authToken=hosttok\n"
		tok, ok, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err != nil || !ok {
			t.Fatalf("expected token, got ok=%v err=%v", ok, err)
		}
		if tok != "hosttok" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("host+path preferred over bare host", func(t *testing.T) {
		npmrc := "//nexus.corp/:_authToken=hosttok\n//nexus.corp/repository/npm-group/:_authToken=pathtok\n"
		tok, _, _ := NpmrcAuthToken([]string{npmrc}, upstream)
		if tok != "pathtok" {
			t.Errorf("expected host+path token to win, got %q", tok)
		}
	})

	t.Run("base64 token with = padding not truncated", func(t *testing.T) {
		npmrc := "//nexus.corp/repository/npm-group/:_authToken=YWJjZGVm==\n"
		tok, ok, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if tok != "YWJjZGVm==" {
			t.Errorf("token truncated: %q", tok)
		}
	})

	t.Run("missing key → no token, no error", func(t *testing.T) {
		npmrc := "//other.host/:_authToken=nope\nregistry=https://nexus.corp/\n"
		tok, ok, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok || tok != "" {
			t.Errorf("expected no token, got ok=%v tok=%q", ok, tok)
		}
	})

	t.Run("empty contents → no token, no crash", func(t *testing.T) {
		tok, ok, err := NpmrcAuthToken(nil, upstream)
		if err != nil || ok || tok != "" {
			t.Errorf("expected clean no-token, got ok=%v tok=%q err=%v", ok, tok, err)
		}
	})

	t.Run("nil upstream → no token", func(t *testing.T) {
		_, ok, err := NpmrcAuthToken([]string{"//x/:_authToken=y"}, nil)
		if ok || err != nil {
			t.Errorf("nil upstream should yield no token, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("comments and blank lines ignored", func(t *testing.T) {
		npmrc := "# a comment\n; another\n\n//nexus.corp/repository/npm-group/:_authToken=realtok\n"
		tok, ok, _ := NpmrcAuthToken([]string{npmrc}, upstream)
		if !ok || tok != "realtok" {
			t.Errorf("token = %q ok=%v", tok, ok)
		}
	})

	t.Run("project file wins over user file", func(t *testing.T) {
		project := "//nexus.corp/repository/npm-group/:_authToken=projecttok\n"
		user := "//nexus.corp/repository/npm-group/:_authToken=usertok\n"
		tok, _, _ := NpmrcAuthToken([]string{project, user}, upstream)
		if tok != "projecttok" {
			t.Errorf("expected project token to win, got %q", tok)
		}
	})
}

// TestResolveNpmrcToken is test-plan case #5: ${VAR} interpolation resolved;
// resolved token failing the safe charset → rejected with a clear error.
func TestResolveNpmrcToken(t *testing.T) {
	upstream := mustParseURL(t, "https://nexus.corp/npm/")

	t.Run("plain ${VAR} interpolated", func(t *testing.T) {
		t.Setenv("ARMIS_TEST_NPM_TOKEN", "resolved-secret")
		npmrc := "//nexus.corp/npm/:_authToken=${ARMIS_TEST_NPM_TOKEN}\n"
		tok, ok, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if tok != "resolved-secret" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("unset ${VAR} → hard error", func(t *testing.T) {
		npmrc := "//nexus.corp/npm/:_authToken=${ARMIS_DEFINITELY_UNSET_VAR}\n"
		_, _, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err == nil {
			t.Fatal("expected an error for an unset env var")
		}
		if !strings.Contains(err.Error(), "ARMIS_DEFINITELY_UNSET_VAR") {
			t.Errorf("error should name the missing var, got: %v", err)
		}
	})

	t.Run("header-hostile resolved token → rejected not sanitized", func(t *testing.T) {
		// A token carrying a CRLF + injected header must be rejected outright.
		t.Setenv("ARMIS_TEST_BAD_TOKEN", "good\r\nX-Injected: evil")
		npmrc := "//nexus.corp/npm/:_authToken=${ARMIS_TEST_BAD_TOKEN}\n"
		_, _, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err == nil {
			t.Fatal("expected rejection of a header-hostile token")
		}
		if !strings.Contains(err.Error(), "rejected") {
			t.Errorf("error should say rejected, got: %v", err)
		}
	})

	t.Run("token with space → rejected", func(t *testing.T) {
		npmrc := "//nexus.corp/npm/:_authToken=has space\n"
		_, _, err := NpmrcAuthToken([]string{npmrc}, upstream)
		if err == nil {
			t.Fatal("expected rejection of a token with a space")
		}
	})
}

// TestReadNpmrcAuthToken exercises the filesystem-backed reader against a real
// project .npmrc, covering the project-file path and the missing-file no-op.
func TestReadNpmrcAuthToken(t *testing.T) {
	upstream := mustParseURL(t, "https://nexus.corp/repository/npm-group/")

	t.Run("reads project .npmrc", func(t *testing.T) {
		dir := t.TempDir()
		npmrc := "//nexus.corp/repository/npm-group/:_authToken=projecttoken\n"
		if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrc), 0o600); err != nil {
			t.Fatal(err)
		}
		tok, ok, err := ReadNpmrcAuthToken(dir, upstream)
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if tok != "projecttoken" {
			t.Errorf("token = %q", tok)
		}
	})

	t.Run("missing project .npmrc → no token from project (home may still apply)", func(t *testing.T) {
		dir := t.TempDir() // no .npmrc written
		// Point HOME at an empty dir too so the user-level read also misses,
		// making the result deterministic regardless of the dev's real ~/.npmrc.
		t.Setenv("HOME", t.TempDir())
		tok, ok, err := ReadNpmrcAuthToken(dir, upstream)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok || tok != "" {
			t.Errorf("expected no token, got ok=%v tok=%q", ok, tok)
		}
	})
}

func TestIndexURLBasicAuth(t *testing.T) {
	t.Run("userinfo extracted", func(t *testing.T) {
		cred, ok, err := IndexURLBasicAuth("https://user:tok@nexus.corp/simple/")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if cred != "user:tok" {
			t.Errorf("cred = %q", cred)
		}
	})

	t.Run("no userinfo → none", func(t *testing.T) {
		_, ok, err := IndexURLBasicAuth("https://nexus.corp/simple/")
		if ok || err != nil {
			t.Errorf("expected no cred, got ok=%v err=%v", ok, err)
		}
	})
}
