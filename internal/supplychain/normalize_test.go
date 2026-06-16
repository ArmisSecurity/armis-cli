package supplychain

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	testProxyOrigin    = "http://127.0.0.1:39801"
	testUpstreamOrigin = "https://registry.npmjs.org"
)

func TestNormalizeArtifact(t *testing.T) {
	t.Run("rewrites every occurrence and preserves surrounding content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bun.lock")
		content := `{
  "packages": {
    "asynckit": ["asynckit@0.4.0", "` + testProxyOrigin + `/asynckit/-/asynckit-0.4.0.tgz", {}, "sha512-aaa"],
    "axios": ["axios@0.30.3", "` + testProxyOrigin + `/axios/-/axios-0.30.3.tgz", {}, "sha512-bbb"],
  }
}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		changed, err := NormalizeArtifact(path, testProxyOrigin, testUpstreamOrigin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected the artifact to be reported as changed")
		}

		got, err := os.ReadFile(path) //nolint:gosec // test reads its own temp file
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(got), testProxyOrigin) {
			t.Errorf("proxy origin still present after normalization:\n%s", got)
		}
		if !strings.Contains(string(got), testUpstreamOrigin+"/axios/-/axios-0.30.3.tgz") {
			t.Errorf("upstream tarball URL not written:\n%s", got)
		}
		if !strings.Contains(string(got), `"sha512-bbb"`) {
			t.Errorf("unrelated content was not preserved:\n%s", got)
		}
	})

	t.Run("preserves file permissions", func(t *testing.T) {
		// A 0o400 (read-only) file cannot be exercised here on Windows: os.Rename
		// refuses to replace a destination with the read-only attribute ("Access is
		// denied"), and Go reports a read-only file as 0o444 rather than 0o400, so
		// the permission assertion could not hold regardless. The cross-platform
		// rewrite behavior is covered by the 0o600 subtests above; the production
		// caller (normalizeProxyResidue) is best-effort and only warns on such a
		// failure. Mirrors the Windows skip on TestRemoveFunctions_PreservesPermissions.
		if runtime.GOOS == goosWindows {
			t.Skip("Unix file permissions not supported on Windows")
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "uv-receipt.toml")
		if err := os.WriteFile(path, []byte(`index-url = "`+testProxyOrigin+`/simple/"`), 0o400); err != nil {
			t.Fatal(err)
		}

		if _, err := NormalizeArtifact(path, testProxyOrigin, "https://pypi.org"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o400 {
			t.Errorf("permissions = %o, want 400", perm)
		}
		got, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
		if want := `index-url = "https://pypi.org/simple/"`; string(got) != want {
			t.Errorf("content = %q, want %q", got, want)
		}
	})

	t.Run("no occurrence leaves the file untouched", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		content := `{"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		changed, err := NormalizeArtifact(path, testProxyOrigin, testUpstreamOrigin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Error("a clean artifact must not be reported as changed")
		}
		got, _ := os.ReadFile(path) //nolint:gosec // test reads its own temp file
		if string(got) != content {
			t.Errorf("clean file was modified:\n%s", got)
		}
	})

	t.Run("symlinked lockfile rewrites the target and keeps the link", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-bun.lock")
		link := filepath.Join(dir, "bun.lock")
		if err := os.WriteFile(target, []byte(`"`+testProxyOrigin+`/axios.tgz"`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		changed, err := NormalizeArtifact(link, testProxyOrigin, testUpstreamOrigin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !changed {
			t.Fatal("expected the artifact to be reported as changed")
		}

		// The link must survive and the target must carry the rewrite.
		fi, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Error("symlink was replaced by a regular file")
		}
		got, _ := os.ReadFile(target) //nolint:gosec // test reads its own temp file
		if !strings.Contains(string(got), testUpstreamOrigin) {
			t.Errorf("target content not rewritten: %s", got)
		}
	})

	t.Run("missing file is not an error", func(t *testing.T) {
		changed, err := NormalizeArtifact(filepath.Join(t.TempDir(), "absent.lock"), testProxyOrigin, testUpstreamOrigin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Error("a missing file must not be reported as changed")
		}
	})
}

func TestFileContainsString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bun.lockb")
	if err := os.WriteFile(path, []byte("\x00\x01"+testProxyOrigin+"\x02"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !FileContainsString(path, testProxyOrigin) {
		t.Error("expected the needle to be found in the binary artifact")
	}
	if FileContainsString(path, "https://example.com") {
		t.Error("absent needle reported as found")
	}
	if FileContainsString(filepath.Join(dir, "absent"), testProxyOrigin) {
		t.Error("missing file reported as containing the needle")
	}
}

func TestDetectLoopbackRegistry(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name     string
		content  string
		wantHost string
		want     bool
	}{
		{"stale proxy residue", `"resolved": "http://127.0.0.1:39801/axios.tgz"`, "127.0.0.1", true},
		{"localhost registry", `registry = "http://localhost:4873/simple"`, "localhost", true},
		{"ipv6 loopback", `url = "http://[::1]:8080/npm/"`, "[::1]", true},
		{"clean upstream", `"resolved": "https://registry.npmjs.org/axios.tgz"`, "", false},
		// A bare IP outside a URL (e.g. in a comment or hash) must not trip it.
		{"non-URL mention", `# tested against 127.0.0.1 locally`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := write("lock-"+strings.ReplaceAll(tt.name, " ", "-"), tt.content)
			host, found := DetectLoopbackRegistry(p)
			if found != tt.want || host != tt.wantHost {
				t.Errorf("DetectLoopbackRegistry = (%q, %v), want (%q, %v)", host, found, tt.wantHost, tt.want)
			}
		})
	}

	if _, found := DetectLoopbackRegistry(filepath.Join(dir, "absent")); found {
		t.Error("missing file reported as containing a loopback registry")
	}
}

func TestFindUpward(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, "bun.lockb")
	if err := os.WriteFile(lock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := FindUpward(nested, "bun.lockb"); got != lock {
		t.Errorf("FindUpward = %q, want %q", got, lock)
	}
	if got := FindUpward(nested, "no-such-file.xyz"); got != "" {
		t.Errorf("FindUpward for a missing file = %q, want empty", got)
	}
}
