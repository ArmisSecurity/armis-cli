package repo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPlanUpload_SummarizesTheArmisignore(t *testing.T) {
	// No .armisignore.
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	plan, err := (&Scanner{}).planUpload(dir, false)
	if err != nil {
		t.Fatalf("planUpload: %v", err)
	}
	if got := plan.ignore; got != (IgnoreSummary{Root: dir}) {
		t.Errorf("no file: summary = %+v", got)
	}

	// Patterns in a nested file, directives of two types in the root one.
	writeFile(t, dir, ".armisignore", "severity:LOW\ncwe:79\n# a comment")
	writeFile(t, dir, filepath.Join("sub", ".armisignore"), "tmp/\n")
	plan, err = (&Scanner{}).planUpload(dir, false)
	if err != nil {
		t.Fatalf("planUpload: %v", err)
	}
	want := IgnoreSummary{Root: dir, RootFile: true, RootLines: 3, Paths: true, Severities: true, CWEs: true}
	if got := plan.ignore; got != want {
		t.Errorf("summary = %+v, want %+v", got, want)
	}

	// A category directive alone: no path patterns anywhere.
	dir = t.TempDir()
	writeFile(t, dir, ".armisignore", "category:license\n")
	plan, err = (&Scanner{}).planUpload(dir, false)
	if err != nil {
		t.Fatalf("planUpload: %v", err)
	}
	if got := plan.ignore; got.Paths || !got.Categories || got.Severities || got.RootLines != 1 {
		t.Errorf("summary = %+v", got)
	}
}

func TestWriteArmisignoreBlock(t *testing.T) {
	block := []string{"# armis-cli project setup: p, d", "dist/", "severity:LOW", "# end armis-cli project setup"}

	t.Run("creates the file", func(t *testing.T) {
		dir := t.TempDir()
		created, err := WriteArmisignoreBlock(dir, block)
		if err != nil || !created {
			t.Fatalf("created %v, err %v", created, err)
		}
		if got := readFile(t, filepath.Join(dir, ".armisignore")); got != strings.Join(block, "\n")+"\n" {
			t.Errorf("file = %q", got)
		}
	})

	t.Run("appends after a blank line, keeping every line", func(t *testing.T) {
		for _, existing := range []string{"node_modules/\n!keep.txt\n", "node_modules/\n!keep.txt"} {
			dir := t.TempDir()
			writeFile(t, dir, ".armisignore", existing)
			created, err := WriteArmisignoreBlock(dir, block)
			if err != nil || created {
				t.Fatalf("created %v, err %v", created, err)
			}
			want := "node_modules/\n!keep.txt\n\n" + strings.Join(block, "\n") + "\n"
			if got := readFile(t, filepath.Join(dir, ".armisignore")); got != want {
				t.Errorf("from %q: file = %q, want %q", existing, got, want)
			}
		}
	})

	t.Run("nothing to write writes nothing", func(t *testing.T) {
		dir := t.TempDir()
		if created, err := WriteArmisignoreBlock(dir, nil); err != nil || created {
			t.Fatalf("created %v, err %v", created, err)
		}
		if _, err := os.Stat(filepath.Join(dir, ".armisignore")); !os.IsNotExist(err) {
			t.Errorf("a file was created: %v", err)
		}
	})

	t.Run("refuses a symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere")
		writeFile(t, filepath.Dir(target), filepath.Base(target), "x/\n")
		if err := os.Symlink(target, filepath.Join(dir, ".armisignore")); err != nil {
			t.Skipf("no symlinks here: %v", err)
		}
		if _, err := WriteArmisignoreBlock(dir, block); err == nil {
			t.Error("a symlinked .armisignore must be refused")
		}
		if got := readFile(t, target); got != "x/\n" {
			t.Errorf("the link's target changed: %q", got)
		}
	})

	t.Run("refuses to pass the line limit", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, ".armisignore", strings.Repeat("a/\n", maxIgnoreFileLines-2))
		if _, err := WriteArmisignoreBlock(dir, block); err == nil {
			t.Error("expected an error past the line limit")
		}
		if got := countLines([]byte(readFile(t, filepath.Join(dir, ".armisignore")))); got != maxIgnoreFileLines-2 {
			t.Errorf("the file changed: %d lines", got)
		}
	})
}

// uploadedNames are the file names in the archive a test S3 upload carries.
func uploadedNames(t *testing.T, r *http.Request) []string {
	t.Helper()
	mr, err := r.MultipartReader()
	if err != nil {
		t.Errorf("multipart: %v", err)
		return nil
	}
	var names []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Errorf("multipart part: %v", err)
			return names
		}
		if part.FormName() != "file" {
			continue
		}
		gz, err := gzip.NewReader(part)
		if err != nil {
			t.Errorf("gzip: %v", err)
			return names
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("tar: %v", err)
				return names
			}
			names = append(names, hdr.Name)
		}
	}
}

// A first-time setup writes the root .armisignore from the resolver: the scan
// reloads it, so the new excludes already keep their files out of this upload.
func TestScan_ReloadsTheArmisignoreASetupWrote(t *testing.T) {
	t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
	var mu sync.Mutex
	var uploaded []string
	srv := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID:       testScanID,
				PresignedURL: testhelpers.SchemeFromRequest(r) + "://" + r.Host + "/_s3/upload",
				Fields:       map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/"):
			names := uploadedNames(t, r)
			mu.Lock()
			uploaded = names
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan"):
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: testScanID, ScanStatus: "INITIATED"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main\n")
	writeFile(t, dir, filepath.Join("secret", "keys.txt"), "nothing to see\n")

	var seen IgnoreSummary
	resolve := func(_ context.Context, ignore IgnoreSummary) (string, string, bool, error) {
		seen = ignore
		_, err := WriteArmisignoreBlock(ignore.Root, []string{"secret/", "severity:LOW"})
		return resolvedProjectID, "cli_dev", true, err
	}
	if _, err := newProjectTestScanner(t, srv.URL).WithAsync().WithProjectResolver(resolve).Scan(context.Background(), dir); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if seen.Root != dir || seen.RootFile || seen.Paths {
		t.Errorf("the resolver saw %+v, want the folder without an .armisignore", seen)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(uploaded, "main.go") || slices.ContainsFunc(uploaded, func(n string) bool { return strings.HasPrefix(n, "secret") }) {
		t.Errorf("uploaded %q: want main.go, and nothing under secret/", uploaded)
	}

	// The reloaded plan also carries the new directive.
	plan, err := (&Scanner{}).planUpload(dir, false)
	if err != nil || plan.suppressionConfig == nil || len(plan.suppressionConfig.Severities) != 1 {
		t.Errorf("reloaded suppression config = %+v, err %v", plan.suppressionConfig, err)
	}
}
