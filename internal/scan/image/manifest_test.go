package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArmisSecurity/armis-cli/internal/api"
	"github.com/ArmisSecurity/armis-cli/internal/httpclient"
	"github.com/ArmisSecurity/armis-cli/internal/model"
	"github.com/ArmisSecurity/armis-cli/internal/scan"
	"github.com/ArmisSecurity/armis-cli/internal/scan/testhelpers"
	"github.com/ArmisSecurity/armis-cli/internal/testutil"
)

type tarEntry struct {
	name string
	body string
	dir  bool
}

// writeImageTar writes entries as a tar, gzip-compressed when the name ends
// in .tar.gz, and returns its path.
func writeImageTar(t *testing.T, name string, entries []tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var gz *gzip.Writer
	if strings.HasSuffix(name, ".tar.gz") {
		gz = gzip.NewWriter(&buf)
		w = gz
	}
	tw := tar.NewWriter(w)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0600, Size: int64(len(e.body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if e.dir {
			hdr = &tar.Header{Name: e.name, Mode: 0700, Typeflag: tar.TypeDir, Format: tar.FormatUSTAR}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write tar: %v", err)
	}
	return path
}

// dockerSave returns the entries of a docker save tarball whose manifest
// lists repoTags.
func dockerSave(repoTags ...string) []tarEntry {
	manifest, _ := json.Marshal([]map[string]any{{
		"Config": "blobs/sha256/c0", "RepoTags": repoTags, "Layers": []string{"blobs/sha256/l1"},
	}})
	return []tarEntry{
		{name: "blobs/", dir: true},
		{name: "blobs/sha256/c0", body: `{"architecture":"amd64"}`},
		{name: "blobs/sha256/l1", body: "layer"},
		{name: "index.json", body: `{"schemaVersion":2}`},
		{name: "manifest.json", body: string(manifest)},
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
	}
}

func TestTarballImageRef(t *testing.T) {
	// The spec's cap, written out rather than taken from maxManifestSize so a
	// change to the constant fails here.
	const oneMiB = 1 << 20
	padded := func(size int) string {
		manifest := `[{"RepoTags":["python:3.12-slim"]}]`
		return manifest + strings.Repeat(" ", size-len(manifest))
	}
	tests := []struct {
		name    string
		file    string
		entries []tarEntry
		want    string
	}{
		{"docker save tar gives the first RepoTags entry", "image.tar", dockerSave("python:3.12-slim", "python:3.12"), "python:3.12-slim"},
		{"gzip-compressed tarball", "image.tar.gz", dockerSave("python:3.12-slim"), "python:3.12-slim"},
		{"tag is normalized", "image.tar", dockerSave("docker.io/library/nginx:1.27"), "nginx:1.27"},
		{"./manifest.json", "image.tar", []tarEntry{{name: "./manifest.json", body: `[{"RepoTags":["alpine:3.20"]}]`}}, "alpine:3.20"},
		{"first manifest entry without tags is skipped", "image.tar",
			[]tarEntry{{name: "manifest.json", body: `[{"RepoTags":null},{"RepoTags":["redis:7"]}]`}}, "redis:7"},
		{"manifest of exactly 1 MiB", "image.tar", []tarEntry{{name: "manifest.json", body: padded(oneMiB)}}, "python:3.12-slim"},
		{"no manifest.json (OCI layout)", "image.tar", []tarEntry{
			{name: "index.json", body: `{"schemaVersion":2}`}, {name: "oci-layout", body: `{}`},
		}, ""},
		{"no RepoTags", "image.tar", dockerSave(), ""},
		{"a tag validateImageName rejects", "image.tar", dockerSave("Bad Image:tag"), ""},
		{"a tag with a leading dash", "image.tar", dockerSave("-v:1"), ""},
		{"an upper-case repository name", "image.tar", dockerSave("Python:3.12"), ""},
		{"manifest.json over 1 MiB", "image.tar", []tarEntry{{name: "manifest.json", body: padded(oneMiB + 1)}}, ""},
		{"manifest.json below the top level", "image.tar", []tarEntry{{name: "blobs/manifest.json", body: `[{"RepoTags":["alpine:3.20"]}]`}}, ""},
		{"manifest.json that is not JSON", "image.tar", []tarEntry{{name: "manifest.json", body: "not json"}}, ""},
		{"manifest.json that is not a list", "image.tar", []tarEntry{{name: "manifest.json", body: `{"RepoTags":["alpine:3.20"]}`}}, ""},
		{"a directory named manifest.json", "image.tar", []tarEntry{{name: "manifest.json", dir: true}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeImageTar(t, tt.file, tt.entries)
			if got := tarballImageRef(context.Background(), path); got != tt.want {
				t.Errorf("tarballImageRef = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("a file that is not a tar", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "image.tar")
		if err := os.WriteFile(path, []byte("garbage"), 0600); err != nil {
			t.Fatal(err)
		}
		if got := tarballImageRef(context.Background(), path); got != "" {
			t.Errorf("tarballImageRef = %q, want empty", got)
		}
	})

	t.Run("a .tar.gz that is not gzip", func(t *testing.T) {
		path := writeImageTar(t, "image.tar", dockerSave("python:3.12-slim"))
		gzName := path + ".gz"
		if err := os.Rename(path, gzName); err != nil {
			t.Fatal(err)
		}
		if got := tarballImageRef(context.Background(), gzName); got != "" {
			t.Errorf("tarballImageRef = %q, want empty", got)
		}
	})

	t.Run("a cancelled context reads nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		path := writeImageTar(t, "image.tar", dockerSave("python:3.12-slim"))
		if got := tarballImageRef(ctx, path); got != "" {
			t.Errorf("tarballImageRef = %q, want empty", got)
		}
	})

	t.Run("Ctrl+C while a gzip layer decompresses stops the read", func(t *testing.T) {
		// An 8 MiB layer, then manifest.json. The loop checks ctx once before
		// each Next, two calls in all, and the Next that skips the layer
		// decompresses all of it. Ctrl+C after those two checks is seen only
		// by a Read inside that skip.
		path := writeImageTar(t, "image.tar.gz", []tarEntry{
			{name: "blobs/sha256/big", body: strings.Repeat("x", 8<<20)},
			{name: "manifest.json", body: `[{"RepoTags":["python:3.12-slim"]}]`},
		})
		ctx := &cancelAfter{Context: context.Background(), after: 2}
		if got := tarballImageRef(ctx, path); got != "" {
			t.Errorf("tarballImageRef = %q, want empty after the cancel", got)
		}
	})

	t.Run("a missing file", func(t *testing.T) {
		if got := tarballImageRef(context.Background(), filepath.Join(t.TempDir(), "none.tar")); got != "" {
			t.Errorf("tarballImageRef = %q, want empty", got)
		}
	})
}

// cancelAfter is a context whose Err reports context.Canceled from call
// after+1 on, standing for a Ctrl+C at a known point of a read.
type cancelAfter struct {
	context.Context
	after, calls int
}

func (c *cancelAfter) Err() error {
	c.calls++
	if c.calls > c.after {
		return context.Canceled
	}
	return nil
}

func TestCtxReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := ctxReader{ctx: ctx, r: strings.NewReader("data")}
	buf := make([]byte, 2)
	if n, err := r.Read(buf); n != 2 || err != nil {
		t.Fatalf("Read before cancel = %d, %v; want 2, nil", n, err)
	}
	cancel()
	if n, err := r.Read(buf); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Read after cancel = %d, %v; want 0, context.Canceled", n, err)
	}
}

func TestImageRefField(t *testing.T) {
	if got := imageRefField(strings.Repeat("a", maxImageRefLength)); len(got) != maxImageRefLength {
		t.Errorf("a %d-character ref must be kept", maxImageRefLength)
	}
	if got := imageRefField(strings.Repeat("a", maxImageRefLength+1)); got != "" {
		t.Errorf("a %d-character ref must be dropped, got %d characters", maxImageRefLength+1, len(got))
	}
}

// newScanBodyServer drives a full ScanTarball flow and records the body of
// POST /api/v1/ingest/scan.
func newScanBodyServer(t *testing.T) (*httptest.Server, func() map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var body []byte
	server := testutil.NewTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/api/v1/ingest/presigned-url"):
			scheme := testhelpers.SchemeFromRequest(r)
			testutil.JSONResponse(t, w, http.StatusOK, model.PresignedUploadResponse{
				ScanID: "scan-123", PresignedURL: scheme + "://" + r.Host + "/_s3/upload",
				Fields:         map[string]string{"key": "k", "policy": "p", "x-amz-signature": "s"},
				MaxUploadBytes: 2 << 30, ExpiresIn: 1800,
			})
		case strings.HasPrefix(r.URL.Path, "/_s3/"):
			testutil.AssertValidS3Upload(t, r)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/api/v1/ingest/scan"):
			data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			mu.Lock()
			body = data
			mu.Unlock()
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestUploadResponse{ScanID: "scan-123", ScanStatus: "INITIATED"})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/status"):
			testutil.JSONResponse(t, w, http.StatusOK, model.IngestStatusResponse{
				Data: []model.IngestStatusData{{ScanID: "scan-123", ScanStatus: "completed"}},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/normalized-results"):
			testutil.JSONResponse(t, w, http.StatusOK, model.NormalizedResultsResponse{
				Data: model.NormalizedResultsData{TenantID: "tenant-456"},
			})
		case strings.Contains(r.URL.Path, "/api/v1/ingest/results"):
			testutil.JSONResponse(t, w, http.StatusOK, api.ArtifactScanResultsResponse{ScanStatus: "COMPLETED", Results: map[string]string{}})
		default:
			t.Errorf("Unexpected request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return server, func() map[string]any {
		mu.Lock()
		defer mu.Unlock()
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode /scan body %s: %v", body, err)
		}
		return got
	}
}

func TestScanTarball_ImageRef(t *testing.T) {
	newScanner := func(t *testing.T, serverURL string, bom bool) *Scanner {
		t.Helper()
		httpClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second})
		uploadClient := httpclient.NewClient(httpclient.Config{Timeout: 5 * time.Second, DisableRetry: true})
		c, err := api.NewClient(serverURL, testutil.NewTestAuthProvider("token123"), false, 1*time.Minute,
			api.WithHTTPClient(httpClient), api.WithUploadHTTPClient(uploadClient), api.WithAllowLocalURLs(true))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		s := NewScanner(c, true, "tenant-456", 100, false, time.Minute, false).WithPollInterval(10 * time.Millisecond)
		if bom {
			s = s.WithSBOMVEXOptions(&scan.SBOMVEXOptions{BOM: &scan.BOMOptions{
				Types: []string{scan.BOMTypeCBOM}, Format: scan.BOMFormatCycloneDX17, Output: t.TempDir(),
			}})
		}
		return s
	}
	scanBody := func(t *testing.T, s *Scanner, tarball string, get func() map[string]any) map[string]any {
		t.Helper()
		var err error
		_ = testutil.CaptureStderr(t, func() { _, err = s.ScanTarball(context.Background(), tarball) })
		if err != nil {
			t.Fatalf("ScanTarball: %v", err)
		}
		return get()
	}

	t.Run("scan image by name sends the normalized reference", func(t *testing.T) {
		t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
		server, get := newScanBodyServer(t)
		s := newScanner(t, server.URL, true)
		// ScanImage stores the normalized name before it hands a temporary
		// tarball to ScanTarball, here for `scan image python:3.12-slim --bom cbom`.
		normalized, err := validateImageName("python:3.12-slim")
		if err != nil {
			t.Fatal(err)
		}
		s.displayName = normalized
		tarball := filepath.Join(t.TempDir(), "armis-image-123.tar")
		testhelpers.WriteMinimalTar(t, tarball)

		got := scanBody(t, s, tarball, get)
		if got["image_ref"] != "python:3.12-slim" {
			t.Errorf("image_ref = %v, want python:3.12-slim", got["image_ref"])
		}
		if types, _ := got["bom_types"].([]any); len(types) != 1 || types[0] != "cbom" {
			t.Errorf("bom_types = %v, want [cbom]", got["bom_types"])
		}
	})

	t.Run("--tarball sends the manifest tag", func(t *testing.T) {
		t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
		server, get := newScanBodyServer(t)
		tarball := writeImageTar(t, "app.tar", dockerSave("myorg/app:2.0"))
		got := scanBody(t, newScanner(t, server.URL, true), tarball, get)
		if got["image_ref"] != "myorg/app:2.0" {
			t.Errorf("image_ref = %v, want myorg/app:2.0", got["image_ref"])
		}
	})

	t.Run("--tarball without a tag sends no image_ref", func(t *testing.T) {
		t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
		server, get := newScanBodyServer(t)
		tarball := writeImageTar(t, "app.tar", dockerSave())
		got := scanBody(t, newScanner(t, server.URL, true), tarball, get)
		if _, ok := got["image_ref"]; ok {
			t.Errorf("image_ref = %v, want it omitted", got["image_ref"])
		}
	})

	t.Run("no image_ref without --bom", func(t *testing.T) {
		t.Setenv("ARMIS_HISTORY_DIR", t.TempDir())
		server, get := newScanBodyServer(t)
		tarball := writeImageTar(t, "app.tar", dockerSave("myorg/app:2.0"))
		got := scanBody(t, newScanner(t, server.URL, false), tarball, get)
		for _, key := range []string{"image_ref", "bom_types", "bom_format"} {
			if _, ok := got[key]; ok {
				t.Errorf("%s = %v, want it omitted without --bom", key, got[key])
			}
		}
	})
}
