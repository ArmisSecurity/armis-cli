package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasAllowedTarExtension(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"foo.tar.gz", true},
		{"foo.TAR.GZ", true},
		{"foo.tgz", true},
		{"foo.tar", true},
		{"foo.zip", false},
		{"foo", false},
		{"foo.tar.bz2", false},
		{"foo.tar.gzip", false},
		{".tar.gz", true}, // hidden file with valid ext
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasAllowedTarExtension(tt.name); got != tt.want {
				t.Errorf("HasAllowedTarExtension(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// makeGzipTar writes a minimal valid gzipped tar archive with one entry to path.
func makeGzipTar(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	body := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Size: int64(len(body)), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

// makePlainTar writes a valid plain (uncompressed) tar archive with one entry.
func makePlainTar(t *testing.T, path string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("hello")
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Size: int64(len(body)), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTarballFormat(t *testing.T) {
	tmp := t.TempDir()

	gzipped := filepath.Join(tmp, "good.tar.gz")
	makeGzipTar(t, gzipped)

	plain := filepath.Join(tmp, "good.tar")
	makePlainTar(t, plain)

	tgz := filepath.Join(tmp, "good.tgz")
	makeGzipTar(t, tgz)

	notTar := filepath.Join(tmp, "fake.tar.gz")
	if err := os.WriteFile(notTar, []byte("PK\x03\x04not really a zip but not gzip either"), 0600); err != nil {
		t.Fatal(err)
	}

	emptyFile := filepath.Join(tmp, "empty.tar.gz")
	if err := os.WriteFile(emptyFile, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	wrongExt := filepath.Join(tmp, "img.zip")
	makeGzipTar(t, wrongExt) // valid gzip body, wrong extension

	dir := filepath.Join(tmp, "adir.tar.gz")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		wantErr   bool
		errSubstr string
	}{
		{"empty path", "", true, "empty"},
		{"gzipped tar", gzipped, false, ""},
		{"plain tar", plain, false, ""},
		{"tgz", tgz, false, ""},
		{"missing file", filepath.Join(tmp, "missing.tar.gz"), true, "stat"},
		{"not a tar", notTar, true, "magic"},
		{"empty file", emptyFile, true, "empty"},
		{"unsupported extension", wrongExt, true, "unsupported"},
		{"directory", dir, true, "directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTarballFormat(tt.path)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestValidateUploadSize(t *testing.T) {
	tests := []struct {
		name      string
		actual    int64
		serverMax int64
		wantErr   bool
	}{
		{"under cap", 1_000_000, 2_000_000, false},
		{"at cap", 2_000_000, 2_000_000, false},
		{"over cap", 3_000_000, 2_000_000, true},
		{"server cap unset", 5_000_000_000, 0, false},
		{"negative server cap (invalid input ignored)", 1_000, -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUploadSize(tt.actual, tt.serverMax)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{int64(2.5 * 1024 * 1024), "2.5 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := FormatBytes(tt.n); got != tt.want {
				t.Fatalf("FormatBytes(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}
