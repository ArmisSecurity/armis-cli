// Package scan provides shared utilities for scanning operations.
package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AllowedTarExtensions are the tarball extensions accepted by the server's
// /api/v1/ingest/presigned-url endpoint. Mirrors the server-side allowlist.
var AllowedTarExtensions = []string{".tar.gz", ".tgz", ".tar"}

// HasAllowedTarExtension reports whether filename ends in one of the allowed
// extensions. Comparison is case-insensitive. Order matters: the longer
// `.tar.gz` is checked before `.tar` so foo.tar.gz is not classified as plain
// tar.
func HasAllowedTarExtension(filename string) bool {
	lower := strings.ToLower(filename)
	for _, ext := range AllowedTarExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// ValidateTarballFormat checks that the file at `path` exists, is non-empty,
// has an allowed tar extension, and starts with the appropriate magic bytes.
//
// gzip magic:    0x1f 0x8b at offset 0
// POSIX/GNU tar: "ustar" at offset 257 (5 bytes), with possibly NUL or "00"
// after it
//
// We do NOT validate size against the upload cap here — that's done after the
// presigned-URL response so the cap can come from the server's policy.
func ValidateTarballFormat(path string) error {
	if path == "" {
		return errors.New("tarball path is empty")
	}
	if !HasAllowedTarExtension(filepath.Base(path)) {
		return fmt.Errorf(
			"file %q has an unsupported extension; expected one of %s",
			filepath.Base(path),
			strings.Join(AllowedTarExtensions, ", "),
		)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat tarball: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory, not a tarball", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("tarball %q is empty", filepath.Base(path))
	}

	// armis:ignore cwe:22 reason:caller is expected to sanitize the path; we only read
	f, err := os.Open(path) //nolint:gosec // G304: caller-sanitized path; only reads first 512 bytes
	if err != nil {
		return fmt.Errorf("failed to open tarball: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only

	// Read enough to check both gzip magic (offset 0) and tar `ustar` magic
	// (offset 257). 512 covers both with one read.
	header := make([]byte, 512)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("failed to read tarball header: %w", err)
	}
	header = header[:n]

	if isGzip(header) || isUstar(header) {
		return nil
	}
	return fmt.Errorf(
		"file %q is not a valid tar or tar.gz archive (header magic mismatch)",
		filepath.Base(path),
	)
}

// isGzip reports whether b starts with the gzip magic bytes.
func isGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// isUstar reports whether b carries the POSIX `ustar` magic at offset 257.
// The magic field is 6 bytes: "ustar\x00" (POSIX) or "ustar " (GNU). We accept
// either by matching the first 5 bytes.
func isUstar(b []byte) bool {
	const ustarOffset = 257
	if len(b) < ustarOffset+5 {
		return false
	}
	return string(b[ustarOffset:ustarOffset+5]) == "ustar"
}

// ValidateUploadSize compares the actual upload size against the server's
// policy cap (returned by /api/v1/ingest/presigned-url as max_upload_bytes).
// Returning the error before the multipart POST means the user gets a clear
// message instead of an opaque S3 EntityTooLarge response after a long upload.
func ValidateUploadSize(actual, serverMax int64) error {
	if serverMax <= 0 {
		// Server didn't advertise a cap; trust it and skip the local check.
		return nil
	}
	if actual > serverMax {
		return fmt.Errorf(
			"upload size %s exceeds server limit %s",
			FormatBytes(actual),
			FormatBytes(serverMax),
		)
	}
	return nil
}

// FormatBytes renders a byte count in IEC units (KiB/MiB/GiB) with one decimal
// place above 1 KiB. Used for human-readable size errors.
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KiB", "MiB", "GiB", "TiB"}[exp]
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffix)
}
