package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
)

// maxManifestSize caps the manifest.json read from a --tarball. A docker
// save manifest is a few hundred bytes per image.
const maxManifestSize = 1 << 20

// maxImageRefLength is the server's cap on image_ref; a longer value would
// fail the whole ingest request with 422, so it is not sent.
const maxImageRefLength = 512

// imageRefField returns ref when it fits the image_ref cap, else "".
func imageRefField(ref string) string {
	if len(ref) > maxImageRefLength {
		return ""
	}
	return ref
}

// tarballImageRef returns the image reference of a docker save tarball: the
// first RepoTags entry of its top-level manifest.json, normalized by
// validateImageName. No other file is read. It returns "" when the tarball
// has no manifest.json (such as an OCI layout), the manifest is over
// maxManifestSize or not valid, or the tag is rejected.
func tarballImageRef(ctx context.Context, path string) string {
	// armis:ignore cwe:22 reason:path was sanitized by util.SanitizePath in ScanTarball; read-only
	f, err := os.Open(path) //nolint:gosec // G304: caller-sanitized path, read-only
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck // read-only

	var r io.Reader = f
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return ""
		}
		defer gz.Close() //nolint:errcheck // read-only
		// Bound the decompressed bytes walked to the image size limit.
		r = io.LimitReader(gz, MaxImageSize)
	}

	tr := tar.NewReader(r)
	for {
		if ctx.Err() != nil {
			return ""
		}
		hdr, err := tr.Next()
		if err != nil {
			return ""
		}
		if hdr.Typeflag != tar.TypeReg || strings.TrimPrefix(hdr.Name, "./") != "manifest.json" {
			continue
		}
		if hdr.Size > maxManifestSize {
			return ""
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxManifestSize+1))
		if err != nil || len(data) > maxManifestSize {
			return ""
		}
		return firstRepoTag(data)
	}
}

// firstRepoTag returns the first RepoTags entry of a docker save manifest,
// normalized, or "" when there is none or validateImageName rejects it.
func firstRepoTag(manifest []byte) string {
	var entries []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(manifest, &entries); err != nil {
		return ""
	}
	for _, entry := range entries {
		if len(entry.RepoTags) == 0 {
			continue
		}
		ref, err := validateImageName(entry.RepoTags[0])
		if err != nil {
			return ""
		}
		return imageRefField(ref)
	}
	return ""
}
