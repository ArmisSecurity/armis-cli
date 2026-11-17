package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/distribution/reference"
)

// IsImageReference reports whether raw is a container image reference that
// `scan image` would accept (for example "nginx:1.27"). A filesystem path such
// as `C:\code\app` is not one.
func IsImageReference(raw string) bool {
	_, err := validateImageName(raw)
	return err == nil
}

func validateImageName(raw string) (string, error) {
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("image name contains illegal whitespace/control characters")
		}
	}
	if strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("image name may not start with '-'")
	}

	// armis:ignore cwe:20 reason:ParseNormalizedNamed IS the input validation; rejects invalid image names
	ref, err := reference.ParseNormalizedNamed(raw)
	if err != nil {
		return "", fmt.Errorf("invalid image name: %w", err)
	}

	ref = reference.TagNameOnly(ref)

	return reference.FamiliarString(ref), nil
}

// maxArtifactNameLength caps imageArtifactName, so the longest file name built
// from it, <name>-bom-sbom.spdx.json, stays well under the usual 255-byte
// limit. A valid reference can be far longer.
const maxArtifactNameLength = 100

// imageArtifactName returns the start of the output file names for an image
// scanned by name: the last path component of the repository, and the tag
// when one was given, such as app-1.2 for ghcr.io/org/app:1.2. A digest is
// left out, so python@sha256:... gives python. A name over
// maxArtifactNameLength bytes is cut and ends in "-" and the first 8 hex
// characters of the SHA-256 of the whole name, so it stays stable and
// distinct. The result has no path separator. It returns "" for a name that
// does not parse.
func imageArtifactName(typed string) string {
	// armis:ignore cwe:20 reason:ParseNormalizedNamed IS the input validation; rejects invalid image names
	ref, err := reference.ParseNormalizedNamed(typed)
	if err != nil {
		return ""
	}
	repoPath := reference.Path(ref)
	name := repoPath[strings.LastIndex(repoPath, "/")+1:]
	if tagged, ok := ref.(reference.Tagged); ok {
		name += "-" + tagged.Tag()
	}
	if len(name) > maxArtifactNameLength {
		// Reference names and tags are ASCII, so a byte cut is safe.
		sum := sha256.Sum256([]byte(name))
		name = name[:maxArtifactNameLength-9] + "-" + hex.EncodeToString(sum[:4])
	}
	return name
}
