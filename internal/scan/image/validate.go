package image

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/distribution/reference"
)

// validImageNamePattern matches the allowlist of characters valid in Docker image references:
// alphanumeric, dots, hyphens, underscores, colons (tag separator), slashes (registry/path),
// and @ (digest separator).
var validImageNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._/:@-]+$`)

// maxImageNameLen is the maximum allowed length for a Docker image reference.
// Docker image names are typically under 256 characters; 1024 provides ample headroom.
const maxImageNameLen = 1024

func validateImageName(raw string) (string, error) {
	if len(raw) > maxImageNameLen {
		return "", fmt.Errorf("image name too long (%d bytes, max %d)", len(raw), maxImageNameLen)
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("image name contains illegal whitespace/control characters")
		}
	}
	if strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("image name may not start with '-'")
	}
	if !validImageNamePattern.MatchString(raw) {
		return "", fmt.Errorf("image name contains invalid characters: only alphanumeric, '.', '-', '_', '/', ':', '@' are allowed")
	}

	ref, err := reference.ParseNormalizedNamed(raw)
	if err != nil {
		return "", fmt.Errorf("invalid image name: %w", err)
	}

	ref = reference.TagNameOnly(ref)

	return reference.FamiliarString(ref), nil
}
