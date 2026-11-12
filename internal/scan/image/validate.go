package image

import (
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
