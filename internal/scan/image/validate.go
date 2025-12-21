package image

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/distribution/reference"
)

func validateImageName(raw string) (string, error) {
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("image name contains illegal whitespace/control characters")
		}
	}
	if strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("image name may not start with '-'")
	}

	ref, err := reference.ParseNormalizedNamed(raw)
	if err != nil {
		return "", fmt.Errorf("invalid image name: %w", err)
	}

	ref = reference.TagNameOnly(ref)

	return reference.FamiliarString(ref), nil
}
