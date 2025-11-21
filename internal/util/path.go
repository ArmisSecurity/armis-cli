package util

import (
	"errors"
	"path/filepath"
	"strings"
)

func SanitizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}

	cleaned := filepath.Clean(p)

	if cleaned == "." || cleaned == "" {
		return "", errors.New("invalid path")
	}

	if strings.Contains(cleaned, "..") {
		return "", errors.New("path traversal detected")
	}

	return cleaned, nil
}
