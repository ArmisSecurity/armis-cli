//go:build windows

package output

import (
	"errors"
	"syscall"
)

// isSyncNotSupported returns true if the error indicates sync is not supported.
// On Windows, ENOTSUP is not defined, so we only check ENOTTY and EINVAL.
func isSyncNotSupported(err error) bool {
	return errors.Is(err, syscall.ENOTTY) ||
		errors.Is(err, syscall.EINVAL)
}
