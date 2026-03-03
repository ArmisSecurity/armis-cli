//go:build !windows

package output

import (
	"errors"
	"syscall"
)

// isSyncNotSupported returns true if the error indicates sync is not supported.
// This is common for pipes, sockets, and /dev/stdout which don't support fsync.
func isSyncNotSupported(err error) bool {
	return errors.Is(err, syscall.ENOTTY) || // "inappropriate ioctl for device"
		errors.Is(err, syscall.EINVAL) || // "invalid argument"
		errors.Is(err, syscall.ENOTSUP) // "operation not supported"
}
