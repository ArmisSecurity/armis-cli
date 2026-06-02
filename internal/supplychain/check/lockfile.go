package check

import (
	"fmt"
	"io"
	"os"
)

// maxLockfileSize bounds how much of a lockfile is read into memory. Real
// lockfiles for very large monorepos are a few tens of MB at most; 64MB leaves
// generous headroom while preventing a pathologically large (or malicious) file
// from exhausting memory when read in full.
const maxLockfileSize = 64 * 1024 * 1024

// readLockfile reads a lockfile from disk with a size cap. It is the single
// chokepoint every Parse*Lockfile function uses, so the size bound and the
// path-handling rationale live in exactly one place.
//
// The path is not sanitized for traversal on purpose: this is a local developer
// CLI auditing the user's own project, and the path arrives from lockfile
// auto-detection or an explicit --lockfile flag the user controls (e.g.
// "--lockfile ../sibling/package-lock.json"), not from an untrusted source
// crossing a trust boundary.
func readLockfile(path string) ([]byte, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	f, err := os.Open(path) //nolint:gosec // path from lockfile detection or explicit user flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	defer f.Close() //nolint:errcheck // best-effort close on read path

	// io.LimitReader caps the read at maxLockfileSize so a huge file cannot
	// exhaust memory (CWE-770).
	data, err := io.ReadAll(io.LimitReader(f, maxLockfileSize))
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	return data, nil
}
