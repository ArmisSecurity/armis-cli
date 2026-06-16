package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
)

type Ecosystem string

const (
	EcosystemNPM     Ecosystem = "npm"
	EcosystemPNPM    Ecosystem = "pnpm"
	EcosystemBun     Ecosystem = "bun"
	EcosystemYarn    Ecosystem = "yarn"
	EcosystemPip     Ecosystem = "pip"
	EcosystemPoetry  Ecosystem = "poetry"
	EcosystemPipfile Ecosystem = "pipfile"
	EcosystemPDM     Ecosystem = "pdm"
	EcosystemUV      Ecosystem = "uv"
	EcosystemMaven   Ecosystem = "maven"
	EcosystemGradle  Ecosystem = "gradle"
)

type DetectedEcosystem struct {
	Ecosystem    Ecosystem
	LockfilePath string
}

// lockfileCheck pairs a well-known lockfile leaf name with the ecosystem it
// indicates. canonical marks whether that name is unique enough to walk parent
// directories for: requirements.txt is not (pip requirements files have no fixed
// name or location), so it participates in directory detection but not the
// upward FindEcosystemLockfile walk.
type lockfileCheck struct {
	file      string
	ecosystem Ecosystem
	canonical bool
}

// lockfileChecks is the single source of truth for lockfile-name ↔ ecosystem
// mapping, in detection priority order. Both DetectEcosystems (stats each name in
// a directory) and ecosystemLockfileName (maps an ecosystem back to its canonical
// filename) derive from it, so a new ecosystem is added in exactly one place.
var lockfileChecks = []lockfileCheck{
	{"package-lock.json", EcosystemNPM, true},
	{"pnpm-lock.yaml", EcosystemPNPM, true},
	{"bun.lock", EcosystemBun, true},
	{"yarn.lock", EcosystemYarn, true},
	{"pom.xml", EcosystemMaven, true},
	{"gradle.lockfile", EcosystemGradle, true},
	{"poetry.lock", EcosystemPoetry, true},
	{"Pipfile.lock", EcosystemPipfile, true},
	{"pdm.lock", EcosystemPDM, true},
	{"uv.lock", EcosystemUV, true},
	{"requirements.txt", EcosystemPip, false},
}

// DetectEcosystems probes dir for well-known Node.js and Python lockfiles and
// reports which package-manager ecosystems are present. dir is the user's own
// scan target and each lockfile name is a constant literal leaf, so the joined
// paths can only resolve under dir; only os.Stat (an existence check) is
// performed on them.
func DetectEcosystems(dir string) ([]DetectedEcosystem, error) {
	var detected []DetectedEcosystem

	for _, c := range lockfileChecks {
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI probing the user's own project dir for well-known lockfile names; c.file is a constant literal and only os.Stat is performed, so the path is not externally controllable across a trust boundary
		path := filepath.Join(dir, c.file)
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:c.file is a constant literal lockfile name and only os.Stat (existence check) runs, so the path is not externally controllable across a trust boundary
		_, err := os.Stat(path)
		if err == nil {
			detected = append(detected, DetectedEcosystem{
				Ecosystem:    c.ecosystem,
				LockfilePath: path,
			})
			continue
		}
		// A missing lockfile is the common case and simply means "this ecosystem
		// is not present". Any other stat failure (permission denied, I/O error,
		// a non-directory path component) means the lockfile may well exist but
		// is unreachable — surface it so callers can distinguish "not present"
		// from "can't access" instead of silently reporting "no lockfile found".
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("checking for %s in %s: %w", c.file, dir, err)
		}
	}

	if len(detected) == 0 {
		return nil, fmt.Errorf("no supported lockfile found in %s\n\n  Supported: package-lock.json, pnpm-lock.yaml, bun.lock, yarn.lock,\n             pom.xml, gradle.lockfile, poetry.lock, Pipfile.lock,\n             pdm.lock, uv.lock, requirements.txt\n  Try:       armis-cli supply-chain check <path-to-project>\n  Or use:    --lockfile <path-to-lockfile>", dir)
	}

	return detected, nil
}

// FindEcosystemLockfile locates the lockfile for a specific ecosystem by walking
// up from startDir to the filesystem root, returning the path of the first match.
// Package managers like poetry/pdm/pipenv are routinely invoked from a project
// subdirectory while their lockfile lives at the project root (monorepos, CI
// steps that cd into a service dir), so probing only the current directory would
// silently skip enforcement. Mirrors FindConfigDir's upward walk. Returns "" when
// no lockfile is found, or when the ecosystem is unknown.
func FindEcosystemLockfile(startDir string, ecosystem Ecosystem) string {
	lockfileName := ecosystemLockfileName(ecosystem)
	if lockfileName == "" {
		return ""
	}
	return FindUpward(startDir, lockfileName)
}

// FindUpward walks up from startDir to the filesystem root probing each
// directory for filename, returning the first match or "" when none exists.
// filename must be a bare leaf name (a well-known lockfile or sibling artifact),
// and only os.Stat (an existence check) is performed on the joined paths.
//
// The bare-leaf contract is enforced fail-closed: a filename carrying a path
// separator, or "."/".."/"", returns "" without probing. Joining such a value
// onto each walked directory would let it climb out of the intended tree (e.g.
// "../../etc/passwd" or an absolute path that filepath.Join would not actually
// anchor under dir), so a caller that accidentally passes a path gets "no
// match" rather than a probe of somewhere unexpected.
func FindUpward(startDir, filename string) string {
	if filename == "" || filename == "." || filename == ".." || filepath.Base(filename) != filename {
		return ""
	}

	dir, err := filepath.Abs(startDir)
	if err != nil {
		dir = startDir
	}
	for {
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:filename is a constant literal lockfile leaf supplied by callers and only os.Stat (existence check) runs; the walked dirs are the user's own project tree, not externally controllable across a trust boundary
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// ecosystemLockfileName returns the canonical lockfile filename for an ecosystem,
// or "" if the ecosystem has no single well-known lockfile (e.g. pip, whose
// requirements files have no fixed name). Derived from lockfileChecks so the
// name lives in exactly one place.
func ecosystemLockfileName(ecosystem Ecosystem) string {
	for _, c := range lockfileChecks {
		if c.ecosystem == ecosystem && c.canonical {
			return c.file
		}
	}
	return ""
}
