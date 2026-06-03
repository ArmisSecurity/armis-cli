package supplychain

import (
	"fmt"
	"os"
	"path/filepath"
)

type Ecosystem string

const (
	EcosystemNPM  Ecosystem = "npm"
	EcosystemPNPM Ecosystem = "pnpm"
	EcosystemBun  Ecosystem = "bun"
	EcosystemYarn Ecosystem = "yarn"
)

type DetectedEcosystem struct {
	Ecosystem    Ecosystem
	LockfilePath string
}

func DetectEcosystems(dir string) ([]DetectedEcosystem, error) {
	var detected []DetectedEcosystem

	checks := []struct {
		file      string
		ecosystem Ecosystem
	}{
		{"package-lock.json", EcosystemNPM},
		{"pnpm-lock.yaml", EcosystemPNPM},
		{"bun.lock", EcosystemBun},
		{"yarn.lock", EcosystemYarn},
	}

	for _, c := range checks {
		path := filepath.Join(dir, c.file)
		// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI probing the user's own project dir for well-known lockfile names; dir is a user-supplied scan target, c.file is a hardcoded literal, and only os.Stat (existence check) is performed
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
		return nil, fmt.Errorf("no supported lockfile found in %s\n\n  Supported: package-lock.json, pnpm-lock.yaml, bun.lock, yarn.lock\n  Try:       armis-cli supply-chain check <path-to-project>\n  Or use:    --lockfile <path-to-lockfile>", dir)
	}

	return detected, nil
}
