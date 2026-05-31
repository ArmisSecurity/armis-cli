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
	EcosystemPip  Ecosystem = "pip"
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
		{"requirements.txt", EcosystemPip},
		{"requirements-lock.txt", EcosystemPip},
	}

	for _, c := range checks {
		path := filepath.Join(dir, c.file)
		if _, err := os.Stat(path); err == nil {
			detected = append(detected, DetectedEcosystem{
				Ecosystem:    c.ecosystem,
				LockfilePath: path,
			})
		}
	}

	if len(detected) == 0 {
		return nil, fmt.Errorf("no supported lockfile found in %s\n\n  Supported: package-lock.json, pnpm-lock.yaml, bun.lock, requirements.txt\n  Try:       armis-cli supply-chain check <path-to-project>\n  Or use:    --lockfile <path-to-lockfile>", dir)
	}

	return detected, nil
}
