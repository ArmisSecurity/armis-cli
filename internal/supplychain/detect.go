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
		{"pom.xml", EcosystemMaven},
		{"gradle.lockfile", EcosystemGradle},
		{"poetry.lock", EcosystemPoetry},
		{"Pipfile.lock", EcosystemPipfile},
		{"pdm.lock", EcosystemPDM},
		{"uv.lock", EcosystemUV},
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
		return nil, fmt.Errorf("no supported lockfile found in %s\n\n  Supported: package-lock.json, pnpm-lock.yaml, bun.lock, yarn.lock,\n             pom.xml, gradle.lockfile, poetry.lock, Pipfile.lock,\n             pdm.lock, uv.lock, requirements.txt\n  Try:       armis-cli supply-chain check <path-to-project>\n  Or use:    --lockfile <path-to-lockfile>", dir)
	}

	return detected, nil
}
