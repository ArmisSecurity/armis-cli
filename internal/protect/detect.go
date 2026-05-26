package protect

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
		return nil, fmt.Errorf("no supported lockfile found in %s (supported: package-lock.json)", dir)
	}

	return detected, nil
}
