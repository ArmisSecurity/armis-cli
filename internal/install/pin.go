package install

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// EnvMCPVersion pins the scanner plugin to one release when set.
const EnvMCPVersion = "ARMIS_MCP_VERSION"

// PinLatest is the explicit request to drop a pin and follow the latest release.
const PinLatest = "latest"

var pinPattern = regexp.MustCompile(`^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$`)

var (
	pinMu       sync.RWMutex
	pinOverride *string
)

// NormalizePin validates a requested plugin version and returns it without a
// leading "v". "" and "latest" are returned as "" and "latest" respectively.
func NormalizePin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == PinLatest {
		return raw, nil
	}
	m := pinPattern.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("invalid plugin version %q: expected something like 1.4.2 or v1.4.2", raw)
	}
	return m[1], nil
}

// SetVersionPin records an explicit plugin version request for this process,
// overriding ARMIS_MCP_VERSION and the pin stored in the manifest. An empty
// raw value clears the override. "latest" drops the pin.
func SetVersionPin(raw string) error {
	pinMu.Lock()
	defer pinMu.Unlock()
	if strings.TrimSpace(raw) == "" {
		pinOverride = nil
		return nil
	}
	v, err := NormalizePin(raw)
	if err != nil {
		return err
	}
	pinOverride = &v
	return nil
}

// requestedPin returns the pin asked for in this invocation (flag, then
// environment). set is false when the caller asked for nothing; a "latest"
// request comes back as set with an empty pin.
func requestedPin() (pin string, set bool) {
	pinMu.RLock()
	o := pinOverride
	pinMu.RUnlock()
	if o != nil {
		if *o == PinLatest {
			return "", true
		}
		return *o, true
	}
	v, err := NormalizePin(os.Getenv(EnvMCPVersion))
	if err != nil || v == "" {
		return "", false
	}
	if v == PinLatest {
		return "", true
	}
	return v, true
}

// EffectivePin returns the plugin version the installer must stay on: the
// version requested in this invocation, otherwise the pin saved in the manifest.
func EffectivePin() string {
	if pin, set := requestedPin(); set {
		return pin
	}
	if m := ReadManifest(defaultPluginDir()); m != nil {
		return m.PinnedVersion
	}
	return ""
}

// ValidatePinEnv reports an invalid ARMIS_MCP_VERSION, which requestedPin
// would otherwise ignore silently.
func ValidatePinEnv() error {
	if _, err := NormalizePin(os.Getenv(EnvMCPVersion)); err != nil {
		return fmt.Errorf("%s: %w", EnvMCPVersion, err)
	}
	return nil
}

func defaultPluginDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
}

// applyRequestedPin stores the pin requested in this invocation in the
// manifest, so later `mcp update` and `mcp doctor --fix` runs keep it.
func (m *Manifest) applyRequestedPin() {
	if pin, set := requestedPin(); set {
		m.PinnedVersion = pin
	}
}
