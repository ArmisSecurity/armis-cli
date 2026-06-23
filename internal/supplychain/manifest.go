package supplychain

import (
	"encoding/json"
	"io"
	"os"
)

// maxManifestSize bounds the root manifest read so a pathological file cannot
// exhaust memory while we look up the direct-dependency set.
const maxManifestSize = 4 << 20 // 4 MB

// DirectDependencies returns the direct-dependency name set declared in the root
// manifest for an ecosystem, walking up from startDir to find the manifest
// (monorepo/CI-subdir friendly, mirroring FindEcosystemLockfile).
//
// The bool reports whether the direct set could be DETERMINED. This is the
// load-bearing distinction for the warn-on-transitive policy (WS5): a false
// return means "undeterminable", and the caller MUST fail safe by treating every
// package as direct (blocking young versions regardless of the warn policy). A
// true return with an empty slice means "determined: this project declares no
// direct deps", which is a meaningfully different state.
//
// Only the npm family (package.json) is supported for the direct/transitive
// split today; PyPI manifests are best-effort. An unsupported ecosystem returns
// (nil, false) so its caller fails safe.
func DirectDependencies(startDir string, ecosystem Ecosystem) ([]string, bool) {
	switch ecosystem {
	case EcosystemNPM, EcosystemPNPM, EcosystemBun, EcosystemYarn:
		return directDepsFromPackageJSON(startDir)
	default:
		// pip/uv and the pre-install ecosystems have no single reliable direct-set
		// manifest the proxy path consults; fail safe.
		return nil, false
	}
}

// packageJSONManifest is the subset of package.json fields that declare direct
// dependencies. All four maps are unioned into the direct set: peer and optional
// deps are still author-declared (direct), so a young version of one is the
// developer's own choice to block, not a transitive surprise.
type packageJSONManifest struct {
	Dependencies         map[string]json.RawMessage `json:"dependencies"`
	DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
	PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
	OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
}

// directDepsFromPackageJSON reads the nearest package.json (walking up from
// startDir) and returns the union of its declared dependency names. The bool is
// false — undeterminable, fail safe — when no package.json is found or it cannot
// be read/parsed; a present, parseable manifest with no deps returns
// ([]string{}, true).
func directDepsFromPackageJSON(startDir string) ([]string, bool) {
	path := FindUpward(startDir, "package.json")
	if path == "" {
		return nil, false
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:path is located by FindUpward stating a constant-literal "package.json" leaf within the user's own project tree (existence check only), not externally controllable across a trust boundary; the read is size-bounded below
	f, err := os.Open(path) //nolint:gosec // root manifest in the user's own project tree
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestSize))
	if err != nil {
		return nil, false
	}

	var m packageJSONManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}

	set := make(map[string]bool)
	for _, group := range []map[string]json.RawMessage{
		m.Dependencies, m.DevDependencies, m.PeerDependencies, m.OptionalDependencies,
	} {
		for name := range group {
			set[name] = true
		}
	}

	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	return names, true
}
