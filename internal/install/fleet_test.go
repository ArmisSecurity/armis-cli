package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeAllAgents creates a config-file parent directory for every supported
// editor under a temp HOME, which is exactly what Editor.IsDetected() looks
// for. Returns the per-editor config paths it wired up.
//
// This lets the fleet tests below cover all ~15 editors on a machine where only
// two or three are actually installed — detection is directory-presence based,
// so faking the directory is faithful to the real check rather than stubbing it.
func fakeAllAgents(t *testing.T) map[EditorID]string {
	t.Helper()

	home := t.TempDir()
	paths := make(map[EditorID]string)

	overrides := make(map[EditorID]string)
	for _, e := range AllEditors {
		// Mirror each editor's real relative layout under the fake HOME so the
		// path shapes stay realistic (nested dirs, per-editor filenames).
		real := defaultConfigPath(e.ID)
		if real == "" {
			continue // not supported on this platform (e.g. Zed on Windows)
		}
		cfg := filepath.Join(home, string(e.ID), filepath.Base(real))
		if err := os.MkdirAll(filepath.Dir(cfg), 0o750); err != nil {
			t.Fatal(err)
		}
		overrides[e.ID] = cfg
		paths[e.ID] = cfg
	}

	configPathOverrides = overrides
	t.Cleanup(func() { configPathOverrides = nil })

	return paths
}

func TestDetectedEditorsFindsEveryAgentWhenAllPresent(t *testing.T) {
	paths := fakeAllAgents(t)

	detected := make(map[EditorID]bool)
	for _, e := range DetectedEditors() {
		detected[e.ID] = true
	}

	for id := range paths {
		if !detected[id] {
			t.Errorf("%s was not detected despite its config directory existing", id)
		}
	}
	if len(detected) != len(paths) {
		t.Errorf("detected %d editors, want %d", len(detected), len(paths))
	}
}

// TestFleetRegistersBothProductsInEveryAgent is the full-fleet coexistence
// check: with every supported editor present, registering the scanner and then
// knowledge must leave BOTH servers in every editor's config, in that editor's
// own format.
//
// Registration is driven directly rather than through the install command
// because KnowledgeMCPInstaller.Fetch performs a network call — CI must not
// depend on GitHub being reachable.
func TestFleetRegistersBothProductsInEveryAgent(t *testing.T) {
	paths := fakeAllAgents(t)

	scannerDir := filepath.Join(t.TempDir(), "armis-appsec-mcp")
	knowledgeDir := filepath.Join(t.TempDir(), "armis-knowledge-mcp")
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvProd, pluginDir: knowledgeDir}

	for id := range paths {
		e, ok := EditorByID(id)
		if !ok {
			t.Fatalf("EditorByID(%s) not found", id)
		}
		if err := e.Register(scannerDir); err != nil {
			t.Errorf("scanner Register(%s): %v", id, err)
			continue
		}
		if err := ki.RegisterEditor(e); err != nil {
			t.Errorf("knowledge RegisterEditor(%s): %v", id, err)
		}
	}

	for id, cfg := range paths {
		t.Run(string(id), func(t *testing.T) {
			b, err := os.ReadFile(filepath.Clean(cfg))
			if err != nil {
				t.Fatalf("reading %s config: %v", id, err)
			}
			var data map[string]interface{}
			if err := json.Unmarshal(b, &data); err != nil {
				t.Fatalf("%s config is not valid JSON: %v\n%s", id, err, b)
			}

			// Each editor family nests its servers under a different key.
			var key string
			switch ConfigFormat(id) {
			case "vscode-servers":
				key = "servers"
			case "zed-context_servers":
				key = "context_servers"
			default:
				key = "mcpServers"
			}

			servers, ok := data[key].(map[string]interface{})
			if !ok {
				t.Fatalf("%s: %q object missing, got: %s", id, key, b)
			}
			if servers[mcpServerName] == nil {
				t.Errorf("%s: scanner entry %q missing", id, mcpServerName)
			}
			if servers[ki.ServerName()] == nil {
				t.Errorf("%s: knowledge entry %q missing", id, ki.ServerName())
			}
		})
	}
}

// TestFleetUninstallRemovesKnowledgeEverywhere verifies the reverse direction
// across the whole fleet: removing knowledge must clear its entry from every
// editor while leaving the scanner's entry intact.
func TestFleetUninstallRemovesKnowledgeEverywhere(t *testing.T) {
	paths := fakeAllAgents(t)

	scannerDir := filepath.Join(t.TempDir(), "armis-appsec-mcp")
	knowledgeDir := filepath.Join(t.TempDir(), "armis-knowledge-mcp")
	if err := os.MkdirAll(knowledgeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	ki := &KnowledgeMCPInstaller{env: KnowledgeEnvProd, pluginDir: knowledgeDir}

	m := NewManifest(scannerDir, "1.0.0")
	k := m.EnsureKnowledge(knowledgeDir, "abc1234")

	for id, cfg := range paths {
		e, _ := EditorByID(id)
		if err := e.Register(scannerDir); err != nil {
			t.Fatalf("scanner Register(%s): %v", id, err)
		}
		if err := ki.RegisterEditor(e); err != nil {
			t.Fatalf("knowledge RegisterEditor(%s): %v", id, err)
		}
		k.AddEditor(id, cfg, ConfigFormat(id))
	}

	u := &Uninstaller{pluginDir: scannerDir, manifest: m}
	removed, warnings := u.RemoveKnowledge(false)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings removing knowledge: %v", warnings)
	}
	if len(removed) != len(paths) {
		t.Errorf("removed %d editors, want %d", len(removed), len(paths))
	}

	for id, cfg := range paths {
		t.Run(string(id), func(t *testing.T) {
			b, err := os.ReadFile(filepath.Clean(cfg))
			if err != nil {
				t.Fatalf("reading %s config: %v", id, err)
			}
			var data map[string]interface{}
			if err := json.Unmarshal(b, &data); err != nil {
				t.Fatalf("%s config is not valid JSON after removal: %v", id, err)
			}

			var key string
			switch ConfigFormat(id) {
			case "vscode-servers":
				key = "servers"
			case "zed-context_servers":
				key = "context_servers"
			default:
				key = "mcpServers"
			}

			servers, ok := data[key].(map[string]interface{})
			if !ok {
				t.Fatalf("%s: %q object missing after removal, got: %s", id, key, b)
			}
			if servers[ki.ServerName()] != nil {
				t.Errorf("%s: knowledge entry survived removal", id)
			}
			if servers[mcpServerName] == nil {
				t.Errorf("%s: scanner entry was lost during knowledge removal", id)
			}
		})
	}
}
