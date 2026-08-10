package install

import (
	"encoding/json"
	"testing"
)

func TestManifestKnowledgeRoundTrips(t *testing.T) {
	dir := t.TempDir()
	m := NewManifest(dir, "1.2.3")

	k := m.EnsureKnowledge("/home/u/.armis/plugins/armis-knowledge-mcp", "abc1234")
	k.AddEditor(EditorCursor, "/home/u/.cursor/mcp.json", "mcpServers")
	k.SetClaude("/home/u/.claude/plugins/cache/armis-knowledge/prod")
	k.SetCodex("/home/u/.codex/config.toml")

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	var got Manifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Knowledge == nil {
		t.Fatal("knowledge key lost in round-trip")
	}
	if got.Knowledge.SHA != "abc1234" {
		t.Errorf("SHA = %q, want abc1234", got.Knowledge.SHA)
	}
	if got.Knowledge.Editors[EditorCursor].ConfigFile != "/home/u/.cursor/mcp.json" {
		t.Errorf("cursor config file not recorded: %+v", got.Knowledge.Editors)
	}
	if got.Knowledge.Claude == nil || got.Knowledge.Codex == nil {
		t.Error("claude/codex knowledge entries not recorded")
	}
}

func TestManifestWithoutKnowledgeStillParses(t *testing.T) {
	// A manifest written before knowledge support must remain readable.
	const legacy = `{"schemaVersion":1,"installedAt":"2026-01-01T00:00:00Z",` +
		`"pluginVersion":"1.0.0","pluginDir":"/tmp/x","editors":{}}`

	var m Manifest
	if err := json.Unmarshal([]byte(legacy), &m); err != nil {
		t.Fatalf("legacy manifest failed to parse: %v", err)
	}
	if m.Knowledge != nil {
		t.Error("Knowledge should be nil for a legacy manifest")
	}
	if m.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", m.SchemaVersion)
	}
}
