package agentdetect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resolvedTempDir returns a temp directory with symlinks resolved.
// On macOS, t.TempDir() returns /var/folders/... which is a symlink to /private/var/folders/...
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", dir, err)
	}
	return resolved
}

func TestScanner_Scan(t *testing.T) {
	home := t.TempDir()
	mustMkdirAll(t, filepath.Join(home, ".claude"))
	mustMkdirAll(t, filepath.Join(home, ".cursor"))

	p := &mockPlatform{
		users:           []UserHome{{Username: "alice", HomeDir: home}},
		vsCodeExtDir:    filepath.Join(home, ".vscode", "extensions"),
		vsCodeConfigDir: filepath.Join(home, ".config", "Code", "User"),
	}

	scanner := NewScanner(p)
	result, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(result.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(result.Users))
	}
	if result.Users[0].User != "alice" {
		t.Errorf("expected user alice, got %s", result.Users[0].User)
	}

	agentNames := make(map[string]bool)
	for _, a := range result.Users[0].Agents {
		agentNames[a.Name] = true
	}
	if !agentNames["ClaudeCode"] {
		t.Error("expected ClaudeCode to be detected")
	}
	if !agentNames["Cursor"] {
		t.Error("expected Cursor to be detected")
	}
}

func TestScanner_Scan_NoAgents(t *testing.T) {
	home := t.TempDir()
	p := &mockPlatform{
		users:        []UserHome{{Username: "bob", HomeDir: home}},
		vsCodeExtDir: filepath.Join(home, ".vscode", "extensions"),
	}
	scanner := NewScanner(p)
	result, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Users) != 0 {
		t.Errorf("expected 0 users with agents, got %d", len(result.Users))
	}
}

func TestScanner_Scan_MultipleUsers(t *testing.T) {
	home1 := t.TempDir()
	home2 := t.TempDir()
	mustMkdirAll(t, filepath.Join(home1, ".claude"))
	mustMkdirAll(t, filepath.Join(home2, ".cursor"))

	p := &mockPlatform{
		users: []UserHome{
			{Username: "alice", HomeDir: home1},
			{Username: "bob", HomeDir: home2},
		},
		vsCodeExtDir:    "/nonexistent",
		vsCodeConfigDir: "/nonexistent",
	}

	scanner := NewScanner(p)
	result, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(result.Users))
	}
}

func TestScanResult_FlatResults(t *testing.T) {
	result := &ScanResult{
		Users: []UserResult{
			{
				User: "alice",
				Agents: []DetectedAgent{
					{Name: "ClaudeCode", User: "alice"},
					{Name: "Cursor", User: "alice"},
				},
			},
			{
				User: "bob",
				Agents: []DetectedAgent{
					{Name: "Copilot", User: "bob"},
				},
			},
		},
	}
	flat := result.FlatResults()
	if len(flat) != 3 {
		t.Errorf("expected 3 flat results, got %d", len(flat))
	}
}

func TestFormatPlain(t *testing.T) {
	result := &ScanResult{
		Users: []UserResult{
			{
				User: "John",
				Agents: []DetectedAgent{
					{Name: "ClaudeCode", MCPInstalled: true, User: "John"},
					{Name: "Cursor", MCPInstalled: false, User: "John"},
				},
			},
			{
				User: "Jack",
				Agents: []DetectedAgent{
					{Name: "Copilot", MCPInstalled: false, User: "Jack"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := FormatPlain(result, &buf); err != nil {
		t.Fatalf("FormatPlain() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "user: John") {
		t.Error("expected 'user: John' in output")
	}
	if !strings.Contains(output, "ClaudeCode(MCP:true), Cursor(MCP:false)") {
		t.Errorf("unexpected agent line, got:\n%s", output)
	}
	if !strings.Contains(output, "user: Jack") {
		t.Error("expected 'user: Jack' in output")
	}
	if !strings.Contains(output, "Copilot(MCP:false)") {
		t.Error("expected 'Copilot(MCP:false)' in output")
	}
}

func TestFormatPlain_Empty(t *testing.T) {
	result := &ScanResult{}
	var buf bytes.Buffer
	if err := FormatPlain(result, &buf); err != nil {
		t.Fatalf("FormatPlain() error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestFormatJSON(t *testing.T) {
	result := &ScanResult{
		Users: []UserResult{
			{
				User: "John",
				Agents: []DetectedAgent{
					{Name: "ClaudeCode", MCPInstalled: true, User: "John"},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := FormatJSON(result, &buf); err != nil {
		t.Fatalf("FormatJSON() error: %v", err)
	}

	var agents []DetectedAgent
	if err := json.Unmarshal(buf.Bytes(), &agents); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name != "ClaudeCode" {
		t.Errorf("expected ClaudeCode, got %s", agents[0].Name)
	}
	if !agents[0].MCPInstalled {
		t.Error("expected MCPInstalled to be true")
	}
}

func TestFormatJSON_Empty(t *testing.T) {
	result := &ScanResult{}
	var buf bytes.Buffer
	if err := FormatJSON(result, &buf); err != nil {
		t.Fatalf("FormatJSON() error: %v", err)
	}

	var agents []DetectedAgent
	if err := json.Unmarshal(buf.Bytes(), &agents); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected empty array, got %d agents", len(agents))
	}
}
