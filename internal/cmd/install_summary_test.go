package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func TestPrintInstallSummary(t *testing.T) {
	vscode, _ := install.EditorByID(install.EditorVSCode)
	cursor, _ := install.EditorByID(install.EditorCursor)

	var buf bytes.Buffer
	printInstallSummary(&buf, installSummary{
		targets:   knowledgeTargets{editors: []install.Editor{vscode, cursor}, claude: true},
		knowledge: []string{"VS Code", "Claude Code"},
	})
	out := buf.String()

	for _, want := range []string{
		"VS Code", vscode.ConfigPath(),
		"Cursor", cursor.ConfigPath(),
		"armis-appsec, armis-knowledge",
		"separate server",
		"MCP: List Servers",
		"MCP servers in Copilot",
		"armis-cli mcp doctor",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	// Cursor didn't get knowledge, so its line must list the scanner alone.
	cursorBlock := out[strings.Index(out, "Cursor"):]
	cursorBlock = cursorBlock[:strings.Index(cursorBlock, "config:")]
	if strings.Contains(cursorBlock, serverKnowledge) {
		t.Errorf("Cursor block claims knowledge: %q", cursorBlock)
	}
}

func TestPrintInstallSummary_NoVSCodeNoCopilotNotes(t *testing.T) {
	cursor, _ := install.EditorByID(install.EditorCursor)
	var buf bytes.Buffer
	printInstallSummary(&buf, installSummary{targets: knowledgeTargets{editors: []install.Editor{cursor}}})
	if strings.Contains(buf.String(), "List Servers") {
		t.Errorf("VS Code instructions shown without VS Code:\n%s", buf.String())
	}
}

func TestPrintInstallSummary_NothingRegistered(t *testing.T) {
	var buf bytes.Buffer
	printInstallSummary(&buf, installSummary{})
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}
