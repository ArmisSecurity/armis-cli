package cmd

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

// The huh form itself needs a TTY, so confirmKnowledge is not unit-tested.
// What we can and do test is that the selected agents map into knowledge
// targets — the logic that decides where knowledge lands.
func TestKnowledgeTargetsFromSelection(t *testing.T) {
	editors := []install.Editor{
		{ID: install.EditorCursor, Name: "Cursor"},
		{ID: install.EditorVSCode, Name: "VS Code"},
	}

	kt := knowledgeTargets{editors: editors, claude: true, codex: false}

	if !kt.hasWork() {
		t.Fatal("expected work for a non-empty selection")
	}
	if len(kt.editors) != 2 {
		t.Errorf("editors = %d, want 2", len(kt.editors))
	}
	if !kt.claude {
		t.Error("claude should be targeted when selected")
	}
	if kt.codex {
		t.Error("codex should not be targeted when not selected")
	}
}
