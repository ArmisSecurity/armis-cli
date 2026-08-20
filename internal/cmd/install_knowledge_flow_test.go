package cmd

import (
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func TestInstallKnowledgeForNoTargetsIsSkipped(t *testing.T) {
	// No agents selected means no network calls and no warnings — knowledge
	// simply has nothing to do.
	got := installKnowledgeFor(knowledgeTargets{}, false, nil)

	if !got.skipped {
		t.Error("expected skipped = true when no targets are selected")
	}
	if len(got.registered) != 0 {
		t.Errorf("expected no registrations, got %v", got.registered)
	}
	if len(got.warnings) != 0 {
		t.Errorf("expected no warnings, got %v", got.warnings)
	}
}

func TestKnowledgeTargetsHasWork(t *testing.T) {
	tests := []struct {
		name string
		tg   knowledgeTargets
		want bool
	}{
		{"empty", knowledgeTargets{}, false},
		{"claude only", knowledgeTargets{claude: true}, true},
		{"codex only", knowledgeTargets{codex: true}, true},
		{"one editor", knowledgeTargets{editors: []install.Editor{{ID: install.EditorCursor, Name: "Cursor"}}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tg.hasWork(); got != tt.want {
				t.Errorf("hasWork() = %v, want %v", got, tt.want)
			}
		})
	}
}
