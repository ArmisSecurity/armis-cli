package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArmisSecurity/armis-cli/internal/install"
)

func stagePlugin(t *testing.T, home string) string {
	t.Helper()
	pluginDir := filepath.Join(home, ".armis", "plugins", "armis-appsec-mcp")
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "server.py"), []byte("# server"), 0o600); err != nil {
		t.Fatal(err)
	}
	return pluginDir
}

func TestUninstallAllJSON(t *testing.T) {
	tests := []struct {
		name        string
		keepCreds   bool
		corruptFile bool
		wantClient  string
		wantDetail  string
		wantErr     string
	}{
		{name: "removes a registered client", wantClient: "ok", wantDetail: "removed"},
		{name: "keeps credentials when asked", keepCreds: true, wantClient: "ok", wantDetail: "removed"},
		{name: "reports a client that cannot be cleaned", corruptFile: true, wantClient: "fail", wantErr: "uninstall failed for: Cursor"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := throwawayHome(t)
			pluginDir := stagePlugin(t, home)

			cursor, _ := install.EditorByID(install.EditorCursor)
			if err := cursor.Register(pluginDir); err != nil {
				t.Fatal(err)
			}
			if tt.corruptFile {
				if err := os.WriteFile(cursor.ConfigPath(), []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			rep := newUninstallReport()
			var out bytes.Buffer
			var err error
			captureStderr(t, func() {
				err = uninstallAll(install.NewUninstaller(), tt.keepCreds, true, rep)
				err = finishUninstall(agentFormatJSON, &out, rep, err)
			})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("error = %v", err)
			case tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}

			doc := decodeReport(t, out.Bytes())
			c := clientByID(t, doc, "cursor")
			if c["status"] != tt.wantClient {
				t.Errorf("cursor = %v, want status %s", c, tt.wantClient)
			}
			if tt.wantDetail != "" && c["detail"] != tt.wantDetail {
				t.Errorf("detail = %v, want %s", c["detail"], tt.wantDetail)
			}
			if hook, _ := c["hook"].(map[string]interface{}); hook["status"] != "ok" {
				t.Errorf("cursor hook = %v, want status ok", c["hook"])
			}

			pf, _ := doc["plugin_files"].(map[string]interface{})
			if pf["status"] != "ok" || pf["credentials_kept"] != tt.keepCreds {
				t.Errorf("plugin_files = %v", pf)
			}
			if doc["knowledge"] != nil {
				t.Errorf("knowledge = %v, want null", doc["knowledge"])
			}
			pc, _ := doc["pre_commit"].(map[string]interface{})
			if pc == nil {
				t.Error("pre_commit should always be present")
			}
			if _, ok := doc["warnings"].([]interface{}); !ok {
				t.Errorf("warnings must be an array, got %v", doc["warnings"])
			}
		})
	}
}

func TestUninstallTargetsJSON(t *testing.T) {
	home := throwawayHome(t)
	pluginDir := stagePlugin(t, home)
	cursor, _ := install.EditorByID(install.EditorCursor)
	if err := cursor.Register(pluginDir); err != nil {
		t.Fatal(err)
	}

	rep := newUninstallReport()
	var out bytes.Buffer
	var err error
	captureStderr(t, func() {
		err = uninstallTargets(install.NewUninstaller(), []string{"cursor", "jetbrains", "aider", "nonexistent-editor"}, rep)
		err = finishUninstall(agentFormatJSON, &out, rep, err)
	})
	if err == nil || !strings.Contains(err.Error(), "nonexistent-editor") {
		t.Fatalf("error = %v, want one naming the failed target", err)
	}

	doc := decodeReport(t, out.Bytes())
	if doc["error"] != err.Error() {
		t.Errorf("error field = %v, want %q", doc["error"], err.Error())
	}
	for id, want := range map[string]string{
		"cursor":             "ok",
		"jetbrains":          "warn",
		"aider":              "skip",
		"nonexistent-editor": "fail",
	} {
		if got := clientByID(t, doc, id)["status"]; got != want {
			t.Errorf("%s status = %v, want %s", id, got, want)
		}
	}
	pf, _ := doc["plugin_files"].(map[string]interface{})
	if pf["status"] != "skip" || pf["credentials_kept"] != true {
		t.Errorf("plugin_files = %v", pf)
	}
}

func TestRunUninstallFormat(t *testing.T) {
	t.Run("rejects an unknown format", func(t *testing.T) {
		throwawayHome(t)
		if err := uninstallCmd.Flags().Set("format", "xml"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f := uninstallCmd.Flags().Lookup("format")
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
		if err := runUninstall(uninstallCmd, nil); err == nil {
			t.Error("expected an error for --format xml")
		}
	})

	for _, tt := range []struct {
		name    string
		force   bool
		wantErr string
		wantPF  interface{}
	}{
		{name: "json without --force removes nothing", wantErr: "pass --force to confirm"},
		{name: "json with --force skips the confirmation prompt", force: true, wantPF: "ok"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := throwawayHome(t)
			pluginDir := stagePlugin(t, home)
			for name, value := range map[string]string{"format": "json", "force": fmt.Sprint(tt.force)} {
				if err := uninstallCmd.Flags().Set(name, value); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					f := uninstallCmd.Flags().Lookup(name)
					_ = f.Value.Set(f.DefValue)
					f.Changed = false
				})
			}

			// An empty stdin would answer "no" if the prompt were shown.
			in, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_ = w.Close()
			oldStdin := os.Stdin
			os.Stdin = in
			t.Cleanup(func() { os.Stdin = oldStdin; _ = in.Close() })

			var runErr error
			raw := captureStdout(t, func() {
				captureStderr(t, func() { runErr = runUninstall(uninstallCmd, nil) })
			})

			doc := decodeReport(t, []byte(raw))
			pf, _ := doc["plugin_files"].(map[string]interface{})
			if tt.wantErr != "" {
				if runErr == nil || !strings.Contains(runErr.Error(), tt.wantErr) {
					t.Fatalf("runUninstall() error = %v, want %q", runErr, tt.wantErr)
				}
				if doc["error"] != runErr.Error() {
					t.Errorf("error field = %v, want %q", doc["error"], runErr.Error())
				}
				if _, statErr := os.Stat(pluginDir); statErr != nil {
					t.Errorf("plugin dir must be kept, stat err = %v", statErr)
				}
				return
			}
			if runErr != nil {
				t.Fatalf("runUninstall() error = %v", runErr)
			}
			if pf["status"] != tt.wantPF {
				t.Errorf("plugin_files = %v, want %v", pf, tt.wantPF)
			}
		})
	}
}
