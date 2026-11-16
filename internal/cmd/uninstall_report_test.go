package cmd

import (
	"bytes"
	"os"
	"path/filepath"
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
	}{
		{name: "removes a registered client", wantClient: "ok", wantDetail: "removed"},
		{name: "keeps credentials when asked", keepCreds: true, wantClient: "ok", wantDetail: "removed"},
		{name: "reports a client that cannot be cleaned", corruptFile: true, wantClient: "fail"},
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
				err = finishUninstall(formatJSON, &out, rep, err)
			})
			if err != nil {
				t.Fatalf("error = %v", err)
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
		err = finishUninstall(formatJSON, &out, rep, err)
	})
	if err != nil {
		t.Fatalf("error = %v", err)
	}

	doc := decodeReport(t, out.Bytes())
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

	t.Run("json skips the confirmation prompt", func(t *testing.T) {
		home := throwawayHome(t)
		stagePlugin(t, home)
		if err := uninstallCmd.Flags().Set("format", "json"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			f := uninstallCmd.Flags().Lookup("format")
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})

		// An empty stdin would answer "no" if the prompt were shown.
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		oldStdin := os.Stdin
		os.Stdin = in
		t.Cleanup(func() { os.Stdin = oldStdin; _ = in.Close() })

		out, outW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = outW
		t.Cleanup(func() { os.Stdout = oldStdout })

		var runErr error
		captureStderr(t, func() { runErr = runUninstall(uninstallCmd, nil) })
		_ = outW.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(out)
		_ = out.Close()

		if runErr != nil {
			t.Fatalf("runUninstall() error = %v", runErr)
		}
		doc := decodeReport(t, buf.Bytes())
		pf, _ := doc["plugin_files"].(map[string]interface{})
		if pf["status"] != "ok" {
			t.Errorf("plugin_files = %v, want ok (prompt must be skipped)", pf)
		}
	})
}
