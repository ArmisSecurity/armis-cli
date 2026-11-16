package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRotateEnvCredentials(t *testing.T) {
	tests := []struct {
		name        string
		existing    *string
		mode        os.FileMode
		staleBak    bool
		id, secret  string
		want        CredentialRotation
		wantLines   []string
		wantMissing []string
	}{
		{
			name:      "changed values are replaced",
			existing:  ptr("ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=old-secret\n"),
			mode:      0o600,
			id:        "new-id",
			secret:    "new-secret",
			want:      CredentialsRotated,
			wantLines: []string{"ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
			wantMissing: []string{
				"old-id", "old-secret",
			},
		},
		{
			name:      "unchanged values are left alone",
			existing:  ptr("ARMIS_CLIENT_ID=same-id\nARMIS_CLIENT_SECRET=same-secret\n"),
			mode:      0o600,
			id:        "same-id",
			secret:    "same-secret",
			want:      CredentialsUnchanged,
			wantLines: []string{"ARMIS_CLIENT_ID=same-id", "ARMIS_CLIENT_SECRET=same-secret"},
		},
		{
			name:      "missing file is created",
			existing:  nil,
			id:        "new-id",
			secret:    "new-secret",
			want:      CredentialsWritten,
			wantLines: []string{"ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
		},
		{
			name:      "other keys and comments are kept",
			existing:  ptr("# proxy for the server\nHTTPS_PROXY=http://proxy:3128\nARMIS_CLIENT_ID=old-id\nSSL_CERT_FILE=/etc/ca.pem\nARMIS_CLIENT_SECRET=old-secret\n"),
			mode:      0o600,
			id:        "new-id",
			secret:    "new-secret",
			want:      CredentialsRotated,
			wantLines: []string{"# proxy for the server", "HTTPS_PROXY=http://proxy:3128", "SSL_CERT_FILE=/etc/ca.pem", "ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
		},
		{
			name:      "only the secret changed",
			existing:  ptr("ARMIS_CLIENT_ID=same-id\nARMIS_CLIENT_SECRET=old-secret\n"),
			mode:      0o600,
			id:        "same-id",
			secret:    "new-secret",
			want:      CredentialsRotated,
			wantLines: []string{"ARMIS_CLIENT_ID=same-id", "ARMIS_CLIENT_SECRET=new-secret"},
		},
		{
			name:      "a loose file mode is tightened to 0600",
			existing:  ptr("ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=old-secret\n"),
			mode:      0o644,
			id:        "new-id",
			secret:    "new-secret",
			want:      CredentialsRotated,
			wantLines: []string{"ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
		},
		{
			name:        "a backup from an earlier run is removed",
			existing:    ptr("ARMIS_CLIENT_ID=old-id\nARMIS_CLIENT_SECRET=old-secret\n"),
			mode:        0o600,
			staleBak:    true,
			id:          "new-id",
			secret:      "new-secret",
			want:        CredentialsRotated,
			wantLines:   []string{"ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
			wantMissing: []string{"old-secret"},
		},
		{
			name:      "credentials absent from an existing file are appended",
			existing:  ptr("HTTPS_PROXY=http://proxy:3128\n"),
			mode:      0o600,
			id:        "new-id",
			secret:    "new-secret",
			want:      CredentialsRotated,
			wantLines: []string{"HTTPS_PROXY=http://proxy:3128", "ARMIS_CLIENT_ID=new-id", "ARMIS_CLIENT_SECRET=new-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			envPath := filepath.Join(dir, "plugin", ".env")
			if err := os.MkdirAll(filepath.Dir(envPath), 0o750); err != nil {
				t.Fatal(err)
			}
			if tt.existing != nil {
				if err := os.WriteFile(envPath, []byte(*tt.existing), tt.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(envPath, tt.mode); err != nil {
					t.Fatal(err)
				}
			}
			if tt.staleBak {
				if err := os.WriteFile(envPath+".bak", []byte("ARMIS_CLIENT_SECRET=old-secret\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got, err := RotateEnvCredentials(envPath, tt.id, tt.secret)
			if err != nil {
				t.Fatalf("RotateEnvCredentials() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("outcome = %q, want %q", got, tt.want)
			}

			b, err := os.ReadFile(filepath.Clean(envPath))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) != len(tt.wantLines) {
				t.Errorf("file has %d lines, want %d:\n%s", len(lines), len(tt.wantLines), b)
			}
			for _, want := range tt.wantLines {
				if !containsLine(lines, want) {
					t.Errorf("file is missing line %q:\n%s", want, b)
				}
			}
			for _, bad := range tt.wantMissing {
				if strings.Contains(string(b), bad) {
					t.Errorf("file still contains %q:\n%s", bad, b)
				}
			}

			if _, err := os.Stat(envPath + ".bak"); !os.IsNotExist(err) {
				t.Errorf(".env.bak must not exist after rotation, stat err = %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(envPath))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != ".env" {
					t.Errorf("unexpected leftover file %q next to .env", e.Name())
				}
			}

			if runtime.GOOS != "windows" && got != CredentialsUnchanged {
				info, err := os.Stat(envPath)
				if err != nil {
					t.Fatal(err)
				}
				if perm := info.Mode().Perm(); perm != 0o600 {
					t.Errorf("file mode = %o, want 600", perm)
				}
			}
		})
	}
}

func TestRotateEnvCredentialsErrors(t *testing.T) {
	tests := []struct {
		name       string
		id, secret string
	}{
		{"empty id", "", "secret-value"},
		{"empty secret", "id-value", ""},
		{"newline in secret", "id-value", "line1\nline2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envPath := filepath.Join(t.TempDir(), ".env")
			_, err := RotateEnvCredentials(envPath, tt.id, tt.secret)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.secret != "" && strings.Contains(err.Error(), tt.secret) {
				t.Errorf("error leaks the secret: %v", err)
			}
			if _, statErr := os.Stat(envPath); !os.IsNotExist(statErr) {
				t.Errorf("no file should be written on error, stat err = %v", statErr)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}
