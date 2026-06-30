package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleToken() *StoredToken {
	return &StoredToken{
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
		TenantID:     "tenant-1",
		Subject:      "user@example.com",
		Role:         "admin",
		Issuer:       "https://moose.armis.com",
		Region:       "us1",
		ClientID:     "armis-cli",
	}
}

const (
	envProd = "https://moose.armis.com"
	envDev  = "http://localhost:8001"
)

func TestTokenStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := &TokenStore{dir: dir}

	want := sampleToken()
	if err := store.Save(envProd, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File should exist with 0600 perms in a 0700 dir.
	path := filepath.Join(dir, tokenStoreFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected token file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file perm = %o, want 600", perm)
	}

	got, err := store.Load(envProd)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil token")
	}
	if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken ||
		got.TenantID != want.TenantID || got.Subject != want.Subject {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
	if got.SchemaVersion != tokenSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, tokenSchemaVersion)
	}
}

// TestTokenStoreMultipleEnvironments is the core of the env-scoped design: two
// environments coexist, are read back independently, and clearing one leaves
// the other intact.
func TestTokenStoreMultipleEnvironments(t *testing.T) {
	store := &TokenStore{dir: t.TempDir()}

	prod := sampleToken()
	prod.TenantID = "tenant-prod"
	dev := sampleToken()
	dev.TenantID = "tenant-dev"
	dev.AccessToken = "dev-access"

	if err := store.Save(envProd, prod); err != nil {
		t.Fatalf("Save prod: %v", err)
	}
	if err := store.Save(envDev, dev); err != nil {
		t.Fatalf("Save dev: %v", err)
	}

	gotProd, _ := store.Load(envProd)
	gotDev, _ := store.Load(envDev)
	if gotProd == nil || gotProd.TenantID != "tenant-prod" {
		t.Errorf("prod token wrong: %+v", gotProd)
	}
	if gotDev == nil || gotDev.TenantID != "tenant-dev" || gotDev.AccessToken != "dev-access" {
		t.Errorf("dev token wrong: %+v", gotDev)
	}

	if envs := store.Environments(); len(envs) != 2 {
		t.Errorf("Environments() = %v, want 2 entries", envs)
	}

	// Clearing dev must not disturb prod.
	if err := store.Clear(envDev); err != nil {
		t.Fatalf("Clear dev: %v", err)
	}
	if got, _ := store.Load(envDev); got != nil {
		t.Errorf("dev should be cleared, got %+v", got)
	}
	if got, _ := store.Load(envProd); got == nil {
		t.Error("prod should survive clearing dev")
	}
}

// TestTokenStoreEnvNormalization: a trailing slash must resolve to the same entry.
func TestTokenStoreEnvNormalization(t *testing.T) {
	store := &TokenStore{dir: t.TempDir()}
	if err := store.Save(envProd+"/", sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, _ := store.Load(envProd)
	if got == nil {
		t.Error("trailing-slash env should resolve to the same entry")
	}
	// Saving the same env (no slash) replaces, not duplicates.
	if err := store.Save(envProd, sampleToken()); err != nil {
		t.Fatalf("Save again: %v", err)
	}
	if envs := store.Environments(); len(envs) != 1 {
		t.Errorf("expected 1 entry after re-save, got %v", envs)
	}
}

func TestTokenStoreSaveReplaces(t *testing.T) {
	store := &TokenStore{dir: t.TempDir()}
	first := sampleToken()
	first.AccessToken = "first"
	second := sampleToken()
	second.AccessToken = "second"

	_ = store.Save(envProd, first)
	_ = store.Save(envProd, second)

	got, _ := store.Load(envProd)
	if got == nil || got.AccessToken != "second" {
		t.Errorf("expected replacement, got %+v", got)
	}
	if envs := store.Environments(); len(envs) != 1 {
		t.Errorf("expected 1 entry, got %v", envs)
	}
}

func TestTokenStoreLoadEmpty(t *testing.T) {
	store := &TokenStore{dir: t.TempDir()}
	got, err := store.Load(envProd)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil token, got %+v", got)
	}
}

func TestTokenStoreClearLastRemovesFile(t *testing.T) {
	dir := t.TempDir()
	store := &TokenStore{dir: dir}
	if err := store.Save(envProd, sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Clear(envProd); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, _ := store.Load(envProd)
	if got != nil {
		t.Errorf("expected nil after Clear, got %+v", got)
	}
	// The file should be gone once the last entry is cleared.
	if _, err := os.Stat(filepath.Join(dir, tokenStoreFileName)); !os.IsNotExist(err) {
		t.Errorf("expected file removed after clearing last entry, stat err = %v", err)
	}
	// Clear is idempotent.
	if err := store.Clear(envProd); err != nil {
		t.Errorf("second Clear errored: %v", err)
	}
}

func TestTokenStoreCorruptedFileTreatedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	store := &TokenStore{dir: dir}
	if err := os.WriteFile(filepath.Join(dir, tokenStoreFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(envProd)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for corrupted file, got %+v", got)
	}
}
