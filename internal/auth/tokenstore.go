// Package auth provides authentication for the Armis API.
// This file persists OAuth2 (device-flow) tokens so they survive across
// invocations and can be shared with other Armis tools (the MCP plugins).
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// CROSS-PROCESS CONTRACT — DO NOT CHANGE THE PATH OR JSON SCHEMA CASUALLY.
//
// The token file and its JSON schema are a wire contract shared with other
// Armis developer tools (the armis-appsec / armis-knowledge MCP plugins, per
// epic PPSC-1032). Those tools read and write the SAME file so a single
// `armis-cli auth login` keeps every tool authenticated.
//
// A plain file (not the OS keychain) is the deliberate choice: the MCP plugins
// are Python, and the refresh-token rotation + reuse-detection on the backend
// requires a SINGLE source of truth (a divergent second store would replay a
// rotated token and get the whole token family revoked). The file is 0600 in a
// 0700 directory; protection at rest relies on the OS account + full-disk
// encryption (FileVault/BitLocker/LUKS), matching the AWS/gcloud/kubectl model.
//
// FILE SHAPE — a JSON array of per-environment entries, so one dev machine can
// hold tokens for several Armis environments at once (prod, dev, a local stack):
//
//	[
//	  {"env": "https://moose.armis.com", "token": { ...StoredToken... }},
//	  {"env": "http://localhost:8001",   "token": { ...StoredToken... }}
//	]
//
// `env` is the API base URL the token was obtained from (the lookup key).
// Python equivalent of the path: Path.home() / ".armis" / ".sessions".
// ---------------------------------------------------------------------------
const (
	// tokenStoreDirName is the per-user Armis config directory (~/.armis).
	tokenStoreDirName = ".armis"
	// tokenStoreFileName is the token file within that directory.
	tokenStoreFileName = ".sessions" // #nosec G101 -- filename, not a credential
	// tokenSchemaVersion versions the StoredToken JSON so future changes can be
	// detected by older readers rather than mis-parsed.
	tokenSchemaVersion = 1
	// maxTokenFileSize bounds reads to guard against a corrupted or maliciously
	// large file exhausting memory. Generous to accommodate many environments.
	maxTokenFileSize = 1 << 20 // 1MB
)

// StoredToken is the persisted result of a device-flow login. Its JSON shape is
// the cross-process contract described above; add fields rather than renaming.
type StoredToken struct {
	SchemaVersion int       `json:"schema_version"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	ExpiresAt     time.Time `json:"expires_at"`
	TenantID      string    `json:"tenant_id"`
	Subject       string    `json:"subject"`
	Role          string    `json:"role"`
	Issuer        string    `json:"issuer,omitempty"`
	Region        string    `json:"region,omitempty"`
	ClientID      string    `json:"client_id,omitempty"`
}

// tokenEntry is one environment's token within the file array.
type tokenEntry struct {
	Env   string       `json:"env"`
	Token *StoredToken `json:"token"`
}

// TokenStore persists OAuth tokens to a 0600 file under ~/.armis, keyed by the
// environment (API base URL) each token belongs to.
type TokenStore struct {
	// dir overrides the directory holding the token file (tests only). Empty
	// means ~/.armis.
	dir string
}

// NewTokenStore returns a TokenStore backed by the per-user ~/.armis directory.
func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

// normalizeEnv canonicalizes an environment key so trivially different spellings
// (a trailing slash, surrounding whitespace) resolve to the same entry.
func normalizeEnv(env string) string {
	return strings.TrimRight(strings.TrimSpace(env), "/")
}

// Save inserts or replaces the token for the given environment.
func (s *TokenStore) Save(env string, tok *StoredToken) error {
	if tok == nil {
		return errors.New("nil token")
	}
	if env == "" {
		return errors.New("env is required to store a token")
	}
	tok.SchemaVersion = tokenSchemaVersion
	env = normalizeEnv(env)

	entries, err := s.read()
	if err != nil {
		return err
	}

	replaced := false
	for i := range entries {
		if normalizeEnv(entries[i].Env) == env {
			entries[i].Token = tok
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, tokenEntry{Env: env, Token: tok})
	}
	return s.write(entries)
}

// Load returns the stored token for the given environment, or (nil, nil) when
// none is present. A corrupted or oversized file is treated as "no token" so a
// bad file never breaks credential resolution — callers fall through to env vars.
func (s *TokenStore) Load(env string) (*StoredToken, error) {
	env = normalizeEnv(env)
	entries, err := s.read()
	if err != nil {
		return nil, nil //nolint:nilerr // unreadable/corrupted file treated as absent
	}
	for i := range entries {
		if normalizeEnv(entries[i].Env) == env {
			tok := entries[i].Token
			if tok == nil || (tok.AccessToken == "" && tok.RefreshToken == "") {
				return nil, nil
			}
			return tok, nil
		}
	}
	return nil, nil
}

// Clear removes the token for the given environment. It is idempotent. When the
// last entry is removed the file itself is deleted.
func (s *TokenStore) Clear(env string) error {
	env = normalizeEnv(env)
	entries, err := s.read()
	if err != nil {
		return nil //nolint:nilerr // nothing usable to clear
	}
	kept := entries[:0]
	for _, e := range entries {
		if normalizeEnv(e.Env) != env {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		return s.remove()
	}
	return s.write(kept)
}

// ClearAll removes every stored token by deleting the file.
func (s *TokenStore) ClearAll() error {
	return s.remove()
}

// Environments lists the environments that currently have a stored token.
func (s *TokenStore) Environments() []string {
	entries, err := s.read()
	if err != nil {
		return nil
	}
	envs := make([]string, 0, len(entries))
	for _, e := range entries {
		envs = append(envs, e.Env)
	}
	return envs
}

// Path returns the resolved token-file path (for diagnostics / logout output).
func (s *TokenStore) Path() string {
	path, _ := s.filePath()
	return path
}

// read loads and parses the token file. A missing file yields an empty slice;
// a corrupted/oversized file yields an error so callers can decide how to react
// (Load/Clear treat it as absent rather than failing the CLI).
func (s *TokenStore) read() ([]tokenEntry, error) {
	path, err := s.filePath()
	if err != nil {
		return nil, err
	}
	// armis:ignore cwe:367 reason:stat-then-read race is benign; worst case reads a stale token, no security impact
	info, statErr := os.Stat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, statErr
	}
	if info.Size() > maxTokenFileSize {
		return nil, fmt.Errorf("token file %s exceeds %d bytes", path, maxTokenFileSize)
	}
	data, err := os.ReadFile(path) //nolint:gosec // path derived from os.UserHomeDir + hardcoded segments
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []tokenEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("token file is not valid JSON: %w", err)
	}
	return entries, nil
}

// write persists the entries to the 0600 file, creating ~/.armis (0700) if needed.
func (s *TokenStore) write(entries []tokenEntry) error {
	path, err := s.filePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ") //nolint:gosec // G117: persisting the token blob to its file IS the purpose of this store
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // path derived from os.UserHomeDir + hardcoded segments
		return fmt.Errorf("failed to write token file: %w", err)
	}
	return nil
}

func (s *TokenStore) remove() error {
	path, err := s.filePath()
	if err != nil {
		return nil //nolint:nilerr // nothing to remove if no path resolves
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// filePath resolves the token file path: <dir>/.sessions, where dir is
// the test override or ~/.armis.
func (s *TokenStore) filePath() (string, error) {
	dir := s.dir
	if dir == "" {
		// armis:ignore cwe:22 reason:os.UserHomeDir is a trusted OS source; joined with hardcoded path segments
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		dir = filepath.Join(home, tokenStoreDirName)
	}
	return filepath.Join(dir, tokenStoreFileName), nil
}
