package supplychain

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxNormalizeFileSize bounds how large an artifact NormalizeArtifact is
// willing to load and rewrite. Lockfiles in even very large monorepos are a
// few tens of MB; anything bigger is almost certainly not a lockfile and
// rewriting it wholesale in memory would be a misuse.
const maxNormalizeFileSize = 64 * 1024 * 1024

// NormalizeArtifact replaces every occurrence of proxyOrigin in the file at
// path with upstreamOrigin, reporting whether the file was modified.
//
// Some package managers persist the registry origin they were invoked with
// into durable artifacts: bun's `update` records full tarball URLs in
// bun.lock, `uv tool install` records index-url in its receipt, and older
// npm/yarn releases recorded the configured registry in resolved fields. The
// wrap proxy's origin is an ephemeral 127.0.0.1:<port> address that dies with
// the wrapper process, so any artifact it leaks into is corrupt — it breaks
// every install or upgrade that runs outside the wrapper (Docker builds, CI,
// teammates). Rewriting the origin back to the real upstream restores exactly
// the content an unwrapped run would have produced: the proxy reverse-proxies
// tarball and metadata paths to the upstream 1:1, so the URL paths are
// identical.
//
// The write is atomic (temp file + rename in the same directory, preserving
// the original permissions) so a crash mid-write can never leave a truncated
// lockfile. A missing file is not an error — the package manager simply did
// not write that artifact.
func NormalizeArtifact(path, proxyOrigin, upstreamOrigin string) (bool, error) {
	// A lockfile may itself be a symlink (Nix setups, monorepo link farms).
	// Rename-over-path would replace the symlink with a regular file and orphan
	// the target, so resolve to the real file first; the rename then lands on
	// the target and the link stays intact. EvalSymlinks errors on a missing
	// path, in which case the original is kept and the stat below reports it.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI rewriting the user's own lockfile/receipt; path comes from well-known lockfile names found in the user's project tree or the uv tools dir, not untrusted input crossing a trust boundary
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if info.Size() > maxNormalizeFileSize {
		return false, fmt.Errorf("%s is too large to normalize (%d bytes)", path, info.Size())
	}

	// armis:ignore cwe:22 cwe:23 cwe:73 reason:same path as the stat above; the read is size-bounded by the check preceding it
	data, err := os.ReadFile(path) //nolint:gosec // path is a well-known lockfile leaf in the user's own tree
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	if !bytes.Contains(data, []byte(proxyOrigin)) {
		return false, nil
	}

	updated := bytes.ReplaceAll(data, []byte(proxyOrigin), []byte(upstreamOrigin))

	// armis:ignore cwe:377 reason:standard safe atomic-replace idiom — os.CreateTemp generates a random name and opens O_EXCL (an attacker cannot predict or pre-seed it), and the temp lives in the target's own directory in the user's project tree (required for os.Rename to be atomic), not a shared tmp dir
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:same path as the stat/read sinks above — a well-known lockfile/receipt leaf discovered in the user's own project tree (FindEcosystemLockfile/FindUpward, now fail-closed on non-leaf names) or the uv tools dir, not untrusted input crossing a trust boundary; the temp file and rename target are both derived from that same path's own directory
	tmp, err := os.CreateTemp(filepath.Dir(path), ".armis-normalize-*")
	if err != nil {
		return false, fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()        //nolint:errcheck,gosec // best-effort cleanup on the error path
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup on the error path
	}
	if _, err := tmp.Write(updated); err != nil {
		cleanup()
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		cleanup()
		return false, fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup on the error path
		return false, fmt.Errorf("closing temp file for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// On Windows, Rename cannot atomically replace an existing destination —
		// it fails when path already exists. Remove the destination and retry, the
		// same workaround the plugin installer uses (internal/install/plugin.go).
		// On Unix, Rename already replaces atomically, so this branch never runs.
		//
		// The invariant through this dance is that at least one complete copy of
		// the content always exists — either the original at path or the rewritten
		// temp — so a failure can never leave the user with no lockfile:
		//   - If removing the destination fails, the original is untouched; clean
		//     up the temp and report, exactly as the non-Windows path does.
		//   - Once the destination is removed, the temp holds the only copy. If the
		//     retry rename then fails, we must NOT delete the temp — that would
		//     destroy the last copy. Leave it in place and point the user to it.
		if runtime.GOOS == goosWindows {
			if rmErr := os.Remove(path); rmErr != nil {
				os.Remove(tmpName) //nolint:errcheck,gosec // original is intact; safe to discard the temp
				return false, fmt.Errorf("replacing %s: %w", path, rmErr)
			}
			if retryErr := os.Rename(tmpName, path); retryErr != nil {
				// The original is already gone and the temp is the only surviving
				// copy of the rewritten content — keep it and name it so the user
				// can recover by moving it back into place.
				return false, fmt.Errorf("replacing %s failed after the original was removed; the rewritten content is preserved at %s — move it back manually: %w", path, tmpName, retryErr)
			}
			return true, nil
		}
		os.Remove(tmpName) //nolint:errcheck,gosec // best-effort cleanup on the error path
		return false, fmt.Errorf("replacing %s: %w", path, err)
	}
	return true, nil
}

// loopbackMarkers are URL fragments indicating a loopback-hosted registry
// reference in a lockfile or generated artifact.
var loopbackMarkers = []string{"://127.0.0.1:", "://localhost:", "://[::1]:"}

// DetectLoopbackRegistry reports whether the artifact at path references a
// loopback-hosted registry URL, returning the first host marker matched (e.g.
// "127.0.0.1"). The wrap's residue sweep can only remove the origin of the
// proxy instance that just ran; a wrapper killed mid-install leaves a stale
// port behind that no later run can recognize, and versions before the sweep
// existed left residue routinely. This lets `supply-chain check` flag such
// lockfiles in CI. A loopback reference may equally be a deliberate local
// registry (e.g. Verdaccio), which is why detection only ever warns.
func DetectLoopbackRegistry(path string) (string, bool) {
	for _, m := range loopbackMarkers {
		if FileContainsString(path, m) {
			return strings.Trim(m, ":/"), true
		}
	}
	return "", false
}

// FileContainsString reports whether the file at path contains needle. It is
// used for artifacts that cannot be safely rewritten in place — bun's legacy
// binary bun.lockb encodes lengths, so a text substitution would corrupt it —
// where the caller can only detect the residue and warn. Read errors and
// oversized files report false; this is a best-effort detection aid, never an
// enforcement decision.
func FileContainsString(path, needle string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxNormalizeFileSize {
		return false
	}
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI probing the user's own lockfile; path is a well-known lockfile leaf in the user's project tree and the read is size-bounded
	data, err := os.ReadFile(path) //nolint:gosec // path is a well-known lockfile leaf in the user's own tree
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(needle))
}
