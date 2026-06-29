package cmd

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArmisSecurity/armis-cli/internal/cli"
	"github.com/ArmisSecurity/armis-cli/internal/output"
	"github.com/ArmisSecurity/armis-cli/internal/supplychain"
	"github.com/ArmisSecurity/armis-cli/internal/util"
)

// envRegistryCABundle overrides the config's registry-ca-bundle for the
// proxy→upstream TLS leg (S6), mirroring how ARMIS_API_URL overrides the API
// base. A minimal CI runner can point at its corporate CA without editing the
// committed policy file.
const envRegistryCABundle = "ARMIS_REGISTRY_CA_BUNDLE"

// registrySettings is the resolved, proxy-ready view of the registries config
// for one ecosystem. Configured is false on the default public path (no
// registries entry for this ecosystem), in which case the other fields are
// zero and the proxy behaves exactly as before this feature.
type registrySettings struct {
	Configured   bool   // an approved registry is set for this ecosystem
	ApprovedURL  string // the registries.<eco> value (for warnings/dry-run)
	UpstreamURL  string // == ApprovedURL; the proxy upstream
	AuthHeader   string // "Bearer <tok>" / "Basic <b64>", or "" if none found
	CABundlePath string // resolved CA bundle path (env over config), or ""
	Enforcement  string // routing-enforcement posture ("warn" or "")
	authFound    bool   // a credential was located (for dry-run reporting)
}

// resolveRegistrySettings reads the supply-chain config (searched upward from
// the current directory) and resolves the approved registry + credentials for
// the given canonical package manager. It returns a zero-value
// registrySettings{Configured:false} on any of: no config, no registries entry
// for this ecosystem, or an audit-path ecosystem that is not routable in v1.
//
// A credential-resolution error (e.g. an unset ${VAR} in the .npmrc token, or a
// resolved token failing the safe charset) is returned as an error — it must
// fail loudly rather than silently produce an unauthenticated proxy that 401s
// with a confusing message.
func resolveRegistrySettings(canonicalPMName string) (registrySettings, error) {
	eco := pmToEcosystem(canonicalPMName)
	if eco == "" {
		return registrySettings{}, nil
	}

	cfg, configDir, err := loadConfigUpward(".")
	if err != nil || cfg == nil {
		// A load error here is non-fatal for routing: resolveWrapPolicy already
		// fails safe to the default policy, and an absent/unreadable config simply
		// means "no custom registry." Surface nothing; stay on the public path.
		return registrySettings{}, nil //nolint:nilerr // absent/invalid config → public path, by design
	}

	approved := cfg.RegistryURLFor(eco)
	if approved == "" {
		return registrySettings{}, nil
	}

	// The URL was validated at config-load (LoadConfig → validate). Parse it here
	// for credential lookup; a parse failure at this point would be a logic error
	// rather than user input, but handle it defensively.
	upstreamURL, err := url.Parse(approved)
	if err != nil {
		return registrySettings{}, fmt.Errorf("parsing approved registry URL: %w", err)
	}

	rs := registrySettings{
		Configured:   true,
		ApprovedURL:  approved,
		UpstreamURL:  approved,
		Enforcement:  cfg.RegistryEnforcement,
		CABundlePath: resolveCABundlePath(cfg),
	}

	authHeader, found, err := resolveUpstreamAuth(eco, configDir, upstreamURL)
	if err != nil {
		return registrySettings{}, err
	}
	rs.AuthHeader = authHeader
	rs.authFound = found

	return rs, nil
}

// resolveUpstreamAuth builds the Authorization header for the upstream from the
// developer's NATIVE package-manager config (never from the committed policy
// file, which is validated to carry no credentials):
//
//   - npm family: the .npmrc _authToken (host- and host+path-scoped), forwarded
//     as "Bearer <token>".
//   - pip/uv: credentials embedded in the developer's index-url env
//     (PIP_INDEX_URL / UV_INDEX_URL), forwarded as "Basic <base64(user:pass)>".
//
// Returns ("", false, nil) when no credential is configured (a valid no-auth
// state for a public-mirror repo), and an error when a credential is present
// but unusable.
func resolveUpstreamAuth(eco supplychain.Ecosystem, configDir string, upstreamURL *url.URL) (string, bool, error) {
	switch eco {
	case supplychain.EcosystemNPM, supplychain.EcosystemPNPM, supplychain.EcosystemBun, supplychain.EcosystemYarn:
		// Read the project .npmrc from the config directory (the project root) and
		// the user ~/.npmrc; project wins.
		dir := configDir
		if dir == "" {
			dir = "."
		}
		token, ok, err := supplychain.ReadNpmrcAuthToken(dir, upstreamURL)
		if err != nil {
			return "", false, err
		}
		if !ok {
			return "", false, nil
		}
		return "Bearer " + token, true, nil

	case supplychain.EcosystemPip:
		return basicAuthFromIndexURL(os.Getenv("PIP_INDEX_URL"))
	case supplychain.EcosystemUV:
		// uv honors UV_INDEX_URL; fall back to PIP_INDEX_URL which uv also reads.
		if v := os.Getenv("UV_INDEX_URL"); v != "" {
			return basicAuthFromIndexURL(v)
		}
		return basicAuthFromIndexURL(os.Getenv("PIP_INDEX_URL"))
	default:
		return "", false, nil
	}
}

// basicAuthFromIndexURL extracts userinfo from a pip/uv index URL and renders an
// HTTP Basic Authorization header value. It returns ("", false, nil) when the
// URL is empty or carries no userinfo.
func basicAuthFromIndexURL(rawIndexURL string) (string, bool, error) {
	if rawIndexURL == "" {
		return "", false, nil
	}
	cred, ok, err := supplychain.IndexURLBasicAuth(rawIndexURL)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred)), true, nil
}

// resolveCABundlePath returns the CA bundle path for the proxy→upstream TLS leg,
// preferring the ARMIS_REGISTRY_CA_BUNDLE env var over the config field so a
// per-runner override works without editing the committed policy.
func resolveCABundlePath(cfg *supplychain.Config) string {
	if v := os.Getenv(envRegistryCABundle); v != "" {
		return v
	}
	if cfg != nil {
		return cfg.RegistryCABundle
	}
	return ""
}

// runWrapDryRun prints the resolved registry configuration for pmName and
// returns without running the package manager (DX6). It is the platform
// engineer's fastest "did I configure this right?" check.
func runWrapDryRun(pmName string) error {
	rs, err := resolveRegistrySettings(canonicalPM(pmName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain (dry-run): credential error: %v\n", err)
		return nil
	}
	printWrapDryRun(pmName, rs)
	return nil
}

// printWrapDryRun renders the dry-run report to stderr (all wrap output goes to
// stderr per project convention; nothing is written to stdout).
func printWrapDryRun(pmName string, rs registrySettings) {
	s := output.GetStyles()
	fmt.Fprintf(os.Stderr, "%s supply-chain wrap dry-run for %s\n", s.MutedText.Render(scPrefix), s.Bold.Render(pmName))

	if !rs.Configured {
		fmt.Fprintf(os.Stderr, "  %s no approved registry configured for this ecosystem — installs use the public registry\n",
			s.MutedText.Render("Registry:"))
		return
	}

	fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Approved registry:"), s.Bold.Render(rs.ApprovedURL))

	authState := s.WarningText.Render("not found (private packages may 401)")
	if rs.authFound {
		authState = s.SuccessText.Render("found")
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Credentials:     "), authState)

	enforcement := rs.Enforcement
	if enforcement == "" {
		enforcement = "off (no routing warning)"
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("Routing warning: "), enforcement)

	if rs.CABundlePath != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", s.MutedText.Render("CA bundle:       "), rs.CABundlePath)
	}

	fmt.Fprintf(os.Stderr, "  %s\n",
		s.MutedText.Render("Publish timestamps: probed at install time; if absent, age enforcement degrades to `supply-chain check` in CI."))
}

// effectiveRegistryHost resolves the registry host the developer's environment
// would have used ABSENT the wrapper, returning ("", false) when it cannot be
// determined from an EXPLICIT source. "Explicit" is the operative word (DX1):
// only an env var the developer set (npm_config_registry / PIP_INDEX_URL /
// UV_INDEX_URL) or an explicit `registry=` in their .npmrc counts. A silent
// default to the public registry is NOT explicit and returns ("", false) — so
// the off-policy warning never fires on the common hybrid Nexus setup, which
// was the self-defeating-warning failure mode the DX review flagged.
//
// Returns the lowercased host (with port) of the effective registry.
func effectiveRegistryHost(canonicalPMName string) (string, bool) {
	eco := pmToEcosystem(canonicalPMName)
	switch eco {
	case supplychain.EcosystemNPM, supplychain.EcosystemPNPM, supplychain.EcosystemBun, supplychain.EcosystemYarn:
		if v := os.Getenv("npm_config_registry"); v != "" {
			return urlHost(v)
		}
		// Explicit registry= in the project .npmrc (NOT a scoped @x:registry=,
		// which v1 does not compare — see the design's scoped-registry exclusion).
		if host, ok := npmrcDefaultRegistryHost("."); ok {
			return host, true
		}
	case supplychain.EcosystemPip:
		if v := os.Getenv("PIP_INDEX_URL"); v != "" {
			return urlHost(v)
		}
	case supplychain.EcosystemUV:
		if v := os.Getenv("UV_INDEX_URL"); v != "" {
			return urlHost(v)
		}
		if v := os.Getenv("PIP_INDEX_URL"); v != "" {
			return urlHost(v)
		}
	}
	return "", false
}

// urlHost parses raw and returns its lowercased host, or ("", false) on failure
// or when no host is present.
func urlHost(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	return strings.ToLower(u.Host), true
}

// npmrcDefaultRegistryHost reads the project .npmrc in dir and returns the host
// of an explicit default `registry=` line, if present. Scoped registry keys
// (@scope:registry=) are intentionally ignored (out of v1 scope).
func npmrcDefaultRegistryHost(dir string) (string, bool) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:reading the developer's own project .npmrc to compare their configured registry against the approved one; the path is a fixed ".npmrc" leaf in the project dir, not untrusted input crossing a trust boundary
	data, err := os.ReadFile(filepath.Join(dir, ".npmrc")) //nolint:gosec // developer's own project .npmrc
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Match the bare "registry=" key only — not "@scope:registry=" and not
		// "//host/:_authToken=". A scoped key contains ':' before '='.
		if after, ok := strings.CutPrefix(line, "registry="); ok {
			return urlHost(strings.TrimSpace(after))
		}
	}
	return "", false
}

// maybeWarnOffPolicyRegistry prints the soft routing warning when the
// developer's EXPLICIT effective registry host differs from the approved one
// (DX1). It is gated three ways to avoid the self-defeating-warning trap:
//   - only an explicit off-policy choice triggers it (effectiveRegistryHost
//     returns ok only for an explicit env/config source);
//   - it is rate-limited to once per shell session via a marker file (reusing
//     the shouldShowRationale marker pattern);
//   - it fires only when registry-enforcement is "warn" (the configured posture);
//   - the footer shows the FIX (set your registry to the approved one), never
//     ARMIS_SUPPLY_CHAIN=off — that would train devs toward disabling ALL
//     enforcement, including age.
func maybeWarnOffPolicyRegistry(canonicalPMName, approvedURL string) {
	cfg, _, err := loadConfigUpward(".")
	if err != nil || cfg == nil || cfg.RegistryEnforcement != "warn" {
		return
	}

	effHost, ok := effectiveRegistryHost(canonicalPMName)
	if !ok {
		return // no EXPLICIT effective registry → not a trigger (silent default is fine)
	}

	approvedHost, ok := urlHost(approvedURL)
	if !ok || effHost == approvedHost {
		return // matches approved (or unparseable) → nothing to warn about
	}

	if !shouldShowRegistryWarning() {
		return // already shown this session
	}

	s := output.GetStyles()
	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		s.MutedText.Render(scPrefix),
		s.WarningText.Render(fmt.Sprintf("supply-chain: your %s registry (%s) is not the approved registry", canonicalPMName, effHost)))
	fmt.Fprintf(os.Stderr, "  %s %s\n",
		s.MutedText.Render("Fix:"),
		s.Bold.Render(fmt.Sprintf("set your registry to %s", approvedURL)))
	markRegistryWarningShown()
}

// registryWarningMarkerFile records that the once-per-session off-policy
// registry warning has been shown, mirroring rationaleMarkerFile.
const registryWarningMarkerFile = "supply-chain-registry-warned"

// shouldShowRegistryWarning reports whether to print the off-policy registry
// warning: on an interactive terminal and not already shown this session.
// Mirrors shouldShowRationale so CI/piped output stays terse.
func shouldShowRegistryWarning() bool {
	if !cli.IsInteractive() {
		return false
	}
	path := util.GetCacheFilePath(registryWarningMarkerFile)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err != nil
}

// markRegistryWarningShown creates the once-per-session marker. Best-effort: any
// failure is ignored so a marker-write error never blocks an install.
func markRegistryWarningShown() {
	dir := util.GetCacheDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := util.GetCacheFilePath(registryWarningMarkerFile)
	if path == "" {
		return
	}
	_ = os.WriteFile(path, []byte("1"), 0o600)
}
