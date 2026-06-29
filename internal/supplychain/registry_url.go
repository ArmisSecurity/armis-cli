package supplychain

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateRegistryURL validates a registry/artifactory URL read from
// .armis-supply-chain.yaml before it is used as the proxy's upstream or as the
// CI check's registry client.
//
// This is a SECURITY BOUNDARY, not a cosmetic check. Once registries.<ecosystem>
// is configurable, the committed config file becomes a trust boundary: a
// malicious PR could repoint the proxy at http://169.254.169.254/ (cloud IMDS)
// or an attacker-controlled host, and the proxy would faithfully forward the
// developer's injected credentials there (SSRF + credential exfiltration). The
// old "hardcoded trusted host" reasoning behind the cwe:918 suppressions in
// proxy.go and registry/*.go is FALSE the moment the upstream is configurable —
// this function is what restores that reasoning to "validated at config-load."
//
// Rules (all must hold):
//   - scheme must be https (no http, file, gopher, etc.) — credentials must
//     never traverse a plaintext hop, and non-http schemes are not registries.
//   - no embedded userinfo (https://user:pass@host) — credentials belong in the
//     PM's native config, never in the committed policy file, and userinfo here
//     would leak into lockfiles via NormalizeArtifact (see S3).
//   - the host must resolve to a routable public address: reject loopback,
//     RFC1918 private ranges, link-local (including 169.254.0.0/16, the cloud
//     metadata range), unique-local IPv6 (fc00::/7), and the unspecified
//     address. A literal IP is checked directly; a hostname's literal-IP forms
//     are rejected, but a DNS name is allowed (we cannot resolve it safely at
//     config-load without a TOCTOU window — the CheckRedirect and https
//     guarantees bound the residual risk, and an internal corporate registry
//     legitimately uses a private DNS name).
func ValidateRegistryURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("registry URL is empty")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL %q: %w", raw, err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("registry URL %q must use https:// (got %q) — credentials must not traverse a plaintext connection", raw, u.Scheme)
	}

	if u.User != nil {
		return nil, fmt.Errorf("registry URL %q must not embed credentials (user:pass@host) — put the token in your .npmrc/pip.conf, not the committed policy file", raw)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("registry URL %q has no host", raw)
	}

	// A literal IP is validated directly. A DNS name is allowed through (an
	// internal registry commonly uses a private name); we deliberately do not
	// resolve it here to avoid a TOCTOU between validation and use.
	// armis:ignore cwe:918 reason:the registry URL is read from the committed .armis-supply-chain.yaml (a code-review trust boundary, not runtime user input); literal non-routable IPs are rejected here, and a DNS name is allowed BY DESIGN because internal corporate registries legitimately run on private hostnames — resolving-and-rejecting-private-IPs would break that required use case and only open a TOCTOU window. Residual rebinding risk is bounded by the https requirement and the proxy's CheckRedirect (refuses any cross-host hop, S2).
	if ip := net.ParseIP(host); ip != nil {
		if err := rejectNonRoutableIP(ip); err != nil {
			return nil, fmt.Errorf("registry URL %q: %w", raw, err)
		}
	}

	return u, nil
}

// StripURLUserinfo returns origin with any embedded userinfo
// (https://user:tok@host) removed, preserving scheme, host, port, and path.
// It is applied to the upstream origin BEFORE it is handed to
// normalizeProxyResidue/NormalizeArtifact (S3): a `https://user:token@nexus/`
// config (rejected for registries.<eco>, but possible via an index-url-derived
// origin) must never be written into a lockfile as the rewrite target. On any
// parse failure it returns the input unchanged — the residue rewrite is
// best-effort and must not panic on a malformed origin.
func StripURLUserinfo(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.User == nil {
		return origin
	}
	u.User = nil
	return u.String()
}

// rejectNonRoutableIP returns an error when ip is in a range the registry
// upstream must never point at — loopback, private, link-local (cloud IMDS),
// unique-local, or unspecified. Centralized so the literal-IP path and any
// future resolved-IP path share one policy.
func rejectNonRoutableIP(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("loopback addresses (%s) are not allowed as a registry host", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("the unspecified address (%s) is not allowed as a registry host", ip)
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		// 169.254.0.0/16 (and fe80::/10) — includes the cloud metadata endpoint
		// 169.254.169.254, the canonical SSRF target.
		return fmt.Errorf("link-local addresses (%s) are not allowed as a registry host (cloud metadata SSRF range)", ip)
	case ip.IsPrivate():
		// RFC1918 (10/8, 172.16/12, 192.168/16) and IPv6 unique-local (fc00::/7).
		return fmt.Errorf("private addresses (%s) are not allowed as a registry host", ip)
	}
	return nil
}
