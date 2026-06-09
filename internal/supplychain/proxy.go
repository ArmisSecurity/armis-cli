package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultUpstreamRegistry = "https://registry.npmjs.org"
	defaultPyPIIndex        = "https://pypi.org"
	maxProxyResponseSize    = 20 * 1024 * 1024
	distTagLatest           = "latest"

	// npmTimeKeyCreated and npmTimeKeyModified are metadata-only keys in the npm
	// registry's "time" object that record when the package was first published
	// and last modified. They are not version strings and must be skipped when
	// iterating over the version→timestamp map.
	npmTimeKeyCreated  = "created"
	npmTimeKeyModified = "modified"

	// pypiSimpleJSONAccept is the PEP 691 content type for the PyPI Simple API
	// JSON representation. The default Simple API response is HTML (PEP 503),
	// which carries no upload timestamps; only the JSON form exposes the PEP 700
	// per-file "upload-time" field the age filter needs, so the proxy must send
	// this Accept header upstream to obtain timestamps at all.
	pypiSimpleJSONAccept = "application/vnd.pypi.simple.v1+json"
)

// ProxyMode selects the upstream registry protocol the proxy speaks. The npm
// registry and the PyPI Simple API are entirely different shapes (one JSON blob
// with a version→time map vs. a per-file distribution index), so metadata
// detection and age filtering differ by mode.
type ProxyMode int

const (
	// ModeNPM filters the npm registry's package metadata document.
	ModeNPM ProxyMode = iota
	// ModePyPI filters the PyPI Simple API (PEP 691/700 JSON) file index.
	ModePyPI
)

type BlockedPackage struct {
	Name    string
	Version string
	Age     time.Duration
}

type InstalledPackage struct {
	Name    string
	Version string
}

type Proxy struct {
	policy       Policy
	mode         ProxyMode
	upstreamURL  *url.URL
	httpClient   *http.Client
	revProxy     *httputil.ReverseProxy
	listener     net.Listener
	server       *http.Server
	blocked      []BlockedPackage
	blockedMu    sync.Mutex
	allowed      map[string]string // package name → latest allowed version
	allowedMu    sync.Mutex
	checked      int
	checkedMu    sync.Mutex
	skipPackages map[string]bool
}

type ProxyConfig struct {
	Policy       Policy
	Mode         ProxyMode
	UpstreamURL  string
	SkipPackages []string
}

func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	upstream := cfg.UpstreamURL
	if upstream == "" {
		// Default the upstream to match the mode so a PyPI proxy constructed with
		// only a Mode (the common case) still points at pypi.org rather than the
		// npm registry.
		if cfg.Mode == ModePyPI {
			upstream = defaultPyPIIndex
		} else {
			upstream = defaultUpstreamRegistry
		}
	}

	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	skipSet := make(map[string]bool, len(cfg.SkipPackages))
	for _, pkg := range cfg.SkipPackages {
		skipSet[pkg] = true
	}

	// NewSingleHostReverseProxy rewrites the request URL's scheme/host but
	// deliberately does NOT rewrite the Host header (see its doc comment). Left
	// as-is, tarball passthrough requests reach the upstream registry carrying
	// the local proxy's Host (e.g. "127.0.0.1:61396"). registry.npmjs.org is
	// fronted by a CDN that routes on Host, so an unknown value returns 403 —
	// the metadata check passes but the actual .tgz download fails. Wrap the
	// Director to point Host at the upstream registry so passthrough works.
	revProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	baseDirector := revProxy.Director
	revProxy.Director = func(req *http.Request) {
		baseDirector(req)
		req.Host = upstreamURL.Host
	}

	return &Proxy{
		policy:      cfg.Policy,
		mode:        cfg.Mode,
		upstreamURL: upstreamURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		revProxy:     revProxy,
		skipPackages: skipSet,
		allowed:      make(map[string]string),
	}, nil
}

func (p *Proxy) Start(ctx context.Context) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("binding listener: %w", err)
	}
	p.listener = listener

	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	p.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		p.server.Close() //nolint:errcheck,gosec // shutdown on context cancel
	}()

	go p.server.Serve(listener) //nolint:errcheck // server shutdown handled via context

	return listener.Addr().String(), nil
}

func (p *Proxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

func (p *Proxy) Blocked() []BlockedPackage {
	p.blockedMu.Lock()
	defer p.blockedMu.Unlock()
	result := make([]BlockedPackage, len(p.blocked))
	copy(result, p.blocked)
	return result
}

func (p *Proxy) Checked() int {
	p.checkedMu.Lock()
	defer p.checkedMu.Unlock()
	return p.checked
}

func (p *Proxy) Allowed() []InstalledPackage {
	p.allowedMu.Lock()
	defer p.allowedMu.Unlock()
	result := make([]InstalledPackage, 0, len(p.allowed))
	for name, version := range p.allowed {
		result = append(result, InstalledPackage{Name: name, Version: version})
	}
	return result
}

func (p *Proxy) Close() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	var pkgName string
	var isMetadata bool
	if p.mode == ModePyPI {
		pkgName = extractPyPIPackageNameFromPath(r.URL.Path)
		isMetadata = isPyPIMetadataRequest(r.URL.Path)
	} else {
		pkgName = extractPackageNameFromPath(r.URL.Path)
		isMetadata = isMetadataRequest(r.URL.Path)
	}

	if pkgName == "" || r.Method != http.MethodGet || !isMetadata {
		p.reverseProxy(w, r)
		return
	}

	if p.skipPackages[pkgName] || p.policy.IsExcluded(pkgName) {
		p.reverseProxy(w, r)
		return
	}

	p.checkedMu.Lock()
	p.checked++
	p.checkedMu.Unlock()

	p.handleMetadataFiltering(w, r, pkgName)
}

func (p *Proxy) handleMetadataFiltering(w http.ResponseWriter, r *http.Request, pkgName string) {
	// Use RequestURI() (escaped path + raw query) rather than just Path so the
	// filtered branch is symmetric with the reverse-proxy passthrough: query
	// params (e.g. ?write=true) and path-escaping nuances reach the upstream.
	// armis:ignore cwe:918 reason:p.upstreamURL is a startup-configured trusted host (defaults to registry.npmjs.org); r.URL.RequestURI() is the path/query from the local proxy client and cannot change the host
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.upstreamURL.String()+r.URL.RequestURI(), nil) //nolint:gosec // upstream URL is configured at startup, path is from local proxy
	if err != nil {
		http.Error(w, fmt.Sprintf("[armis] supply-chain: failed to create request for %s", pkgName), http.StatusBadGateway)
		return
	}
	if p.mode == ModePyPI {
		// Request the PEP 691 JSON form so the response carries PEP 700 per-file
		// upload-time fields; the default Simple API HTML has no timestamps.
		upstreamReq.Header.Set("Accept", pypiSimpleJSONAccept)
	} else {
		upstreamReq.Header.Set("Accept", "application/json")
	}

	// armis:ignore cwe:918 reason:p.upstreamURL is a startup-configured trusted host (defaults to registry.npmjs.org); the request host is not attacker-controlled
	resp, err := p.httpClient.Do(upstreamReq) //nolint:gosec // URL constructed from trusted upstream config
	if err != nil {
		if p.policy.FailOpen {
			fmt.Fprintf(os.Stderr, "[armis] supply-chain: age check unavailable for %s, allowing (fail-open): %v\n", pkgName, err)
			p.reverseProxy(w, r)
			return
		}
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: registry unreachable for %s: %v\n", pkgName, err)
		http.Error(w, fmt.Sprintf("[armis] supply-chain: registry unreachable for %s", pkgName), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		// Copy headers value-by-value with CR/LF stripped rather than aliasing the
		// upstream slices wholesale (w.Header()[k] = v). The verbatim copy both
		// shared upstream's backing arrays and bypassed the response-splitting
		// sanitization the 200 path relies on (CWE-93); Add preserves multi-value
		// headers (e.g. multiple Set-Cookie / WWW-Authenticate entries).
		dst := w.Header()
		for k, vals := range resp.Header {
			for _, v := range vals {
				// armis:ignore cwe:93 cwe:113 reason:sanitizeHeaderValue strips every CR and LF byte from the value before it reaches the header writer, which is the canonical neutralization for HTTP response splitting; the value cannot terminate the header line early
				dst.Add(k, sanitizeHeaderValue(v))
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck,gosec
		return
	}

	// Read one byte past the cap so an oversize response is detectable rather
	// than silently truncated: a body larger than maxProxyResponseSize yields
	// maxProxyResponseSize+1 bytes, which would otherwise be fed to the JSON
	// filter as incomplete data.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseSize+1))
	if err != nil {
		if p.policy.FailOpen {
			fmt.Fprintf(os.Stderr, "[armis] supply-chain: age check unavailable for %s, allowing (fail-open): %v\n", pkgName, err)
			p.reverseProxy(w, r)
			return
		}
		http.Error(w, fmt.Sprintf("[armis] supply-chain: failed to read upstream response for %s", pkgName), http.StatusBadGateway)
		return
	}
	if int64(len(body)) > maxProxyResponseSize {
		if p.policy.FailOpen {
			fmt.Fprintf(os.Stderr, "[armis] supply-chain: upstream response too large for %s, allowing (fail-open)\n", pkgName)
			p.reverseProxy(w, r)
			return
		}
		http.Error(w, fmt.Sprintf("[armis] supply-chain: upstream response too large for %s", pkgName), http.StatusBadGateway)
		return
	}

	var filtered []byte
	var blocked []BlockedPackage
	contentType := "application/json"
	if p.mode == ModePyPI {
		filtered, blocked = p.filterPyPISimple(body, pkgName)
		// Echo the PEP 691 JSON content type so pip/uv parse the body as the
		// Simple API JSON representation rather than guessing.
		contentType = pypiSimpleJSONAccept
	} else {
		filtered, blocked = p.filterMetadata(body, pkgName)
	}
	if blocked != nil {
		p.blockedMu.Lock()
		p.blocked = append(p.blocked, blocked...)
		p.blockedMu.Unlock()
	}

	// Forward only an explicit allowlist of cache-relevant headers so npm/pnpm/yarn
	// can populate their HTTP cache (~/.npm/_cacache) and skip a full re-download on
	// every wrapped invocation. Copying upstream headers wholesale would be wrong on
	// two counts: payload-describing headers (Content-Length, Content-Encoding)
	// refer to upstream's original bytes, not our re-marshaled body, and forwarding
	// unvalidated upstream header values verbatim is an HTTP-response-splitting
	// vector (CWE-93). copyCacheHeaders sanitizes each value before writing it.
	copyCacheHeaders(w.Header(), resp.Header, blocked != nil)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(filtered) //nolint:errcheck,gosec
}

// cacheHeaderAllowlist is the set of upstream response headers safe to forward
// on a filtered metadata response. It deliberately excludes payload-describing
// headers (Content-Length, Content-Encoding, Content-Type) because the served
// body is freshly re-marshaled and no longer matches upstream's bytes.
var cacheHeaderAllowlist = []string{
	"Cache-Control",
	"Vary",
	"Date",
	"Expires",
	"Age",
}

// copyCacheHeaders forwards a sanitized allowlist of cache-relevant headers from
// the upstream response to the client. Each value is stripped of CR/LF so a
// malicious upstream cannot inject extra headers or split the response
// (CWE-93). When the body was filtered (versionsRemoved), the validator headers
// ETag/Last-Modified are omitted: they describe upstream's full metadata, so
// forwarding them would let the client revalidate, receive a 304 from upstream
// (whose metadata is unchanged), and keep serving this filtered snapshot —
// hiding a blocked version even after it ages past the threshold. Cache-Control
// still bounds freshness in that case.
func copyCacheHeaders(dst, upstream http.Header, versionsRemoved bool) {
	forward := func(name string) {
		v := upstream.Get(name)
		if v == "" {
			return
		}
		dst.Set(name, sanitizeHeaderValue(v))
	}
	for _, name := range cacheHeaderAllowlist {
		forward(name)
	}
	if !versionsRemoved {
		// The body matches upstream byte-for-byte, so its validators are accurate
		// and safe to forward for conditional-request revalidation.
		forward("ETag")
		forward("Last-Modified")
	}
}

// sanitizeHeaderValue removes CR and LF bytes from a header value so an
// attacker-controlled upstream value cannot terminate the header line early and
// inject additional headers or a response body (HTTP response splitting).
func sanitizeHeaderValue(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

func (p *Proxy) filterMetadata(body []byte, pkgName string) ([]byte, []BlockedPackage) {
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(body, &metadata); err != nil {
		return body, nil
	}

	timeRaw, ok := metadata["time"]
	if !ok {
		return body, nil
	}

	var timeMap map[string]string
	if err := json.Unmarshal(timeRaw, &timeMap); err != nil {
		return body, nil
	}

	now := time.Now()
	var blocked []BlockedPackage
	versionsToRemove := make(map[string]bool)

	for version, timeStr := range timeMap {
		if version == npmTimeKeyCreated || version == npmTimeKeyModified {
			continue
		}
		publishTime, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			continue
		}
		age := now.Sub(publishTime)
		if age < p.policy.MinReleaseAge {
			versionsToRemove[version] = true
			blocked = append(blocked, BlockedPackage{
				Name:    pkgName,
				Version: version,
				Age:     age,
			})
		}
	}

	if len(versionsToRemove) == 0 {
		return body, nil
	}

	// Remove blocked versions from the time map
	for v := range versionsToRemove {
		delete(timeMap, v)
	}

	// Determine the resolved version: prefer dist-tags.latest if it wasn't blocked,
	// otherwise find the newest stable (non-prerelease) version still in the map.
	var latestVersion string
	if distTagsRaw, ok := metadata["dist-tags"]; ok {
		var distTags map[string]string
		if err := json.Unmarshal(distTagsRaw, &distTags); err == nil {
			if tagged, ok := distTags[distTagLatest]; ok && !versionsToRemove[tagged] {
				latestVersion = tagged
			}
		}
	}
	if latestVersion == "" {
		var latestTime time.Time
		for version, timeStr := range timeMap {
			if version == npmTimeKeyCreated || version == npmTimeKeyModified {
				continue
			}
			if isPrerelease(version) {
				continue
			}
			t, err := time.Parse(time.RFC3339, timeStr)
			if err != nil {
				continue
			}
			if t.After(latestTime) {
				latestTime = t
				latestVersion = version
			}
		}
	}
	if latestVersion != "" && p.allowed != nil {
		p.allowedMu.Lock()
		p.allowed[pkgName] = latestVersion
		p.allowedMu.Unlock()
	}

	newTime, _ := json.Marshal(timeMap)
	metadata["time"] = newTime

	// Remove blocked versions from the "versions" map if it exists
	if versionsRaw, ok := metadata["versions"]; ok {
		var versionsMap map[string]json.RawMessage
		if err := json.Unmarshal(versionsRaw, &versionsMap); err == nil {
			for v := range versionsToRemove {
				delete(versionsMap, v)
			}
			newVersions, _ := json.Marshal(versionsMap)
			metadata["versions"] = newVersions
		}
	}

	// Update dist-tags that point to blocked versions. Only "latest" is repointed
	// to the fallback stable version — channel tags like "next"/"beta" intentionally
	// track prereleases, so rewriting them to a stable version would mislead
	// `npm install pkg@next` into the wrong channel. Instead, drop blocked channel
	// tags so those installs fail closed rather than silently switch channels.
	if distTagsRaw, ok := metadata["dist-tags"]; ok {
		var distTags map[string]string
		if err := json.Unmarshal(distTagsRaw, &distTags); err == nil {
			updated := false
			for tag, ver := range distTags {
				if !versionsToRemove[ver] {
					continue
				}
				if tag == distTagLatest {
					// Repoint "latest" to the fallback stable version when one
					// exists; otherwise leave it untouched — the version is gone
					// from the versions map, so the install fails closed.
					if latestVersion != "" {
						distTags[tag] = latestVersion
						updated = true
					}
				} else {
					delete(distTags, tag)
					updated = true
				}
			}
			if updated {
				newDistTags, _ := json.Marshal(distTags)
				metadata["dist-tags"] = newDistTags
			}
		}
	}

	result, err := json.Marshal(metadata)
	if err != nil {
		return body, blocked
	}
	return result, blocked
}

// filterPyPISimple filters a PEP 691 Simple API JSON document, removing every
// distribution file whose PEP 700 "upload-time" is younger than the policy
// threshold. It returns the re-marshaled body and the list of blocked files
// (one BlockedPackage per file, since PyPI can add a new file to an existing
// version — per-file filtering catches that where per-version would not).
//
// Files are decoded as map[string]json.RawMessage so every untouched field
// (url, hashes, requires-python, yanked, dist-info-metadata, ...) round-trips
// verbatim; only "upload-time" is inspected.
//
// Fail-closed posture: a file with a missing or unparseable "upload-time" is
// REMOVED, not kept. The whole point of this control is age verification, so an
// undatable file (e.g. an HTML response slipping through, or a registry that
// omits PEP 700 timestamps) must not be silently installable. The version label
// in BlockedPackage is the filename, which is what the user sees and what makes
// the block actionable.
func (p *Proxy) filterPyPISimple(body []byte, pkgName string) ([]byte, []BlockedPackage) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, nil
	}

	filesRaw, ok := doc["files"]
	if !ok {
		return body, nil
	}

	var files []map[string]json.RawMessage
	if err := json.Unmarshal(filesRaw, &files); err != nil {
		return body, nil
	}

	now := time.Now()
	kept := make([]map[string]json.RawMessage, 0, len(files))
	var blocked []BlockedPackage

	for _, f := range files {
		filename := jsonString(f["filename"])
		age, ok := pypiFileAge(f["upload-time"], now)
		if !ok || age < p.policy.MinReleaseAge {
			// Undatable or too-young file: remove it. Record an age of 0 for the
			// undatable case so the summary still names the blocked file.
			if !ok {
				age = 0
			}
			blocked = append(blocked, BlockedPackage{Name: pkgName, Version: filename, Age: age})
			continue
		}
		kept = append(kept, f)
	}

	if len(blocked) == 0 {
		return body, nil
	}

	// Populate the allowed map with the newest safe version so the wrap summary
	// can report "→ 2.30.0 installed" instead of "no older safe version". PyPI
	// file objects carry no explicit "version" field, so we parse it from the
	// wheel/sdist filename (e.g. "requests-2.30.0-py3-none-any.whl" → "2.30.0").
	// We skip pre-releases (alpha/beta/rc) and pick the newest stable version
	// still in kept; ties go to the last one encountered (upload order is newest-
	// first in the Simple API, so the first non-prerelease is the right pick).
	if p.allowed != nil {
		var bestVersion string
		var bestAge time.Duration
		for _, f := range kept {
			fname := jsonString(f["filename"])
			ver := pypiVersionFromFilename(fname)
			if ver == "" || isPrerelease(ver) {
				continue
			}
			age, ok := pypiFileAge(f["upload-time"], now)
			if !ok {
				continue
			}
			if bestVersion == "" || age < bestAge {
				bestVersion = ver
				bestAge = age
			}
		}
		if bestVersion != "" {
			p.allowedMu.Lock()
			p.allowed[pkgName] = bestVersion
			p.allowedMu.Unlock()
		}
	}

	newFiles, err := json.Marshal(kept)
	if err != nil {
		return body, blocked
	}
	doc["files"] = newFiles

	// PEP 700 also exposes a "versions" array. We intentionally leave it intact:
	// a version remains "known" to the index even when all its files are filtered
	// out — pip simply finds no installable distribution for it and reports no
	// matching distribution, which is the correct fail-closed outcome. Rewriting
	// it risks desyncing from clients that key off the versions list.

	result, err := json.Marshal(doc)
	if err != nil {
		return body, blocked
	}
	return result, blocked
}

// pypiFileAge parses a PEP 700 "upload-time" raw JSON value and returns the age
// relative to now. The bool is false when the field is absent or unparseable.
// PEP 700 specifies RFC 3339; some mirrors omit the timezone, so a no-zone
// fallback is accepted as well (mirroring the PyPI registry client).
func pypiFileAge(raw json.RawMessage, now time.Time) (time.Duration, bool) {
	s := jsonString(raw)
	if s == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05", s)
		if err != nil {
			return 0, false
		}
	}
	return now.Sub(t), true
}

// pypiVersionFromFilename extracts the version component from a wheel or sdist
// filename. Wheels and sdists use different grammars, so they are parsed
// separately. Returns "" if the pattern does not match.
func pypiVersionFromFilename(filename string) string {
	// Wheels (and the legacy egg format) carry trailing build/interpreter/
	// platform tags after the version, e.g.
	// "{name}-{version}-{python}-{abi}-{platform}.whl". PEP 427 normalizes the
	// distribution so it never contains '-' (runs of [-_.] collapse to '_'), so
	// the version is reliably the second '-'-delimited field.
	if strings.HasSuffix(filename, ".whl") || strings.HasSuffix(filename, ".egg") {
		base := filename[:strings.LastIndex(filename, ".")]
		parts := strings.SplitN(base, "-", 3)
		if len(parts) < 2 {
			return ""
		}
		return parts[1]
	}

	// sdists are "{name}-{version}{ext}" with no trailing tags. Unlike wheels the
	// project name is NOT normalized, so it may legitimately contain '-' (e.g.
	// "zope-interface-6.0.tar.gz"). PEP 440 versions never contain '-', so the
	// version is everything after the FINAL '-'. Splitting on the first '-' (as a
	// single shared parser would) misreads such names — yielding "interface".
	name := filename
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".zip"} {
		if strings.HasSuffix(name, ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}
	idx := strings.LastIndex(name, "-")
	if idx <= 0 || idx == len(name)-1 {
		return ""
	}
	return name[idx+1:]
}

// jsonString decodes a JSON string value, returning "" for absent or non-string
// values rather than erroring — callers treat both as "field not usable".
func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func (p *Proxy) reverseProxy(w http.ResponseWriter, r *http.Request) {
	p.revProxy.ServeHTTP(w, r) //nolint:gosec // G704: single-host reverse proxy to a fixed upstream registry set at construction, not request-controlled
}

func extractPackageNameFromPath(path string) string {
	// npm clients may request scoped metadata with percent-encoded characters
	// (e.g. /%40scope%2Fname for @scope/name). Decode up front so scoped
	// detection works for both encoded and decoded forms; %40→@ and %2F→/ in
	// particular must round-trip. PathUnescape errors only on malformed escapes,
	// in which case we keep the original and fall through to best-effort parsing.
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return ""
	}

	// Scoped package: @scope/name
	if strings.HasPrefix(path, "@") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return ""
	}

	// Unscoped: just the package name (first path segment)
	parts := strings.SplitN(path, "/", 2)
	return parts[0]
}

// isMetadataRequest reports whether a request path targets package metadata
// (which the proxy filters) rather than a tarball or registry RPC endpoint.
// The distinction is purely path-based — npm serves metadata and tarballs from
// different URL shapes — so this takes the path alone and deliberately ignores
// method and headers, which the caller checks separately.
func isMetadataRequest(path string) bool {
	if strings.Contains(path, "/-/") || strings.HasSuffix(path, ".tgz") {
		return false
	}
	return true
}

func isPrerelease(version string) bool {
	parts := strings.SplitN(version, "-", 2)
	return len(parts) == 2 && parts[0] != ""
}

// extractPyPIPackageNameFromPath pulls the project name from a PyPI Simple API
// request path of the form "/simple/<name>/". It returns "" for the index root
// ("/simple/") and for any path that is not a single project under /simple/, so
// only per-project metadata requests are filtered.
func extractPyPIPackageNameFromPath(path string) string {
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	path = strings.Trim(path, "/")
	const prefix = "simple"
	if path == prefix {
		return "" // index root, not a project page
	}
	rest, ok := strings.CutPrefix(path, prefix+"/")
	if !ok {
		return ""
	}
	// rest should be a single project segment (with or without trailing slash,
	// already trimmed). A nested path (e.g. files) is not a metadata request.
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// isPyPIMetadataRequest reports whether a path targets a PyPI Simple API project
// page (which the proxy filters) rather than the index root or a file download.
// File downloads are served from a separate host (files.pythonhosted.org) and
// never reach this proxy, so a path-based check on "/simple/<name>/" suffices.
func isPyPIMetadataRequest(path string) bool {
	return extractPyPIPackageNameFromPath(path) != ""
}
