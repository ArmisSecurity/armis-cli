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
	"regexp"
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

	// maxConstraintEntries bounds each WS2 accumulator (distinct dependency
	// names in requiredRanges, distinct packages in keptVersions/removedVersions).
	// A real dependency graph is well under this; the cap is a backstop so a
	// hostile or pathological upstream metadata stream cannot grow the maps
	// without limit. Once reached, new keys are dropped (the one-hop diagnostic
	// degrades to best-effort; it never blocks the install).
	maxConstraintEntries = 50000
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
	Name string
	// Version is the raw artifact identifier the proxy removed: a wheel/sdist
	// filename for PyPI (e.g. "filelock-3.29.2.tar.gz"), a semver string for npm.
	// It records exactly which file/version was withheld and is what the proxy
	// tests assert against.
	Version string
	// DisplayVersion is the normalized version string shown to the user and used
	// for prerelease classification. For npm it equals Version (a SemVer string);
	// for PyPI it is parsed out of the filename and may be a PEP 440 version
	// ("3.29.2", "1.0.0rc1", "1.0.0.dev1"). Empty when a filename cannot be
	// parsed, in which case callers fall back to Version. Keeping classification
	// on this field — not the raw Version — stops a PyPI filename like
	// "filelock-3.29.2.tar.gz" from being misread as a "filelock" prerelease.
	DisplayVersion string
	Age            time.Duration
}

type InstalledPackage struct {
	Name    string
	Version string
	// Age is how old the resolved safe version was at install time — the figure
	// behind the summary's "0.2.3 installed (8 days old)". Zero when unknown.
	Age time.Duration
}

// WarnedPackage records a young transitive dependency the proxy let through
// unfiltered because the policy is TransitivePolicyWarn (WS5). It is surfaced as
// a per-package warning and marked in the compliance report so a security team
// can audit exactly which freshly-published packages entered the build.
type WarnedPackage struct {
	Name string
	// Version is the youngest version that was allowed through despite being
	// younger than the policy window — the one the warning names.
	Version string
	Age     time.Duration
}

// requiredRange is one declared dependency constraint harvested from a surviving
// package version's "dependencies" map: ByPkg requires Dep to satisfy Range.
// It is the raw material for the post-install one-hop conflict check (WS2).
type requiredRange struct {
	Range string
	ByPkg string
}

// allowedVersion is the proxy's internal record of the safe version it resolved
// "latest" to for one package, paired with that version's age so the summary can
// report how old the installed version was, not just its number.
type allowedVersion struct {
	version string
	age     time.Duration
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
	allowed      map[string]allowedVersion // package name → resolved safe version
	allowedMu    sync.Mutex
	checked      int
	checkedMu    sync.Mutex
	skipPackages map[string]bool

	// directSet is the root manifest's direct-dependency names (WS5). It is read
	// once at wrap start and never mutated afterward, so no lock guards it. A nil
	// directSet means "direct set undeterminable" — the proxy then fails safe and
	// treats every package as direct (blocks young versions regardless of the
	// transitive policy). An empty (non-nil) set means "determined, no direct
	// deps", so every checked package is transitive.
	directSet map[string]bool

	// requiredRanges and keptVersions are the two WS2 accumulators, populated
	// during filterMetadata. Only map writes happen under their locks — no JSON
	// parsing or semver evaluation in the critical section — so they stay off the
	// latency-sensitive filter path. The post-install pass (EvaluateConstraints)
	// reads them after the package manager exits, when all metadata has flowed,
	// making the conflict set deterministic regardless of arrival order.
	requiredRanges    map[string][]requiredRange // dependency name → ranges declared on it
	requiredRangesMu  sync.Mutex
	keptVersions      map[string][]string // package name → versions NOT removed
	keptVersionsMu    sync.Mutex
	removedVersions   map[string][]string // package name → versions removed by the age filter
	removedVersionsMu sync.Mutex

	// warned records young transitive dependencies allowed through under
	// TransitivePolicyWarn (WS5). Guarded by its own mutex like blocked/allowed.
	warned   []WarnedPackage
	warnedMu sync.Mutex
}

type ProxyConfig struct {
	Policy      Policy
	Mode        ProxyMode
	UpstreamURL string
	// SkipPackages are package names passed through without an age check (the
	// ARMIS_SUPPLY_CHAIN_SKIP set).
	SkipPackages []string
	// DirectDeps is the root manifest's direct-dependency name set (WS5). Pass
	// nil when it could not be determined; the proxy then treats every package as
	// direct and blocks young versions regardless of the transitive policy
	// (fail-safe). Only consulted when Policy.TransitivePolicy is warn.
	DirectDeps []string
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

	// Preserve the nil-vs-empty distinction: a nil DirectDeps means the direct
	// set could not be determined (fail-safe → treat all as direct), while a
	// non-nil-but-empty slice means "determined, project has no direct deps". A
	// blanket make() would erase that difference, so only build the map when
	// DirectDeps is non-nil.
	var directSet map[string]bool
	if cfg.DirectDeps != nil {
		directSet = make(map[string]bool, len(cfg.DirectDeps))
		for _, name := range cfg.DirectDeps {
			directSet[name] = true
		}
	}

	// NewSingleHostReverseProxy rewrites the request URL's scheme/host but
	// deliberately does NOT rewrite the Host header (see its doc comment). Left
	// as-is, tarball passthrough requests reach the upstream registry carrying
	// the local proxy's Host (e.g. "127.0.0.1:61396"). registry.npmjs.org is
	// fronted by a CDN that routes on Host, so an unknown value returns 403 —
	// the metadata check passes but the actual .tgz download fails. Wrap the
	// Director to point Host at the upstream registry so passthrough works.
	// upstreamURL is parsed from cfg.UpstreamURL, a startup-configured trusted
	// host defaulting to registry.npmjs.org/pypi.org — not a per-request
	// attacker-controlled value (matches the CWE-918 suppressions in reverseProxy).
	// armis:ignore cwe:918 reason:upstreamURL is a startup-configured trusted host defaulting to registry.npmjs.org/pypi.org, not a per-request attacker-controlled value
	revProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	baseDirector := revProxy.Director
	revProxy.Director = func(req *http.Request) {
		baseDirector(req)
		// armis:ignore cwe:918 reason:upstreamURL.Host is the startup-configured trusted upstream (default registry.npmjs.org/pypi.org); setting the outbound Host to it is required for CDN routing and is not attacker-controlled
		req.Host = upstreamURL.Host
	}

	return &Proxy{
		policy:      cfg.Policy,
		mode:        cfg.Mode,
		upstreamURL: upstreamURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		revProxy:        revProxy,
		skipPackages:    skipSet,
		allowed:         make(map[string]allowedVersion),
		directSet:       directSet,
		requiredRanges:  make(map[string][]requiredRange),
		keptVersions:    make(map[string][]string),
		removedVersions: make(map[string][]string),
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

// Upstream returns the configured upstream registry origin that callers use to
// rewrite the ephemeral proxy origin back to the real registry in artifacts a
// package manager persisted it into. It is scheme://host plus any base path
// (e.g. "https://registry.npmjs.org", or "https://registry.example.com/npm" for
// an Artifactory/Nexus repo path).
//
// The base path is essential: NewSingleHostReverseProxy joins the upstream's
// path onto every forwarded request, so an artifact the PM recorded as
// <proxy-origin>/axios/-/axios.tgz resolves upstream to <host>/npm/axios/-/...
// Dropping the /npm here would rewrite the residue to a host-rooted URL that
// 404s. A trailing slash is trimmed because the recorded URLs already begin the
// path segment (".../npm" + "/axios", not ".../npm/" + "/axios").
func (p *Proxy) Upstream() string {
	origin := p.upstreamURL.Scheme + "://" + p.upstreamURL.Host
	if path := strings.TrimSuffix(p.upstreamURL.Path, "/"); path != "" {
		origin += path
	}
	return origin
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
	for name, av := range p.allowed {
		result = append(result, InstalledPackage{Name: name, Version: av.version, Age: av.age})
	}
	return result
}

// Warned returns the young transitive dependencies the proxy let through
// unfiltered under TransitivePolicyWarn (WS5). Empty under the default block
// policy. The caller renders these as warnings and marks them in the report.
func (p *Proxy) Warned() []WarnedPackage {
	p.warnedMu.Lock()
	defer p.warnedMu.Unlock()
	result := make([]WarnedPackage, len(p.warned))
	copy(result, p.warned)
	return result
}

// isTransitive reports whether pkgName is a transitive dependency under the
// configured direct set. It is the policy-driving predicate for warn mode (WS5)
// and fails safe in two ways: a nil directSet (undeterminable) returns false so
// every package is treated as direct and blocked, and a name present in the
// direct set is never transitive. Only meaningful when the transitive policy is
// warn; the block path never calls it.
func (p *Proxy) isTransitive(pkgName string) bool {
	if p.directSet == nil {
		return false // direct set undeterminable → fail safe, treat as direct
	}
	return !p.directSet[pkgName]
}

// warnThroughTransitive reports whether a young version of pkgName should be
// allowed through with a warning instead of stripped. True only when the policy
// is warn AND the package is transitive AND a determinable direct set exists.
// Every other case (block policy, direct dep, undeterminable direct set) returns
// false so the version is filtered — the secure default.
func (p *Proxy) warnThroughTransitive(pkgName string) bool {
	return p.policy.TransitivePolicy == TransitivePolicyWarn && p.isTransitive(pkgName)
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
	// body is already bounded to maxProxyResponseSize (20MB) by the io.LimitReader
	// at the sole production call site; oversize upstream responses are rejected
	// with a 502 before they ever reach this function, so these unmarshals operate
	// on throttled input — there is no unbounded allocation here.
	var metadata map[string]json.RawMessage
	// armis:ignore cwe:770 reason:input body is capped at maxProxyResponseSize (20MB) by io.LimitReader at the caller before filterMetadata runs; larger responses are rejected with 502, so this unmarshal is not an unbounded allocation
	if err := json.Unmarshal(body, &metadata); err != nil {
		return body, nil
	}

	timeRaw, ok := metadata["time"]
	if !ok {
		return body, nil
	}

	var timeMap map[string]string
	// armis:ignore cwe:770 reason:timeRaw is a sub-slice of the already size-bounded body (capped at 20MB by io.LimitReader at the caller); unmarshaling it cannot allocate beyond that cap
	if err := json.Unmarshal(timeRaw, &timeMap); err != nil {
		return body, nil
	}

	now := time.Now()
	var blocked []BlockedPackage
	versionsToRemove := make(map[string]bool)

	// allVersions captures every real version key (skipping the created/modified
	// metadata keys) so the WS2 accumulators can record what survived — derived as
	// allVersions minus versionsToRemove — even for a package that had nothing
	// filtered (the dependent whose ranges we harvest).
	allVersions := make([]string, 0, len(timeMap))

	// Under TransitivePolicyWarn, a young *transitive* dependency is let through
	// unfiltered (so its parent's range stays satisfiable and the install
	// succeeds) and recorded as a warning instead of a block. warnThrough is
	// false for direct deps, for the default block policy, and when the direct
	// set is undeterminable — every one of those keeps the secure strip behavior.
	warnThrough := p.warnThroughTransitive(pkgName)
	var youngWarned []WarnedPackage

	for version, timeStr := range timeMap {
		if version == npmTimeKeyCreated || version == npmTimeKeyModified {
			continue
		}
		allVersions = append(allVersions, version)
		publishTime, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			continue
		}
		age := now.Sub(publishTime)
		if age < p.policy.MinReleaseAge {
			if warnThrough {
				// Allow the young transitive version through; record it so the wrap
				// can warn and the report can mark it. NOT added to versionsToRemove.
				youngWarned = append(youngWarned, WarnedPackage{Name: pkgName, Version: version, Age: age})
				continue
			}
			versionsToRemove[version] = true
			blocked = append(blocked, BlockedPackage{
				Name: pkgName,
				// npm versions are already semver, so the raw and display forms
				// coincide — no filename to parse, unlike PyPI.
				Version:        version,
				DisplayVersion: version,
				Age:            age,
			})
		}
	}

	// Record WS2 constraint data before any early return: the dependent package
	// (express) usually has nothing filtered itself, yet its declared ranges on
	// the dependency (debug) are exactly what the post-install conflict check
	// needs. recordConstraintData does its JSON parsing off-lock and takes the
	// accumulator mutexes only for the map writes.
	p.recordConstraintData(metadata, allVersions, versionsToRemove, pkgName)

	if warnThrough && len(youngWarned) > 0 {
		p.recordWarned(youngWarned)
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
			if IsPrerelease(version) {
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
		// Age of the resolved version, parsed from the (still-present) time map
		// entry. Unparseable or absent → zero, and the summary simply omits the
		// age rather than guessing.
		var latestAge time.Duration
		if ts, ok := timeMap[latestVersion]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				latestAge = now.Sub(t)
			}
		}
		p.allowedMu.Lock()
		p.allowed[pkgName] = allowedVersion{version: latestVersion, age: latestAge}
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

// recordConstraintData harvests the two WS2 accumulators from one package's npm
// metadata as it flows through the filter, for the deterministic post-install
// conflict pass (EvaluateConstraints). It does ALL JSON parsing off-lock and
// takes each accumulator mutex only for the final map write, so it adds no
// semver work to the latency-sensitive filter path.
//
//   - keptVersions[pkgName] = every version NOT removed (allVersions minus
//     versionsToRemove). This is the set the conflict check tests dependents'
//     ranges against.
//   - requiredRanges[dep] gains one entry per (range, byPkg) declared in each
//     surviving version's "dependencies" map. Only surviving versions contribute
//     constraints: a range declared solely by a version we removed isn't a real
//     post-install requirement.
func (p *Proxy) recordConstraintData(metadata map[string]json.RawMessage, allVersions []string, versionsToRemove map[string]bool, pkgName string) {
	// kept = allVersions \ versionsToRemove, removed = the rest. Both computed
	// off-lock. removed is recorded into its own accumulator (rather than read
	// back from p.blocked) so EvaluateConstraints is self-contained on the
	// accumulators and does not depend on the HTTP handler having appended to
	// p.blocked — which a direct filterMetadata call (unit tests) never does.
	kept := make([]string, 0, len(allVersions))
	var removed []string
	for _, v := range allVersions {
		if versionsToRemove[v] {
			removed = append(removed, v)
		} else {
			kept = append(kept, v)
		}
	}

	// Harvest declared dependency ranges from each surviving version's
	// "dependencies" map. npm embeds the full per-version dependencies object in
	// the "versions" map, so no extra fetch is needed.
	var harvested map[string][]requiredRange
	if versionsRaw, ok := metadata["versions"]; ok {
		var versionsMap map[string]json.RawMessage
		if err := json.Unmarshal(versionsRaw, &versionsMap); err == nil {
			for ver, raw := range versionsMap {
				if versionsToRemove[ver] {
					continue // a removed version's constraints are not post-install requirements
				}
				var verObj struct {
					Dependencies map[string]string `json:"dependencies"`
				}
				if err := json.Unmarshal(raw, &verObj); err != nil {
					continue
				}
				for dep, rng := range verObj.Dependencies {
					if harvested == nil {
						harvested = make(map[string][]requiredRange)
					}
					harvested[dep] = append(harvested[dep], requiredRange{Range: rng, ByPkg: pkgName})
				}
			}
		}
	}

	// Only map writes happen under the locks; no parsing or semver eval here. The
	// maps are lazy-initialized under their own lock so a Proxy built as a bare
	// struct literal (as several unit tests do) is safe too, not just one from
	// NewProxy. Each map is capped at maxConstraintEntries distinct keys so a
	// hostile/pathological metadata stream cannot grow them without bound; a new
	// key past the cap is dropped, degrading the one-hop diagnostic to
	// best-effort rather than exhausting memory. kept/removed are each a full
	// snapshot of the package's version set, so a repeat fetch of the same
	// pkgName overwrites rather than appends — that keeps a single key's slice
	// bounded by the version count even if a client spams the proxy for one
	// package.
	if len(kept) > 0 {
		p.keptVersionsMu.Lock()
		if p.keptVersions == nil {
			p.keptVersions = make(map[string][]string)
		}
		if _, exists := p.keptVersions[pkgName]; exists || len(p.keptVersions) < maxConstraintEntries {
			p.keptVersions[pkgName] = kept
		}
		p.keptVersionsMu.Unlock()
	}
	if len(removed) > 0 {
		p.removedVersionsMu.Lock()
		if p.removedVersions == nil {
			p.removedVersions = make(map[string][]string)
		}
		if _, exists := p.removedVersions[pkgName]; exists || len(p.removedVersions) < maxConstraintEntries {
			p.removedVersions[pkgName] = removed
		}
		p.removedVersionsMu.Unlock()
	}
	if len(harvested) > 0 {
		p.requiredRangesMu.Lock()
		if p.requiredRanges == nil {
			p.requiredRanges = make(map[string][]requiredRange)
		}
		for dep, ranges := range harvested {
			if _, exists := p.requiredRanges[dep]; !exists && len(p.requiredRanges) >= maxConstraintEntries {
				continue // cap reached; drop new dependency keys (existing ones still grow)
			}
			p.requiredRanges[dep] = append(p.requiredRanges[dep], ranges...)
		}
		p.requiredRangesMu.Unlock()
	}
}

// recordWarned collapses the young versions allowed through for one package
// (under TransitivePolicyWarn) to the single youngest — the one a default
// install would have selected as latest, and the most security-relevant to
// surface — and appends it to the warned set under its lock.
func (p *Proxy) recordWarned(youngWarned []WarnedPackage) {
	youngest := youngWarned[0]
	for _, w := range youngWarned[1:] {
		if w.Age < youngest.Age {
			youngest = w
		}
	}
	p.warnedMu.Lock()
	p.warned = append(p.warned, youngest)
	p.warnedMu.Unlock()
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
			// Version is the filename (what the user sees and what makes the block
			// actionable); DisplayVersion is the semver parsed from it, used for
			// prerelease classification and the clean number shown in the summary.
			blocked = append(blocked, BlockedPackage{
				Name:           pkgName,
				Version:        filename,
				DisplayVersion: pypiVersionFromFilename(filename),
				Age:            age,
			})
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
			if ver == "" || IsPrerelease(ver) {
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
			p.allowed[pkgName] = allowedVersion{version: bestVersion, age: bestAge}
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

// pep440Prerelease matches a PEP 440 pre-release (aN/bN/cN/rcN and the long
// spellings alpha/beta/pre/preview) or development-release (devN) segment. These
// attach to the numeric release with an optional ".", "-", or "_" separator and,
// unlike SemVer, without a leading "-" tag — e.g. "1.0.0rc1", "1.0.0b2",
// "1.0.0.dev1". Longer spellings precede shorter ones in the alternation so
// "alpha" is preferred over a bare "a" (Go's regexp is leftmost-first). PEP 440
// post-releases (".postN") are stable and are intentionally NOT matched.
var pep440Prerelease = regexp.MustCompile(`(?i)[0-9][._-]?(?:alpha|beta|preview|pre|rc|dev|a|b|c)[0-9]*`)

// semverNumericHead matches the part before a SemVer pre-release "-" only when it
// is a numeric dotted release core (optionally "v"-prefixed): "1", "1.2",
// "1.2.3", "v2.0.0". A raw PyPI filename fallback's head ("filelock", "pkg2",
// "4ti2") is NOT a bare numeric core, so it never qualifies — including the
// digit-bearing and digit-leading project names that a looser "contains/starts
// with a digit" test would misfire on.
var semverNumericHead = regexp.MustCompile(`^[vV]?[0-9]+(?:\.[0-9]+)*$`)

// IsPrerelease reports whether a version string denotes a pre-release in either
// ecosystem's grammar. It is the single source of truth shared by the proxy and
// the CLI summary so the two can never drift (a past divergence is what let PyPI
// filenames be misclassified). It recognizes:
//
//   - SemVer/npm: a "-" suffix on a version whose head is a numeric release core
//     ("2.0.0-alpha.1", "v1.2.3-beta").
//   - PyPI/PEP 440: dash-less pre/dev markers on the release ("2.0.0rc1",
//     "1.0.0b2", "1.0.0.dev1").
//
// The SemVer branch fires only when the head before "-" is a bare numeric core
// (see semverNumericHead). That guards against a raw, unparseable PyPI filename
// used as a fallback being misread as a prerelease — not just hyphenated names
// like "filelock-3.29.2.tar.gz" but digit-bearing/-leading ones like
// "pkg2-1.0.tar.gz" or the real package "4ti2-1.0.tar.gz", which a looser
// "contains a digit" check would wrongly flag. This is the very failure mode the
// helper exists to prevent. Valid stable versions in one ecosystem never match
// the other's pre-release syntax, so a unified check is safe for both.
// Post-releases stay stable.
func IsPrerelease(version string) bool {
	if i := strings.IndexByte(version, '-'); i > 0 && semverNumericHead.MatchString(version[:i]) {
		return true
	}
	return pep440Prerelease.MatchString(version)
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
