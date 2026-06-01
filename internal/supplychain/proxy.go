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
	maxProxyResponseSize    = 20 * 1024 * 1024
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
	UpstreamURL  string
	SkipPackages []string
}

func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	upstream := cfg.UpstreamURL
	if upstream == "" {
		upstream = defaultUpstreamRegistry
	}

	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL: %w", err)
	}

	skipSet := make(map[string]bool, len(cfg.SkipPackages))
	for _, pkg := range cfg.SkipPackages {
		skipSet[pkg] = true
	}

	return &Proxy{
		policy:      cfg.Policy,
		upstreamURL: upstreamURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		revProxy:     httputil.NewSingleHostReverseProxy(upstreamURL),
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
	pkgName := extractPackageNameFromPath(r.URL.Path)

	if pkgName == "" || r.Method != http.MethodGet || !isMetadataRequest(r) {
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
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.upstreamURL.String()+r.URL.Path, nil) //nolint:gosec // upstream URL is configured at startup, path is from local proxy
	if err != nil {
		http.Error(w, fmt.Sprintf("[armis] supply-chain: failed to create request for %s", pkgName), http.StatusBadGateway)
		return
	}
	upstreamReq.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(upstreamReq) //nolint:gosec // URL constructed from trusted upstream config
	if err != nil {
		fmt.Fprintf(os.Stderr, "[armis] supply-chain: registry unreachable for %s: %v\n", pkgName, err)
		http.Error(w, fmt.Sprintf("[armis] supply-chain: registry unreachable for %s", pkgName), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck,gosec
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseSize))
	if err != nil {
		http.Error(w, fmt.Sprintf("[armis] supply-chain: failed to read upstream response for %s", pkgName), http.StatusBadGateway)
		return
	}

	filtered, blocked := p.filterMetadata(body, pkgName)
	if blocked != nil {
		p.blockedMu.Lock()
		p.blocked = append(p.blocked, blocked...)
		p.blockedMu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(filtered) //nolint:errcheck,gosec
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
		if version == "created" || version == "modified" {
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
			if tagged, ok := distTags["latest"]; ok && !versionsToRemove[tagged] {
				latestVersion = tagged
			}
		}
	}
	if latestVersion == "" {
		var latestTime time.Time
		for version, timeStr := range timeMap {
			if version == "created" || version == "modified" {
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

	// Update dist-tags that point to blocked versions
	if distTagsRaw, ok := metadata["dist-tags"]; ok && latestVersion != "" {
		var distTags map[string]string
		if err := json.Unmarshal(distTagsRaw, &distTags); err == nil {
			updated := false
			for tag, ver := range distTags {
				if versionsToRemove[ver] {
					distTags[tag] = latestVersion
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

func (p *Proxy) reverseProxy(w http.ResponseWriter, r *http.Request) {
	p.revProxy.ServeHTTP(w, r)
}

func extractPackageNameFromPath(path string) string {
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

func isMetadataRequest(r *http.Request) bool {
	path := r.URL.Path
	if strings.Contains(path, "/-/") || strings.HasSuffix(path, ".tgz") {
		return false
	}
	return true
}

func isPrerelease(version string) bool {
	parts := strings.SplitN(version, "-", 2)
	return len(parts) == 2 && parts[0] != ""
}
