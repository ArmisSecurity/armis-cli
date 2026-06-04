package check

import (
	"encoding/xml"
	"fmt"
	"strings"
)

type pomProject struct {
	XMLName      xml.Name   `xml:"project"`
	Dependencies pomDeps    `xml:"dependencies"`
	DepMgmt      pomDepMgmt `xml:"dependencyManagement"`
}

type pomDepMgmt struct {
	Dependencies pomDeps `xml:"dependencies"`
}

type pomDeps struct {
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// ParseMavenDeps parses a pom.xml file for direct dependencies with explicit versions.
// Only direct dependencies are covered; transitive dependencies resolved by Maven
// at build time are not present in pom.xml.
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseMavenDeps(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var project pomProject
	// armis:ignore cwe:502 cwe:770 reason:xml.Unmarshal into a typed struct does not execute code; data is size-bounded by readLockfile and is the user's own lockfile, not untrusted data
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("parsing pom.xml: %w", err)
	}

	var entries []PackageEntry
	seen := make(map[string]bool)

	for _, dep := range project.Dependencies.Dependency {
		entry := mavenDepToEntry(dep)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	for _, dep := range project.DepMgmt.Dependencies.Dependency {
		entry := mavenDepToEntry(dep)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

func mavenDepToEntry(dep pomDependency) *PackageEntry {
	if dep.GroupID == "" || dep.ArtifactID == "" || dep.Version == "" {
		return nil
	}

	// Skip property references that can't be resolved
	if strings.Contains(dep.Version, "${") {
		return nil
	}

	// Skip test and provided scope
	scope := strings.ToLower(dep.Scope)
	if scope == "test" || scope == "provided" {
		return nil
	}

	return &PackageEntry{
		Name:    dep.GroupID + ":" + dep.ArtifactID,
		Version: dep.Version,
	}
}
