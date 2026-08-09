// Package discovery runs the engine chains that find and characterise hosts.
//
// The stages that are not engines live here: scraping hostnames out of
// checked-in manifests, and asking DNS for the NS and MX targets of the
// configured zones. Both produce plain hostnames, which is what the first
// engine in a chain consumes.
package discovery

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// hostPattern matches a hostname. Deliberately loose — the zone check below is
// what decides whether a match is in scope.
var hostPattern = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9.*-]*\.[a-zA-Z][a-zA-Z0-9-]+`)

// StaticScrape finds hostnames in checked-in manifests: Ingress `host:` values,
// cert-manager `dnsNames`, and anything else that looks like a hostname in a
// configured zone.
//
// The previous implementation shelled out to ripgrep over a path fixed relative
// to the repo — a hard dependency on a tool being installed, and on this code
// living next to somebody else's Kubernetes manifests. Both are now the
// caller's to supply, and the zones decide what is in scope instead of a
// hardcoded domain.
type StaticScrape struct {
	// Dirs are the manifest trees to read. There is no default: a scrape with
	// nowhere to look would silently find nothing, which reads as "no hosts"
	// rather than "not configured".
	Dirs []string

	// Zones bound what counts. A hostname outside every configured zone belongs
	// to somebody else and must not end up in the inventory.
	Zones []string

	// Extensions limits which files are read. Empty means the common manifest
	// extensions.
	Extensions []string
}

// Run scrapes the configured directories.
func (s StaticScrape) Run() ([]string, error) {
	if len(s.Dirs) == 0 {
		return nil, fmt.Errorf(
			"static discovery has no spec directories configured: set them or disable the stage")
	}
	if len(s.Zones) == 0 {
		return nil, fmt.Errorf(
			"static discovery has no zones configured: every hostname would be out of scope")
	}

	extensions := s.Extensions
	if len(extensions) == 0 {
		extensions = []string{".yaml", ".yml", ".json", ".tf", ".hcl"}
	}
	allowed := map[string]bool{}
	for _, extension := range extensions {
		allowed[strings.ToLower(extension)] = true
	}

	found := map[string]bool{}
	for _, dir := range s.Dirs {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("static discovery: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("static discovery: %s is not a directory", dir)
		}

		err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if skipDir(entry.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !allowed[strings.ToLower(filepath.Ext(path))] {
				return nil
			}

			body, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			for _, host := range s.hostsIn(string(body)) {
				found[host] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("static discovery: %w", err)
		}
	}

	hosts := make([]string, 0, len(found))
	for host := range found {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

// hostsIn extracts the in-scope hostnames from one file's contents.
func (s StaticScrape) hostsIn(body string) []string {
	var hosts []string
	for _, match := range hostPattern.FindAllString(body, -1) {
		host := normaliseHost(match)
		if host != "" && s.inZone(host) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// inZone reports whether a host belongs to a configured zone. The zone itself
// counts, so a bare `example.test` matches the zone `example.test`.
func (s StaticScrape) inZone(host string) bool {
	for _, zone := range s.Zones {
		zone = normaliseHost(zone)
		if host == zone || strings.HasSuffix(host, "."+zone) {
			return true
		}
	}
	return false
}

// normaliseHost lowercases, drops a trailing dot, and strips a leading wildcard
// label. A wildcard certificate names a zone rather than a host, so `*.a.test`
// contributes `a.test` — which is a real name worth probing.
func normaliseHost(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "*.")
	if host == "" || strings.Contains(host, "*") {
		return ""
	}
	return host
}

// skipDir keeps the walk out of directories that hold no manifests but plenty
// of hostname-shaped text.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".terraform":
		return true
	default:
		return false
	}
}
