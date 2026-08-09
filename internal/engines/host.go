package engines

import (
	"net"
	"net/url"
	"strings"
)

// HostOf reduces whatever an engine reported — a bare host, host:port, or a full
// URL — to a lowercase hostname.
//
// Engines are inconsistent about this: naabu reports a host, httpx echoes back
// whatever it was given, and katana emits URLs. Normalising in one place means
// the inventory is keyed consistently no matter which engine observed a host.
func HostOf(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}

	// A bare host:port. SplitHostPort also handles the bracketed IPv6 form,
	// which a naive strings.Split on ":" would mangle.
	if host, _, err := net.SplitHostPort(value); err == nil && host != "" {
		return strings.ToLower(host)
	}

	return strings.ToLower(strings.TrimSuffix(value, "."))
}
