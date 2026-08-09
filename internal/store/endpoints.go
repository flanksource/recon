package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/flanksource/recon/internal/api"
)

// Endpoint is one address a scan will actually contact. A selector names hosts;
// an engine needs somewhere to connect, and a host with three open ports is
// three endpoints.
type Endpoint struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme,omitempty"`
	URL    string `json:"url"`

	// Class is carried through because the intrusive-scan gate is decided per
	// endpoint, and an unclassified host is treated as risky.
	Class api.Class `json:"class"`
}

// Endpoints resolves a selector to the addresses a scan would contact.
//
// This exists to be looked at before a run, not only during one: "which
// endpoints does this hit" has to be answerable in advance or an intrusive scan
// can surprise someone.
func (s *Store) Endpoints(ctx context.Context, opts TargetOpts) ([]Endpoint, error) {
	targets, err := s.ListTargets(ctx, opts)
	if err != nil {
		return nil, err
	}

	var endpoints []Endpoint
	for _, target := range targets {
		endpoints = append(endpoints, endpointsOf(target, opts.Ports)...)
	}

	// Stable order so a recorded command and its rendered input list are
	// diffable between runs.
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Host != endpoints[j].Host {
			return endpoints[i].Host < endpoints[j].Host
		}
		return endpoints[i].Port < endpoints[j].Port
	})
	return endpoints, nil
}

// endpointsOf resolves one target. The known URL wins: it is what actually
// answered, redirects and all. Failing that, the observed open ports and the
// curated ports are used, in that order.
func endpointsOf(target api.TargetDocument, only []int) []Endpoint {
	wanted := map[int]bool{}
	for _, port := range only {
		wanted[port] = true
	}
	keep := func(port int) bool { return len(wanted) == 0 || wanted[port] }

	seen := map[int]bool{}
	var endpoints []Endpoint

	if target.HTTP != nil && target.HTTP.URL != "" {
		port := target.HTTP.Port
		if port == 0 {
			port = defaultPort(target.HTTP.Scheme)
		}
		if keep(port) {
			seen[port] = true
			endpoints = append(endpoints, Endpoint{
				Host: target.Host, Port: port, Scheme: target.HTTP.Scheme,
				URL: target.HTTP.URL, Class: target.Class,
			})
		}
	}

	ports := []int{}
	if target.Network != nil {
		ports = append(ports, target.Network.OpenPorts...)
	}
	ports = append(ports, target.Ports...)

	for _, port := range ports {
		if seen[port] || !keep(port) {
			continue
		}
		seen[port] = true
		scheme := schemeFor(port)
		endpoints = append(endpoints, Endpoint{
			Host: target.Host, Port: port, Scheme: scheme,
			URL: buildURL(scheme, target.Host, port), Class: target.Class,
		})
	}

	return endpoints
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// schemeFor guesses from the port. Only 80 is assumed cleartext: defaulting the
// rest to https is the safer error, since an https probe of a plain HTTP port
// fails harmlessly while the reverse can send a request in the clear.
func schemeFor(port int) string {
	if port == 80 || port == 8080 {
		return "http"
	}
	return "https"
}

func buildURL(scheme, host string, port int) string {
	if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port)
}

// Risky returns the endpoints whose class means an intrusive scan needs
// confirmation. Naming them is the point: a prompt that says "3 production
// hosts" without saying which is not a prompt anyone can answer.
func Risky(endpoints []Endpoint) []Endpoint {
	var risky []Endpoint
	for _, endpoint := range endpoints {
		if endpoint.Class.Risky() {
			risky = append(risky, endpoint)
		}
	}
	return risky
}

// Hosts returns the distinct hosts of a set of endpoints, in order.
func Hosts(endpoints []Endpoint) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, endpoint := range endpoints {
		if seen[endpoint.Host] {
			continue
		}
		seen[endpoint.Host] = true
		hosts = append(hosts, endpoint.Host)
	}
	return hosts
}

// String renders an endpoint as host:port, which is what the engines take.
func (e Endpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}
