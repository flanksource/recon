package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// Resolver is the DNS surface this stage needs. An interface so the tests can
// answer without a network, and so a run can be pointed at specific resolvers
// rather than whatever the machine is configured with.
type Resolver interface {
	LookupNS(ctx context.Context, zone string) ([]*net.NS, error)
	LookupMX(ctx context.Context, zone string) ([]*net.MX, error)
}

// SystemResolver uses the machine's configured resolvers.
func SystemResolver() Resolver { return net.DefaultResolver }

// DNSFailure is one query that did not answer. Failures are reported rather
// than swallowed: a zone whose NS lookup fails is not a zone with no
// nameservers, and treating it as one silently shrinks the attack surface.
type DNSFailure struct {
	Zone   string `json:"zone"`
	Record string `json:"record"`
	Error  string `json:"error"`
}

// DNSResult is what a sweep of the configured zones found.
type DNSResult struct {
	Hosts         []string     `json:"hosts"`
	Nameservers   []string     `json:"nameservers"`
	MailExchanges []string     `json:"mailExchanges"`
	Failures      []DNSFailure `json:"failures"`
}

// DiscoverDNS asks each zone for its NS and MX records. Those point at
// infrastructure that is often run by someone else and just as often forgotten,
// which is why they are worth enumerating at all.
func DiscoverDNS(ctx context.Context, resolver Resolver, zones []string) (DNSResult, error) {
	unique := map[string]bool{}
	for _, zone := range zones {
		if host := normaliseHost(zone); host != "" {
			unique[host] = true
		}
	}
	if len(unique) == 0 {
		return DNSResult{}, fmt.Errorf("DNS discovery requires at least one zone")
	}

	ordered := make([]string, 0, len(unique))
	for zone := range unique {
		ordered = append(ordered, zone)
	}
	sort.Strings(ordered)

	var (
		mu            sync.Mutex
		nameservers   = map[string]bool{}
		mailExchanges = map[string]bool{}
		failures      []DNSFailure
		wait          sync.WaitGroup
	)

	record := func(zone, kind string, err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, DNSFailure{Zone: zone, Record: kind, Error: err.Error()})
	}

	for _, zone := range ordered {
		wait.Add(2)

		go func() {
			defer wait.Done()
			found, err := resolver.LookupNS(ctx, zone)
			if err != nil {
				record(zone, "NS", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, ns := range found {
				if host := normaliseHost(ns.Host); host != "" {
					nameservers[host] = true
				}
			}
		}()

		go func() {
			defer wait.Done()
			found, err := resolver.LookupMX(ctx, zone)
			if err != nil {
				record(zone, "MX", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, mx := range found {
				// "." is the null MX of RFC 7505: the zone is declaring that it
				// accepts no mail, not naming a host.
				if strings.TrimSpace(mx.Host) == "." {
					continue
				}
				if host := normaliseHost(mx.Host); host != "" {
					mailExchanges[host] = true
				}
			}
		}()
	}
	wait.Wait()

	result := DNSResult{
		Nameservers:   sortedKeys(nameservers),
		MailExchanges: sortedKeys(mailExchanges),
		Failures:      failures,
	}

	combined := map[string]bool{}
	for host := range nameservers {
		combined[host] = true
	}
	for host := range mailExchanges {
		combined[host] = true
	}
	result.Hosts = sortedKeys(combined)

	sort.Slice(result.Failures, func(i, j int) bool {
		if result.Failures[i].Zone != result.Failures[j].Zone {
			return result.Failures[i].Zone < result.Failures[j].Zone
		}
		return result.Failures[i].Record < result.Failures[j].Record
	})

	// Every query failing means the resolver is unreachable, not that the zones
	// are empty. Reporting an empty result here would look like a clean sweep.
	if len(result.Failures) == len(ordered)*2 {
		return result, fmt.Errorf("all %d NS/MX queries failed: %s",
			len(result.Failures), result.Failures[0].Error)
	}
	return result, nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
