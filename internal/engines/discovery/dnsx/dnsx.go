// Package dnsx wraps the ProjectDiscovery DNS toolkit. It resolves hosts and
// pulls the records that reveal further infrastructure — CNAME chains pointing
// at third parties, and the NS and MX targets that are themselves hosts worth
// knowing about.
package dnsx

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the dnsx resolver.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

var catalog = engines.Sections{
	{
		ID:          "records",
		Title:       "Records",
		Description: "Which record types to query.",
		SourceURL:   "https://github.com/projectdiscovery/dnsx#usage",
		Properties: []engines.Field{
			engines.Bool("a", "A", "Query IPv4 addresses."),
			engines.Bool("aaaa", "AAAA", "Query IPv6 addresses."),
			engines.Bool("cname", "CNAME", "Query canonical names. A dangling CNAME is how a subdomain takeover starts."),
			engines.Bool("ns", "NS", "Query name servers."),
			engines.Bool("mx", "MX", "Query mail exchangers."),
			engines.Bool("txt", "TXT", "Query text records."),
			engines.Bool("soa", "SOA", "Query the start of authority."),
			engines.Bool("ptr", "PTR", "Query reverse records."),
		},
	},
	{
		ID:          "resolvers",
		Title:       "Resolvers",
		Description: "Who answers the queries.",
		SourceURL:   "https://github.com/projectdiscovery/dnsx#usage",
		Properties: []engines.Field{
			engines.StrList("resolver", "Resolvers", "Resolvers to query, in order."),
			engines.Bool("trace", "Trace", "Trace the delegation path from the root."),
			engines.Int("retry", "Retries", "Retries per query.", 0),
		},
	},
	{
		ID:          "performance",
		Title:       "Performance",
		Description: "Bound the sweep.",
		SourceURL:   "https://github.com/projectdiscovery/dnsx#usage",
		Properties: []engines.Field{
			engines.Int("threads", "Threads", "Concurrent queries.", 1),
			engines.Int("rate-limit", "Rate limit", "Queries per second.", 1),
		},
	},
}

// Spec describes dnsx.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        "dnsx",
		Binary:      "dnsx",
		Title:       "dnsx",
		Description: "DNS resolution and record enumeration.",
		DocsURL:     "https://github.com/projectdiscovery/dnsx",
		Install:     engines.ProjectDiscovery("dnsx"),
		Version:     ">=1.3.0",
		Sections:    catalog,
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Resolution plus the records that point at other infrastructure.\n" +
				"CNAME is not optional here: a CNAME to a deprovisioned third-party\n" +
				"service is a subdomain takeover waiting to happen.",
			Config: map[string]any{
				"a": true, "aaaa": true, "cname": true,
				"threads": 50, "retry": 2,
			},
		},
	}
}

// Accepts hostnames.
func (Engine) Accepts() discovery.Kind { return discovery.Hosts }

// Emits observations — resolution results, not new hosts.
func (Engine) Emits() discovery.Kind { return discovery.Observations }

// Args builds the command line.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-json",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// record is one line of dnsx's JSON output.
type record struct {
	Host  string   `json:"host"`
	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname"`
	NS    []string `json:"ns"`
	MX    []string `json:"mx"`
}

// Parse reads dnsx's JSON lines.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var decoded record
		if err := json.Unmarshal(line, &decoded); err != nil {
			return fmt.Errorf("dnsx: %w", err)
		}
		if decoded.Host == "" {
			return fmt.Errorf("dnsx: record has no host")
		}

		host := engines.HostOf(decoded.Host)
		fields := map[string]any{"input": host}
		set := func(key string, values []string) {
			if len(values) > 0 {
				fields[key] = toAny(values)
			}
		}
		set("a", decoded.A)
		set("aaaa", decoded.AAAA)
		set("cname", decoded.CNAME)
		set("ns", decoded.NS)
		set("mx", decoded.MX)

		return emit(discovery.Record{Host: host, Fields: fields})
	})
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}
