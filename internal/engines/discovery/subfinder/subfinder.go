// Package subfinder wraps the ProjectDiscovery passive subdomain enumerator.
package subfinder

import (
	"io"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the subfinder enumerator.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

var catalog = engines.Sections{
	{
		ID:          "sources",
		Title:       "Sources",
		Description: "Which passive data sources to query.",
		SourceURL:   "https://github.com/projectdiscovery/subfinder#usage",
		Properties: []engines.Field{
			engines.StrList("sources", "Only these sources", "Restrict enumeration to the named sources."),
			engines.StrList("exclude-sources", "Excluded sources", "Sources to skip."),
			engines.Bool("all", "All sources", "Query every source, including the slow ones."),
			engines.Bool("recursive", "Recursive", "Use only sources that can enumerate subdomains recursively."),
		},
	},
	{
		ID:          "performance",
		Title:       "Performance",
		Description: "Bound how long enumeration may take.",
		SourceURL:   "https://github.com/projectdiscovery/subfinder#usage",
		Properties: []engines.Field{
			engines.Int("timeout", "Timeout", "Seconds to wait before giving up on a source.", 1),
			engines.Int("max-time", "Maximum runtime", "Minutes before enumeration is cut short.", 1),
			engines.Int("rate-limit", "Rate limit", "Maximum HTTP requests per second across all sources.", 1),
		},
	},
}

// Spec describes subfinder.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:   "subfinder",
		Binary: "subfinder",
		Title:  "Subfinder",
		Description: "Passive subdomain enumeration. Queries public sources rather than touching " +
			"the estate, so it finds hosts nothing else knows about.",
		DocsURL: "https://github.com/projectdiscovery/subfinder",
		Install: engines.ProjectDiscovery("subfinder"),
		Version: ">=2.15.0",
		Options: engines.OptionsFromSections(catalog),
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Bounded passive enumeration. max-time matters: without it a slow source\n" +
				"can stall a discovery run indefinitely.",
			Config: map[string]any{
				"timeout":  10,
				"max-time": 1,
			},
		},
	}
}

// Accepts DNS zones.
func (Engine) Accepts() discovery.Kind { return discovery.Zones }

// Emits hostnames.
func (Engine) Emits() discovery.Kind { return discovery.Hosts }

// Args builds the command line. Output is plain hostnames, one per line.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-dL", run.In,
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// Parse reads the hostname list.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanLines(r, func(line string) error {
		host := engines.HostOf(line)
		if host == "" {
			return nil
		}
		return emit(discovery.Record{Host: host, Fields: map[string]any{"source": "subfinder"}})
	})
}
