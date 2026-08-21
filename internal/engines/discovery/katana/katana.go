// Package katana wraps the ProjectDiscovery crawler. It is the one discovery
// engine that goes past the front door: given a live origin it walks the site
// and reports the endpoints, which is how paths that nothing links to from the
// root get found.
package katana

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the katana crawler.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

var catalog = engines.Sections{
	{
		ID:          "scope",
		Title:       "Scope",
		Description: "How far the crawl may wander. Getting this wrong is how a crawl ends up on somebody else's site.",
		SourceURL:   "https://github.com/projectdiscovery/katana#usage",
		Properties: []engines.Field{
			engines.Int("depth", "Depth", "How many links deep to follow.", 1),
			engines.Enum("field-scope", "Field scope", "What counts as in scope.", "rdn", "fqdn", "dn"),
			engines.StrList("crawl-scope", "In scope", "Regular expressions a URL must match to be crawled."),
			engines.StrList("crawl-out-scope", "Out of scope", "Regular expressions that exclude a URL."),
			engines.Bool("no-scope", "Ignore scope", "Crawl outside the target domain. Rarely what you want."),
			engines.Bool("js-crawl", "Crawl JavaScript", "Parse JavaScript files for endpoints."),
		},
	},
	{
		ID:          "performance",
		Title:       "Performance",
		Description: "Bound the crawl so it cannot become a load test.",
		SourceURL:   "https://github.com/projectdiscovery/katana#usage",
		Properties: []engines.Field{
			engines.Int("concurrency", "Concurrency", "Parallel fetches.", 1),
			engines.Int("parallelism", "Parallel hosts", "Hosts crawled at once.", 1),
			engines.Int("rate-limit", "Rate limit", "Requests per second.", 1),
			engines.Int("timeout", "Timeout", "Seconds to wait for a response.", 1),
			engines.Int("crawl-duration", "Maximum duration", "Seconds before the crawl is cut short.", 1),
			engines.Int("max-pages", "Maximum pages", "Pages to fetch per host.", 1),
		},
	},
	{
		ID:          "output",
		Title:       "Output",
		Description: "What the crawl reports.",
		SourceURL:   "https://github.com/projectdiscovery/katana#usage",
		Properties: []engines.Field{
			engines.StrList("extension-filter", "Excluded extensions", "File extensions to ignore."),
			engines.StrList("match-regex", "Match", "Only report URLs matching these expressions."),
			engines.StrList("filter-regex", "Filter", "Drop URLs matching these expressions."),
		},
	},
}

// Spec describes katana.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        "katana",
		Binary:      "katana",
		Title:       "Katana",
		Description: "Web crawler. Finds endpoints that are not linked from the root.",
		DocsURL:     "https://github.com/projectdiscovery/katana",
		// katana names its checksum file with hyphens where every other
		// ProjectDiscovery tool uses underscores.
		Install: engines.WithChecksumFile(
			engines.ProjectDiscovery("katana"), "katana-{{.version}}-checksums.txt"),
		Version: ">=1.7.0",
		Options: engines.OptionsFromSections(catalog),
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Shallow, bounded crawl. Depth and duration are both capped: this fetches\n" +
				"real pages from live services, and an unbounded crawl of a large site is\n" +
				"indistinguishable from a load test.",
			Config: map[string]any{
				"depth":          2,
				"field-scope":    "rdn",
				"concurrency":    10,
				"rate-limit":     20,
				"timeout":        10,
				"crawl-duration": 60,
				"max-pages":      200,
			},
		},
	}
}

// Accepts live origins.
func (Engine) Accepts() discovery.Kind { return discovery.Origins }

// Emits the endpoints it found.
func (Engine) Emits() discovery.Kind { return discovery.Endpoints }

// Args builds the command line.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// record is one line of katana's JSONL output.
type record struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method string `json:"method"`
		URL    string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode int    `json:"status_code"`
		Title      string `json:"title"`
	} `json:"response"`
}

// Parse reads katana's JSONL output.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var decoded record
		if err := json.Unmarshal(line, &decoded); err != nil {
			return fmt.Errorf("katana: %w", err)
		}
		if decoded.Request.URL == "" {
			return nil // a crawl event that is not an endpoint
		}

		host := engines.HostOf(decoded.Request.URL)
		if host == "" {
			return fmt.Errorf("katana: no host in %s", decoded.Request.URL)
		}

		fields := map[string]any{
			"input":  host,
			"url":    decoded.Request.URL,
			"method": decoded.Request.Method,
		}
		if decoded.Response.StatusCode > 0 {
			fields["status_code"] = decoded.Response.StatusCode
		}
		if decoded.Response.Title != "" {
			fields["title"] = decoded.Response.Title
		}

		return emit(discovery.Record{Host: host, Fields: fields})
	})
}
