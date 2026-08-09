// Package httpx wraps the ProjectDiscovery HTTP prober. It turns endpoints into
// the observations that populate a target's http, tls, tech and network
// sections.
package httpx

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the httpx prober.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

// Spec describes httpx.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:   "httpx",
		Binary: "httpx",
		Title:  "httpx",
		Description: "HTTP prober. Reports status, title, server, technologies and TLS for each " +
			"endpoint, and is what most of a target's observed state comes from.",
		DocsURL:  "https://github.com/projectdiscovery/httpx",
		Install:  engines.ProjectDiscovery("httpx"),
		Version:  ">=1.10.0",
		Sections: catalog,
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Metadata collection only. Every option here reads what a normal client\n" +
				"would see; nothing probes for weaknesses — that is a scan engine's job.",
			Config: map[string]any{
				"status-code":   true,
				"title":         true,
				"web-server":    true,
				"tech-detect":   true,
				"content-type":  true,
				"location":      true,
				"response-time": true,
				"tls-grab":      true,
				"cname":         true,
				"asn":           true,
				"cdn":           true,
				"follow-redirects": true,
				"max-redirects": 3,
				"timeout":       10,
				"retries":       1,
				"rate-limit":    50,
			},
		},
	}
}

// Accepts host:port endpoints (and bare hosts, which httpx resolves itself).
func (Engine) Accepts() discovery.Kind { return discovery.Endpoints }

// Emits normalised observations.
func (Engine) Emits() discovery.Kind { return discovery.Observations }

// Args builds the command line. The input list and JSON output are the runner's
// concern; -no-color and -disable-update-check keep the output parseable.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-json",
		"-silent",
		"-no-color",
		"-disable-update-check",
		"-no-stdin",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// Parse reads httpx's JSON lines.
//
// The record is passed through nearly whole: normalising it into a target's
// machine-owned sections is internal/observe's job, and doing it here would
// duplicate that logic in every engine that reports HTTP metadata.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var fields map[string]any
		if err := json.Unmarshal(line, &fields); err != nil {
			return fmt.Errorf("httpx: %w", err)
		}

		host, err := observationHost(fields)
		if err != nil {
			return err
		}

		// Request and response bodies can be large and carry credentials from a
		// redirect chain. Nothing downstream reads them, so they are dropped
		// here rather than stored.
		for _, key := range []string{"header", "raw_header", "request", "response", "body"} {
			delete(fields, key)
		}
		// Every engine's record carries `input`, so the normaliser can attribute
		// one without knowing which engine produced it. httpx omits it when the
		// host came from a url, so restate it here.
		fields["input"] = host

		return emit(discovery.Record{Host: host, Fields: fields})
	})
}

// observationHost recovers the host an httpx record describes. `input` is what
// was fed in and is preferred; `url` is the fallback for records that omit it.
func observationHost(fields map[string]any) (string, error) {
	if input, ok := fields["input"].(string); ok && input != "" {
		return engines.HostOf(input), nil
	}
	if raw, ok := fields["url"].(string); ok && raw != "" {
		return engines.HostOf(raw), nil
	}
	return "", fmt.Errorf("httpx: record has neither input nor url")
}
