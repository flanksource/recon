// Package nuclei wraps the ProjectDiscovery template scanner.
package nuclei

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// Engine is the nuclei scanner.
type Engine struct{}

// Compile-time proof that nuclei reports progress; most engines do not, which is
// why Progress is a separate optional interface.
var _ scan.Progress = Engine{}

func init() { scan.Register(Engine{}) }

// excludedTags never run, whatever a profile says. Denial-of-service, fuzzing,
// brute-force and intrusive templates are not something a profile should be able
// to switch on by accident against production.
var excludedTags = []string{"dos", "fuzz", "bruteforce", "intrusive"}

// Spec describes nuclei.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:            "nuclei",
		Binary:          "nuclei",
		Title:           "Nuclei",
		Description:     "Template-driven vulnerability scanner.",
		DocsURL:         "https://github.com/projectdiscovery/nuclei",
		Install:         engines.ProjectDiscovery("nuclei"),
		Version:         ">=3.11.1",
		Sections:        catalog,
		ValidateOptions: validateConfig,
		Defaults: engines.DefaultProfile{
			Name: "safe",
			Comment: "Non-intrusive baseline, safe to run against production.\n" +
				"No fuzzing, no DAST, no brute force. Rate limited so a scan cannot\n" +
				"become an outage.",
			Config: map[string]any{
				"severity":       []any{"low", "medium", "high", "critical"},
				"rate-limit":     50,
				"bulk-size":      25,
				"concurrency":    25,
				"timeout":        10,
				"retries":        1,
				"max-host-error": 30,
			},
		},
	}
}

func validateConfig(config map[string]any) error {
	automatic, _ := config["automatic-scan"].(bool)
	dast, _ := config["dast"].(bool)
	if automatic && dast {
		return fmt.Errorf("automatic-scan cannot be combined with dast: DAST excludes the technology-detection templates automatic-scan requires")
	}
	return nil
}

// Risk judges a configuration. DAST fuzzes live endpoints with attack payloads,
// so it is the line between "reads what an attacker sees" and "behaves like
// one".
func (Engine) Risk(config map[string]any) engines.Risk {
	if enabled, ok := config["dast"].(bool); ok && enabled {
		return engines.Intrusive("DAST sends fuzzing payloads (SQLi, XSS, SSTI, traversal) to live endpoints")
	}
	return engines.Safe()
}

// Args builds the command line.
//
// The template root, output paths and stats flags belong to the runner. The tag
// excludes are appended last and unconditionally: a profile must not be able to
// enable a denial-of-service template.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-jsonl",
		"-output", run.Out,
		"-silent",
		"-no-color",
		"-disable-update-check",
		"-stats",
		"-stats-json",
		"-stats-interval", "2",
	}
	args = append(args, engines.ConfigArgs(run.Config)...)
	return append(args, "-exclude-tags", strings.Join(excludedTags, ","))
}

// finding mirrors the fields of nuclei's JSONL output that map onto the
// normalised type. Everything else is preserved in Raw.
type finding struct {
	TemplateID  string   `json:"template-id"`
	MatcherName string   `json:"matcher-name"`
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matched-at"`
	URL         string   `json:"url"`
	Timestamp   string   `json:"timestamp"`
	Extracted   []string `json:"extracted-results"`
	Curl        string   `json:"curl-command"`
	Request     string   `json:"request"`
	Response    string   `json:"response"`

	Info struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
		Remediation string   `json:"remediation"`
	} `json:"info"`
}

// Parse reads nuclei's JSONL output.
func (Engine) Parse(r io.Reader, emit func(api.Finding) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var decoded finding
		if err := json.Unmarshal(line, &decoded); err != nil {
			return fmt.Errorf("nuclei: %w", err)
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			return fmt.Errorf("nuclei: %w", err)
		}
		// A base64 copy of the whole template, on every finding. Large, and
		// nothing reads it.
		delete(raw, "template-encoded")

		// A finding with no locatable host cannot be attributed to a target.
		// Fall back the way the previous implementation did rather than
		// dropping it.
		host := decoded.Host
		if host == "" {
			host = engines.HostOf(firstNonEmpty(decoded.MatchedAt, decoded.URL))
		}
		if host == "" {
			return fmt.Errorf("nuclei: finding %q has no host, matched-at or url", decoded.TemplateID)
		}

		name := decoded.Info.Name
		if name == "" {
			name = decoded.TemplateID
		}

		return emit(api.Finding{
			TemplateID:  decoded.TemplateID,
			Name:        name,
			Severity:    api.ParseSeverity(decoded.Info.Severity),
			Host:        host,
			MatchedAt:   firstNonEmpty(decoded.MatchedAt, decoded.URL, host),
			MatcherName: decoded.MatcherName,
			Type:        decoded.Type,
			Tags:        orEmpty(decoded.Info.Tags),
			Timestamp:   decoded.Timestamp,
			Extracted:   decoded.Extracted,
			Remediation: decoded.Info.Remediation,
			Reference:   decoded.Info.Reference,
			Curl:        decoded.Curl,
			Request:     decoded.Request,
			Response:    decoded.Response,
			Raw:         raw,
		})
	})
}

// stats mirrors nuclei's -stats-json line. Every value arrives as a string,
// including the numbers.
type stats struct {
	Requests  string `json:"requests"`
	Total     string `json:"total"`
	Percent   string `json:"percent"`
	RPS       string `json:"rps"`
	Matched   string `json:"matched"`
	Errors    string `json:"errors"`
	Hosts     string `json:"hosts"`
	Templates string `json:"templates"`
	Duration  string `json:"duration"`
}

// Progress recognises a -stats-json line.
//
// These are interleaved with ordinary log output on the same stream, so the
// caller uses the second return value to decide whether the line was progress or
// something to show the user.
func (Engine) Progress(line string) (api.ScanStats, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "{") {
		return api.ScanStats{}, false
	}

	var decoded stats
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		return api.ScanStats{}, false
	}
	// Findings are also JSON objects on this stream; requests/total are what
	// distinguishes a stats line from one.
	if decoded.Total == "" && decoded.Requests == "" {
		return api.ScanStats{}, false
	}

	progress := api.ScanStats{
		Requests:  engines.ParseFloat(decoded.Requests),
		Total:     engines.ParseFloat(decoded.Total),
		Percent:   engines.ParseFloat(decoded.Percent),
		RPS:       engines.ParseFloat(decoded.RPS),
		Matched:   engines.ParseFloat(decoded.Matched),
		Errors:    engines.ParseFloat(decoded.Errors),
		Hosts:     engines.ParseFloat(decoded.Hosts),
		Templates: engines.ParseFloat(decoded.Templates),
		Duration:  decoded.Duration,
	}
	if progress.Total <= 0 || progress.Percent < 0 || progress.Percent > 100 || math.IsNaN(progress.Percent) || math.IsInf(progress.Percent, 0) {
		progress.Percent = 0
	}
	return progress, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
