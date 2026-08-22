package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/report"
	scanruntime "github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// ReportFindingLimit is how many findings one report asks the store for.
//
// Higher than the interactive default: a printed report is read once and
// archived, so truncating it at the page size of a table would quietly turn a
// document into a sample. A run past this cap is still printed — the report says
// which part of the run it covers.
const ReportFindingLimit = 2000

// ScanReportSource resolves what a report is printed from.
type ScanReportSource interface {
	GetScan(ctx context.Context, id string) (api.Scan, error)
	ListFindings(ctx context.Context, opts store.FindingOpts) ([]api.Finding, error)
}

// ReportRenderer prints a payload. Narrowed to what these routes need, so the
// handlers can be tested without a facet install.
type ReportRenderer interface {
	Available() error
	Render(ctx context.Context, format report.Format, payload any) ([]byte, error)
}

// RegisterScanReport adds the report routes for a run.
//
// Three routes over one payload, and that is the point: `/report` serves the
// JSON the template consumes, `/report.pdf` and `/report.html` serve the same
// JSON rendered. The playground reads the first and mounts the template in the
// browser, so what is designed on screen is what prints — there is no second
// description of a run to keep in step.
//
// They are not entity operations: the subject is a document derived from two
// tables, its representation is a PDF, and its query string is presentation
// rather than selection.
func RegisterScanReport(mux *http.ServeMux, scans ScanReportSource, renderer ReportRenderer) {
	mux.HandleFunc("GET /api/scan/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		payload, status, err := buildScanReport(r, scans)
		if err != nil {
			writeError(w, status, err)
			return
		}
		writeJSON(w, payload)
	})

	render := func(format report.Format) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := renderer.Available(); err != nil {
				// The request is fine; this deployment cannot answer it. 501
				// rather than 500, so the UI can say how to fix the environment
				// instead of presenting it as a failed export.
				writeError(w, http.StatusNotImplemented, err)
				return
			}
			payload, status, err := buildScanReport(r, scans)
			if err != nil {
				writeError(w, status, err)
				return
			}
			document, err := renderer.Render(r.Context(), format, payload)
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			w.Header().Set("Content-Type", format.ContentType())
			w.Header().Set("Content-Disposition",
				fmt.Sprintf("attachment; filename=%q", reportFilename(payload.Scan, format)))
			w.Header().Set("Content-Length", strconv.Itoa(len(document)))
			_, _ = w.Write(document)
		}
	}

	mux.HandleFunc("GET /api/scan/{id}/report.pdf", render(report.FormatPDF))
	mux.HandleFunc("GET /api/scan/{id}/report.html", render(report.FormatHTML))
}

func buildScanReport(r *http.Request, scans ScanReportSource) (api.ScanReport, int, error) {
	options, err := reportOptions(r.URL.Query())
	if err != nil {
		// A malformed option is the caller's, and answering it as "no such
		// scan" would send them looking in the wrong place.
		return api.ScanReport{}, http.StatusBadRequest, err
	}
	scan, err := scans.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		return api.ScanReport{}, http.StatusNotFound, err
	}
	parameters, err := reportScanParameters(scan)
	if err != nil {
		return api.ScanReport{}, http.StatusInternalServerError, err
	}
	findings, err := scans.ListFindings(r.Context(), store.FindingOpts{
		Scan:  []string{scan.ID},
		Limit: ReportFindingLimit,
	})
	if err != nil {
		return api.ScanReport{}, http.StatusInternalServerError, err
	}

	return api.ScanReport{
		Scan:         scan,
		Findings:     findings,
		Parameters:   parameters,
		Options:      options,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		FindingLimit: ReportFindingLimit,
		SourceURL:    reportSourceURL(r, scan.ID),
	}, http.StatusOK, nil
}

func reportScanParameters(run api.Scan) (map[string]any, error) {
	if run.Result == "" {
		return nil, nil
	}
	path, err := scanruntime.ResolveArtifact(run.Result, scanruntime.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("scan %s parameters: %w", run.ID, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scan %s parameters: %w", run.ID, err)
	}
	var parameters map[string]any
	if err := json.Unmarshal(content, &parameters); err != nil {
		return nil, fmt.Errorf("scan %s parameters: %w", run.ID, err)
	}
	if parameters == nil {
		return nil, fmt.Errorf("scan %s parameters: %s must contain a JSON object", run.ID, scanruntime.ConfigFile)
	}
	return parameters, nil
}

// reportOptions reads the presentation of a report off the query string.
//
// The query string is the whole of it: the playground builds a URL and the
// export button follows it, so a report someone liked on screen is a link they
// can paste into a runbook and get the same document back.
func reportOptions(query url.Values) (*api.ScanReportOptions, error) {
	options := &api.ScanReportOptions{
		Title:          query.Get("title"),
		Subtitle:       query.Get("subtitle"),
		Classification: query.Get("classification"),
		PreparedBy:     query.Get("preparedBy"),
		Audience:       query.Get("audience"),
		Scope:          query.Get("scope"),
		Watermark:      query.Get("watermark"),
	}

	if value := query.Get("minSeverity"); value != "" {
		severity := api.Severity(strings.ToLower(value))
		if !slices.Contains(api.Severities(), severity) {
			return nil, fmt.Errorf("unknown minSeverity %q", value)
		}
		options.MinSeverity = severity
	}
	if value := query.Get("maxDetailedFindings"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("maxDetailedFindings must be a non-negative number, got %q", value)
		}
		options.MaxDetailedFindings = parsed
	}

	sections, err := reportSections(query)
	if err != nil {
		return nil, err
	}
	options.Sections = sections
	return options, nil
}

// reportSections reads the section toggles, or nil when the caller set none —
// which the template reads as "print everything".
func reportSections(query url.Values) (*api.ScanReportSections, error) {
	sections := &api.ScanReportSections{}
	toggles := []struct {
		key   string
		field **bool
	}{
		{"coverage", &sections.Coverage},
		{"traffic", &sections.Traffic},
		{"breakdowns", &sections.Breakdowns},
		{"summaryTable", &sections.SummaryTable},
		{"detailedFindings", &sections.DetailedFindings},
		{"evidence", &sections.Evidence},
		{"appendix", &sections.Appendix},
	}

	set := false
	for _, toggle := range toggles {
		value := query.Get(toggle.key)
		if value == "" {
			continue
		}
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("section %s must be true or false, got %q", toggle.key, value)
		}
		*toggle.field = &enabled
		set = true
	}
	if !set {
		return nil, nil
	}
	return sections, nil
}

// reportSourceURL points the report back at the run it describes. Absent when
// the request carries no host to build one from, rather than guessed.
func reportSourceURL(r *http.Request, scanID string) string {
	if r.Host == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return fmt.Sprintf("%s://%s/scans/%s", scheme, r.Host, scanID)
}

// reportFilename names the download after the run rather than the route, so a
// directory of exports is readable.
func reportFilename(scan api.Scan, format report.Format) string {
	name := scan.Name
	if name == "" {
		name = scan.ID
	}
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '"' || r < ' ' {
			return '-'
		}
		return r
	}, name)
	return safe + "-report." + string(format)
}
