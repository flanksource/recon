package api

import "encoding/json"

// The payload the printed scan report is rendered from.
//
// Every field here mirrors a field of `ScanReportData` in
// app/reports/scan-report-types.ts, which is the template's declared input. The
// two are kept in step by TestScanReportJSONContract, which pins the JSON key
// set this marshals to — a rename on either side then fails a test rather than
// silently printing a report with a blank section.
//
// Nothing is derived here. The template owns every count it prints, so the
// browser preview and the PDF cannot disagree about what a run found.

// ScanReportSections selects which parts of the report to print. A nil pointer
// means every section, which is why each field is a pointer: `false` and
// "unset" are different answers and a plain bool cannot tell them apart.
type ScanReportSections struct {
	Coverage         *bool `json:"coverage,omitempty"`
	Traffic          *bool `json:"traffic,omitempty"`
	Breakdowns       *bool `json:"breakdowns,omitempty"`
	SummaryTable     *bool `json:"summaryTable,omitempty"`
	DetailedFindings *bool `json:"detailedFindings,omitempty"`
	Evidence         *bool `json:"evidence,omitempty"`
	Appendix         *bool `json:"appendix,omitempty"`
}

// ScanReportOptions is the presentation of one report: what it is called, who it
// is for, and how much of the run it prints.
type ScanReportOptions struct {
	Title    string `json:"title,omitempty"`
	Subtitle string `json:"subtitle,omitempty"`

	// Classification is printed in the footer of every page.
	Classification string `json:"classification,omitempty"`
	PreparedBy     string `json:"preparedBy,omitempty"`
	Audience       string `json:"audience,omitempty"`
	Scope          string `json:"scope,omitempty"`

	// Watermark draws diagonally across every page, e.g. "DRAFT".
	Watermark string `json:"watermark,omitempty"`

	Sections *ScanReportSections `json:"sections,omitempty"`

	// MinSeverity drops findings below this level. The severity totals stay
	// whole-run, and the report says what it excluded.
	MinSeverity Severity `json:"minSeverity,omitempty"`

	// MaxDetailedFindings caps the detailed occurrences before they are grouped
	// by template. The summary still includes every finding group.
	MaxDetailedFindings int `json:"maxDetailedFindings,omitempty"`
}

// ScanReport is what the renderer is handed.
type ScanReport struct {
	Scan       Scan               `json:"scan"`
	Findings   []Finding          `json:"findings"`
	Parameters map[string]any     `json:"parameters,omitempty"`
	Options    *ScanReportOptions `json:"options,omitempty"`

	// GeneratedAt is stamped by the server rather than read inside the template,
	// so rendering one payload twice produces the same document.
	GeneratedAt string `json:"generatedAt"`

	// FindingLimit is how many findings were asked for. When the run holds more,
	// the report prints that it covers a page of the run rather than all of it.
	FindingLimit int `json:"findingLimit,omitempty"`

	// SourceURL is where the run can be read interactively.
	SourceURL string `json:"sourceURL,omitempty"`
}

// MarshalJSON emits an empty findings list rather than null, matching Scan: the
// template maps over it without checking.
func (r ScanReport) MarshalJSON() ([]byte, error) {
	type alias ScanReport // shed the method set, or this recurses
	out := alias(r)
	if out.Findings == nil {
		out.Findings = []Finding{}
	}
	return json.Marshal(out)
}
