package api

import "strings"

// Severity is the normalised severity ladder. Engines report their own
// vocabularies; anything unrecognised becomes SeverityUnknown rather than being
// dropped, because a finding nobody can classify is still a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// Severities lists the ladder from most to least severe — the order the UI
// groups and sorts by.
func Severities() []Severity {
	return []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium,
		SeverityLow, SeverityInfo, SeverityUnknown,
	}
}

// ParseSeverity normalises an engine's severity string.
func ParseSeverity(value string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(value))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInfo:
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// Finding is one result from a scan engine, normalised across engines.
//
// Raw keeps the engine's original record. The typed fields are what the UI
// filters and groups on, but a finding is evidence — dropping whatever did not
// fit the schema would lose exactly the detail someone investigating needs.
type Finding struct {
	// ScanID and LineNo are the finding's address. They are set when it is read
	// back from a run, not when it is parsed: a finding has no identity apart
	// from where it appeared.
	ScanID string `json:"scanId,omitempty"`
	LineNo int    `json:"lineNo,omitempty"`

	TemplateID  string   `json:"templateId"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Host        string   `json:"host"`
	MatchedAt   string   `json:"matchedAt"`
	MatcherName string   `json:"matcherName,omitempty"`
	Type        string   `json:"type,omitempty"`
	Tags        []string `json:"tags"`
	Timestamp   string   `json:"timestamp,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Curl        string   `json:"curl,omitempty"`
	Request     string   `json:"request,omitempty"`
	Response    string   `json:"response,omitempty"`

	Raw map[string]any `json:"raw,omitempty"`
}
