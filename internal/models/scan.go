package models

import (
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
)

// Scan is one row of the scans table.
type Scan struct {
	ID   string `gorm:"column:id;primaryKey;default:generate_ulid()"`
	Name string `gorm:"column:name"`

	Engine        string  `gorm:"column:engine"`
	EngineVersion *string `gorm:"column:engine_version"`
	Profile       string  `gorm:"column:profile"`

	Selector      JSON[map[string]any] `gorm:"column:selector;type:jsonb"`
	EndpointCount int                  `gorm:"column:endpoint_count"`

	Phase      string     `gorm:"column:phase"`
	StartedAt  time.Time  `gorm:"column:started_at"`
	FinishedAt *time.Time `gorm:"column:finished_at"`

	ExitCode *int           `gorm:"column:exit_code"`
	Error    *string        `gorm:"column:error"`
	Command  pq.StringArray `gorm:"column:command;type:text[]"`

	Stats      JSON[api.ScanStats]  `gorm:"column:stats;type:jsonb"`
	Severities JSON[map[string]int] `gorm:"column:severities;type:jsonb"`
	ResultPath *string              `gorm:"column:result_path"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
}

// TableName is explicit so a gorm naming-strategy change cannot repoint the
// model at a different table than the HCL declares.
func (Scan) TableName() string { return "scans" }

// Document projects the row onto the wire type.
//
// Timestamps are formatted without a zone deliberately: the previous
// implementation wrote "2026-08-08T23:18:40" and the frontend sorts these as
// strings, so emitting an offset here would reorder the runs list.
func (s Scan) Document(findings int, hosts []string, label string) api.Scan {
	scan := api.Scan{
		ID:            s.ID,
		Name:          s.Name,
		Engine:        s.Engine,
		EngineVersion: deref(s.EngineVersion),
		Profile:       s.Profile,
		Selector:      s.Selector.Get(),
		SelectorLabel: label,
		EndpointCount: s.EndpointCount,
		Phase:         api.Phase(s.Phase),
		StartedAt:     localTimestamp(s.StartedAt),
		Command:       stringSlice(s.Command),
		ExitCode:      s.ExitCode,
		Error:         deref(s.Error),
		Findings:      findings,
		Severities:    s.Severities.Get(),
		Stats:         s.Stats.V,
		Hosts:         hosts,
		Result:        deref(s.ResultPath),
	}
	if s.FinishedAt != nil {
		scan.FinishedAt = localTimestamp(*s.FinishedAt)
	}
	if scan.Selector == nil {
		scan.Selector = map[string]any{}
	}
	if scan.Severities == nil {
		scan.Severities = map[string]int{}
	}
	if scan.Hosts == nil {
		scan.Hosts = []string{}
	}
	return scan
}

// localTimestamp renders a time the way the runs list expects: local wall clock,
// no offset. See Document.
func localTimestamp(t time.Time) string {
	return t.In(time.Local).Format("2006-01-02T15:04:05")
}

// Finding is one row of the findings table.
type Finding struct {
	ID     string `gorm:"column:id;primaryKey;default:generate_ulid()"`
	ScanID string `gorm:"column:scan_id"`
	// LineNo preserves the order the engine emitted findings in, which is the
	// order the results file has and the UI renders.
	LineNo int `gorm:"column:line_no"`

	TemplateID  string  `gorm:"column:template_id"`
	Name        string  `gorm:"column:name"`
	Severity    string  `gorm:"column:severity"`
	Host        string  `gorm:"column:host"`
	MatchedAt   string  `gorm:"column:matched_at"`
	MatcherName *string `gorm:"column:matcher_name"`
	Type        *string `gorm:"column:type"`

	Tags      pq.StringArray `gorm:"column:tags;type:text[]"`
	Timestamp *time.Time     `gorm:"column:timestamp"`

	Extracted   pq.StringArray `gorm:"column:extracted;type:text[]"`
	Remediation *string        `gorm:"column:remediation"`
	Reference   pq.StringArray `gorm:"column:reference;type:text[]"`
	Curl        *string        `gorm:"column:curl"`
	Request     *string        `gorm:"column:request"`
	Response    *string        `gorm:"column:response"`

	Raw JSON[map[string]any] `gorm:"column:raw;type:jsonb"`
}

// TableName is explicit; see Scan.TableName.
func (Finding) TableName() string { return "findings" }

// Document projects the row onto the wire type.
func (f Finding) Document() api.Finding {
	finding := api.Finding{
		ScanID:      f.ScanID,
		LineNo:      f.LineNo,
		TemplateID:  f.TemplateID,
		Name:        f.Name,
		Severity:    api.Severity(f.Severity),
		Host:        f.Host,
		MatchedAt:   f.MatchedAt,
		MatcherName: deref(f.MatcherName),
		Type:        deref(f.Type),
		Tags:        stringSlice(f.Tags),
		Extracted:   stringSlice(f.Extracted),
		Remediation: deref(f.Remediation),
		Reference:   stringSlice(f.Reference),
		Curl:        deref(f.Curl),
		Request:     deref(f.Request),
		Response:    deref(f.Response),
		Raw:         f.Raw.Get(),
	}
	if f.Timestamp != nil {
		finding.Timestamp = f.Timestamp.Format(time.RFC3339)
	}
	if finding.Tags == nil {
		finding.Tags = []string{}
	}
	return finding
}

// FindingFrom builds a row from a parsed finding.
func FindingFrom(scanID string, lineNo int, finding api.Finding) Finding {
	row := Finding{
		ScanID:      scanID,
		LineNo:      lineNo,
		TemplateID:  finding.TemplateID,
		Name:        finding.Name,
		Severity:    string(finding.Severity),
		Host:        finding.Host,
		MatchedAt:   finding.MatchedAt,
		MatcherName: nonEmpty(finding.MatcherName),
		Type:        nonEmpty(finding.Type),
		Tags:        pq.StringArray(finding.Tags),
		Extracted:   pq.StringArray(finding.Extracted),
		Remediation: nonEmpty(finding.Remediation),
		Reference:   pq.StringArray(finding.Reference),
		Curl:        nonEmpty(finding.Curl),
		Request:     nonEmpty(finding.Request),
		Response:    nonEmpty(finding.Response),
		Raw:         wrapMap(finding.Raw),
	}
	if finding.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, finding.Timestamp); err == nil {
			row.Timestamp = &parsed
		}
	}
	return row
}

// wrapMap stores a map as jsonb, keeping an absent map as SQL NULL rather than
// an empty object.
func wrapMap(value map[string]any) JSON[map[string]any] {
	if value == nil {
		return JSON[map[string]any]{}
	}
	return JSON[map[string]any]{V: &value}
}

func nonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
